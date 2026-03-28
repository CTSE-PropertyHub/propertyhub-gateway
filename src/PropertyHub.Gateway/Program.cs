using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Polly.CircuitBreaker;
using PropertyHub.Gateway.Configuration;
using PropertyHub.Gateway.Infrastructure;
using PropertyHub.Gateway.Middleware;
using Scalar.AspNetCore;
using Yarp.ReverseProxy.Forwarder;

// ============================================================
// SERVICE REGISTRATION
// ============================================================

var builder = WebApplication.CreateBuilder(args);

// 1. Typed options — bind the "Gateway" section from appsettings.json.
//    Fail fast at startup if the section is missing rather than at runtime.
builder.Services.Configure<GatewayOptions>(
    builder.Configuration.GetSection(GatewayOptions.SectionName));

var gatewayOptions = builder.Configuration
    .GetSection(GatewayOptions.SectionName)
    .Get<GatewayOptions>()
    ?? throw new InvalidOperationException(
        $"Missing required configuration section '{GatewayOptions.SectionName}'.");

// 2. CORS — allow the frontend (any origin for now; tighten in production).
//    AllowAnyOrigin is safe with Bearer token auth because no cookies are used.
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod());
});

// 3. Rate Limiter — global fixed-window limiter, partitioned by client IP.
//    100 requests per minute per IP. Runs before authentication to reject
//    abusive traffic without spending resources on JWT validation.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.OnRejected = async (ctx, cancellationToken) =>
    {
        ctx.HttpContext.Response.Headers.RetryAfter = "60";
        await ctx.HttpContext.Response.WriteAsync(
            "Too many requests. Please slow down.", cancellationToken);
    };

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1),
            }));
});

// 3. JWT Bearer Authentication — RS256 + OIDC discovery.
//    Microsoft.AspNetCore.Authentication.JwtBearer is in the ASP.NET Core shared
//    framework on .NET 8+; no NuGet package is required.
//
//    options.Authority instructs the handler to fetch:
//      {JwtAuthority}/.well-known/openid-configuration   (OIDC discovery document)
//    which contains the jwks_uri. The handler fetches public RSA keys from there
//    and uses them to verify RS256 token signatures.
//
//    Keys are loaded lazily on the first validated request — the gateway starts
//    successfully even when the Auth Service is offline.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = gatewayOptions.JwtAuthority;

        // Allow plain HTTP OIDC in development (Auth Service runs on localhost).
        // In production (appsettings.json), RequireHttpsMetadata defaults to true.
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();

        // Preserve original JWT claim names ("sub", "role", "email") instead of
        // mapping them to legacy WS-Federation URI names. This is the modern
        // recommended setting and is required for ClaimsForwardingMiddleware to
        // locate claims by their raw JWT names.
        options.MapInboundClaims = false;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = gatewayOptions.JwtIssuer,

            ValidateAudience = true,
            ValidAudience = gatewayOptions.JwtAudience,

            ValidateLifetime = true,
            // 30-second tolerance for clock drift between services.
            ClockSkew = TimeSpan.FromSeconds(30),

            // RS256 — asymmetric signing. The public key is retrieved automatically
            // from the JWKS endpoint discovered via Authority above.
            // IssuerSigningKey is intentionally NOT set here.
            ValidateIssuerSigningKey = true,
        };
    });

// 4. Authorization policies.
//    "authenticated" — requires a valid JWT; applied to all protected YARP routes.
//    "anonymous"     — YARP's built-in string; maps to [AllowAnonymous] on the endpoint.
//                      Do NOT register it as a named policy here.
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("authenticated", policy =>
        policy.RequireAuthenticatedUser());
});

// 5. YARP Reverse Proxy.
//    Routes and clusters are loaded from appsettings.json ("ReverseProxy" section).
//    The custom IForwarderHttpClientFactory replaces YARP's default to inject
//    per-cluster Polly v8 resilience pipelines (retry → circuit breaker → timeout).
//    YARP registers its default factory with TryAddSingleton, so our explicit
//    AddSingleton call takes precedence.
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .Services.AddSingleton<IForwarderHttpClientFactory, ResilientForwarderHttpClientFactory>();

// 6. OpenAPI documentation.
builder.Services.AddOpenApi();

// ============================================================
// MIDDLEWARE PIPELINE
// ============================================================

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

// Pipeline order is intentional and must not be changed:
//   HTTPS redirect → rate limiter → authentication → authorization
//   → claims forwarding → YARP forwarding

app.UseHttpsRedirection();

app.UseCors();

app.UseRateLimiter();

// Populates HttpContext.User from the validated JWT Bearer token.
app.UseAuthentication();

// Enforces the AuthorizationPolicy set on each YARP route in appsettings.json.
// Protected routes return 401 if the user is unauthenticated, 403 if unauthorised.
app.UseAuthorization();

// Strips caller-supplied X-User-Id / X-User-Role headers and injects values
// derived from the validated JWT claims. Runs after authorisation so only
// authenticated, authorised requests reach downstream services with these headers.
app.UseMiddleware<ClaimsForwardingMiddleware>();

// Health check — handled inline, not forwarded through YARP.
// Mapped before MapReverseProxy so YARP's catch-all does not intercept it.
app.MapGet("/health", () => Results.Ok(new
{
    status = "healthy",
    service = "PropertyHub Gateway",
    version = "1.0.0",
})).AllowAnonymous();

// YARP Reverse Proxy — forwards matched requests to downstream clusters.
// The inner pipeline catches BrokenCircuitException (thrown by ResilientForwarderHttpClientFactory
// when a cluster's circuit is open) and returns 503 with a Retry-After header.
app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use(async (context, next) =>
    {
        try
        {
            await next();
        }
        catch (BrokenCircuitException ex)
        {
            var logger = context.RequestServices
                .GetRequiredService<ILogger<Program>>();

            logger.LogWarning(
                ex,
                "Circuit breaker open — returning 503 for path {Path}",
                context.Request.Path);

            var opts = context.RequestServices
                .GetRequiredService<IOptions<GatewayOptions>>()
                .Value;

            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.RetryAfter =
                opts.BrokenCircuitRetryAfterSeconds.ToString();

            await context.Response.WriteAsync(
                "Service temporarily unavailable. Please retry later.");
        }
    });
});

app.Run();
