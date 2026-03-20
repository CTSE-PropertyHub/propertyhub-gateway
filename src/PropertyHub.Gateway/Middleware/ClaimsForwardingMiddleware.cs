using System.Security.Claims;

namespace PropertyHub.Gateway.Middleware;

/// <summary>
/// Extracts validated JWT claims from HttpContext.User and injects them as
/// HTTP headers before YARP forwards the request to a downstream service.
///
/// Headers injected:
///   X-User-Id   ← JWT "sub" claim (the user's unique identifier)
///   X-User-Role ← JWT "role" claim
///
/// Security: existing X-User-Id and X-User-Role headers from the caller are
/// unconditionally stripped before injection to prevent header spoofing attacks.
///
/// Must run after UseAuthentication and UseAuthorization in the pipeline.
/// Skips header injection for unauthenticated requests (anonymous routes such
/// as /auth/* and /health).
/// </summary>
public sealed class ClaimsForwardingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ClaimsForwardingMiddleware> _logger;

    public ClaimsForwardingMiddleware(
        RequestDelegate next,
        ILogger<ClaimsForwardingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Always strip caller-supplied values to prevent downstream services
        // from trusting spoofed headers, regardless of authentication state.
        context.Request.Headers.Remove("X-User-Id");
        context.Request.Headers.Remove("X-User-Role");

        // Skip injection for unauthenticated users (anonymous routes).
        // UseAuthorization has already run — any protected route with an invalid
        // or missing token has been rejected with 401 before reaching here.
        if (context.User.Identity?.IsAuthenticated != true)
        {
            await _next(context);
            return;
        }

        // Support both MapInboundClaims = false ("sub", "role" — raw JWT names)
        // and MapInboundClaims = true (ClaimTypes.NameIdentifier, ClaimTypes.Role
        // — legacy WS-Federation names). The gateway sets MapInboundClaims = false,
        // but the fallback keeps the middleware resilient to configuration changes.
        var userId = context.User.FindFirstValue("sub")
                  ?? context.User.FindFirstValue(ClaimTypes.NameIdentifier);

        var userRole = context.User.FindFirstValue("role")
                    ?? context.User.FindFirstValue(ClaimTypes.Role);

        if (userId is not null)
        {
            context.Request.Headers["X-User-Id"] = userId;
        }
        else
        {
            _logger.LogWarning(
                "Authenticated request is missing the expected 'sub' claim. Path: {Path}",
                context.Request.Path);
        }

        if (userRole is not null)
        {
            context.Request.Headers["X-User-Role"] = userRole;
        }
        else
        {
            _logger.LogWarning(
                "Authenticated request is missing the expected 'role' claim. " +
                "UserId: {UserId}, Path: {Path}",
                userId ?? "unknown",
                context.Request.Path);
        }

        await _next(context);
    }
}
