namespace PropertyHub.Gateway.Configuration;

/// <summary>
/// Strongly-typed options for the API Gateway, bound from the "Gateway" section
/// of appsettings.json via IOptions&lt;GatewayOptions&gt;.
/// </summary>
public sealed class GatewayOptions
{
    public const string SectionName = "Gateway";

    /// <summary>
    /// OIDC issuer URL. The JwtBearer handler fetches
    /// {JwtAuthority}/.well-known/openid-configuration to discover the JWKS URI,
    /// then fetches public RSA keys from there for RS256 signature verification.
    /// Keys are loaded lazily on first token validation — the gateway starts
    /// successfully even when the Auth Service is temporarily offline.
    /// Example: "https://auth.propertyhub.internal"
    /// </summary>
    public string JwtAuthority { get; init; } = string.Empty;

    /// <summary>
    /// Expected value of the "iss" claim in incoming JWTs.
    /// Must exactly match what the Auth Service puts in tokens.
    /// </summary>
    public string JwtIssuer { get; init; } = string.Empty;

    /// <summary>
    /// Expected value of the "aud" claim in incoming JWTs.
    /// Example: "propertyhub-api"
    /// </summary>
    public string JwtAudience { get; init; } = string.Empty;

    /// <summary>
    /// Value placed in the Retry-After response header when a downstream
    /// circuit breaker is open and the gateway returns 503.
    /// Should match the circuit breaker's BreakDuration in seconds.
    /// </summary>
    public int BrokenCircuitRetryAfterSeconds { get; init; } = 30;
}
