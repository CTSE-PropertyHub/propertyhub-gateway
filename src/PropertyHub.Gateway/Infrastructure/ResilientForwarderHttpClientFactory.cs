using System.Net;
using Microsoft.Extensions.Http.Resilience;
using Yarp.ReverseProxy.Forwarder;

namespace PropertyHub.Gateway.Infrastructure;

/// <summary>
/// Custom IForwarderHttpClientFactory that wraps each downstream cluster's
/// HttpMessageInvoker in an independent Polly v8 resilience pipeline.
///
/// Pipeline per cluster (outermost → innermost):
///   circuit breaker (opens at 50% failure ratio over 30s, breaks for 30s)
///     → timeout (10s per attempt)
///       → SocketsHttpHandler (actual TCP connection)
///
/// Retries are omitted: YARP request bodies are single-read streams, so a retry
/// attempt would throw "Stream was already consumed". Retries are also unsafe for
/// non-idempotent requests (POST, PATCH, DELETE) on a reverse proxy.
///
/// Per-cluster isolation: each cluster has its own circuit breaker state.
/// A tripped circuit on property-service does not affect tenancy-service.
///
/// YARP lifecycle: YARP calls CreateClient on every configuration reload.
/// When configuration is unchanged, we return the existing client (OldClient)
/// to avoid recreating the SocketsHttpHandler and leaking connection pools.
/// This mirrors the behaviour of YARP's own default ForwarderHttpClientFactory.
/// </summary>
public sealed class ResilientForwarderHttpClientFactory : IForwarderHttpClientFactory
{
    private readonly ILogger<ResilientForwarderHttpClientFactory> _logger;

    public ResilientForwarderHttpClientFactory(
        ILogger<ResilientForwarderHttpClientFactory> logger)
    {
        _logger = logger;
    }

    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
    {
        // Reuse the existing client when cluster configuration has not changed.
        // Creating a new SocketsHttpHandler on every call would exhaust the
        // connection pool. This is the standard YARP extension point pattern.
        if (context.OldClient is not null && context.NewConfig == context.OldConfig)
        {
            return context.OldClient;
        }

        _logger.LogInformation(
            "Creating resilient HTTP client for cluster '{ClusterId}'",
            context.ClusterId);

        // Transport layer — settings match YARP's own defaults to ensure correct
        // proxy behaviour (no cookie jars, no auto-redirects, no proxy hop).
        var socketsHandler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            EnableMultipleHttp2Connections = true,
            ConnectTimeout = TimeSpan.FromSeconds(15),
        };

        // Polly v8 resilience pipeline.
        // Retries are intentionally omitted: YARP proxies the request body as a
        // StreamCopyHttpContent (one-time-read stream). Retrying after the stream
        // has been consumed throws "Stream was already consumed" and also risks
        // double-submission of non-idempotent requests (POST, PATCH, DELETE).
        // Circuit breaker + timeout provide sufficient resilience without that risk.
        var pipeline = new ResiliencePipelineBuilder<HttpResponseMessage>()
            .AddCircuitBreaker(new HttpCircuitBreakerStrategyOptions
            {
                // Open the circuit when >= 50% of requests fail within the sampling window.
                FailureRatio = 0.5,
                // Require at least 10 requests before evaluating the failure ratio,
                // preventing a single failure from tripping the circuit at startup.
                MinimumThroughput = 10,
                // Evaluate the failure ratio over a 30-second rolling window.
                SamplingDuration = TimeSpan.FromSeconds(30),
                // Keep the circuit open for 30 seconds, then enter half-open to probe.
                // BrokenCircuitRetryAfterSeconds in GatewayOptions should match this.
                BreakDuration = TimeSpan.FromSeconds(30),
            })
            .AddTimeout(TimeSpan.FromSeconds(10))
            .Build();

        // ResilienceHandler is a DelegatingHandler that executes the pipeline
        // around each outbound HTTP call. Chaining it over SocketsHttpHandler gives
        // us the full resilience pipeline without going through IHttpClientFactory.
        var resilienceHandler = new ResilienceHandler(pipeline)
        {
            InnerHandler = socketsHandler,
        };

        return new HttpMessageInvoker(resilienceHandler, disposeHandler: true);
    }
}
