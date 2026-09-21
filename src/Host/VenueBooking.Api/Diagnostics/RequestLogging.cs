using System.Security.Claims;
using Serilog;
using Serilog.AspNetCore;
using Serilog.Events;

namespace VenueBooking.Api.Diagnostics;

/// <summary>
/// Collapses the framework's several log lines per request into one summary event, and decides how
/// loudly each request is worth reporting.
/// </summary>
internal static class RequestLogging
{
    /// <summary>
    /// Endpoints that say nothing about the business: tooling and probes that would otherwise
    /// dominate the log on a quiet system. They drop to Debug rather than disappearing, so they
    /// are still there when a sink is turned up to diagnose something.
    /// </summary>
    private static readonly string[] NoisePathPrefixes =
    [
        "/openapi",
        "/scalar",
        "/health",
        "/favicon.ico",
    ];

    public static void Configure(RequestLoggingOptions options)
    {
        options.MessageTemplate = "{RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0} ms";
        options.GetLevel = GetLevel;
        options.EnrichDiagnosticContext = Enrich;
    }

    private static LogEventLevel GetLevel(HttpContext httpContext, double elapsedMilliseconds, Exception? exception)
    {
        if (exception is not null || httpContext.Response.StatusCode >= StatusCodes.Status500InternalServerError)
        {
            return LogEventLevel.Error;
        }

        // 4xx is the client's fault rather than ours, but a burst of them is worth noticing —
        // repeated 401s on /api/auth are what a credential-stuffing attempt looks like.
        if (httpContext.Response.StatusCode >= StatusCodes.Status400BadRequest)
        {
            return LogEventLevel.Warning;
        }

        return IsNoise(httpContext.Request.Path) ? LogEventLevel.Debug : LogEventLevel.Information;
    }

    private static void Enrich(IDiagnosticContext diagnosticContext, HttpContext httpContext)
    {
        diagnosticContext.Set("RequestHost", httpContext.Request.Host.ToString());
        diagnosticContext.Set("RequestScheme", httpContext.Request.Scheme);

        if (httpContext.User.Identity?.IsAuthenticated is true)
        {
            // The subject claim only — an opaque user id. The email on the same principal is
            // personal data and has no place in a log line.
            var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId is not null)
            {
                diagnosticContext.Set("UserId", userId);
            }
        }
    }

    private static bool IsNoise(PathString path) =>
        NoisePathPrefixes.Any(prefix => path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase));
}
