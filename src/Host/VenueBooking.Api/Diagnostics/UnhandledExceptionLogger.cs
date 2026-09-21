using System.Diagnostics;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace VenueBooking.Api.Diagnostics;

/// <summary>
/// Last line of defence for a request that threw: records the failure with its full detail, and
/// answers the caller with a trace identifier instead.
/// </summary>
/// <remarks>
/// Exception messages and stack traces routinely carry connection strings, file paths and
/// whatever data was being processed, so they are written to the log and never to the response.
/// The caller quotes the trace id, and the log is where the detail is looked up.
/// </remarks>
internal sealed class UnhandledExceptionLogger(
    IProblemDetailsService problemDetailsService,
    ILogger<UnhandledExceptionLogger> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var traceId = Activity.Current?.TraceId.ToString() ?? httpContext.TraceIdentifier;

        logger.LogError(
            exception,
            "Unhandled exception handling {RequestMethod} {RequestPath} (trace {TraceId})",
            httpContext.Request.Method,
            httpContext.Request.Path,
            traceId);

        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;

        return await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            Exception = exception,
            ProblemDetails = new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "An unexpected error occurred.",
                Extensions = { ["traceId"] = traceId },
            },
        });
    }
}
