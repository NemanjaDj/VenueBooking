using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi.Models;

namespace VenueBooking.Api.OpenApi;

/// <summary>
/// Marks each protected operation in the generated document as requiring a bearer token, and
/// documents the 401/403 it can answer with.
/// </summary>
/// <remarks>
/// The test for "protected" is the absence of <see cref="IAllowAnonymous"/> rather than the
/// presence of <see cref="IAuthorizeData"/>, which mirrors the fallback policy the API actually
/// runs with: an endpoint that says nothing needs a token. Deriving it from the endpoint's own
/// metadata keeps the document honest as endpoints are added, instead of relying on whoever adds
/// them to also annotate the spec.
/// </remarks>
internal sealed class BearerSecurityRequirementTransformer : IOpenApiOperationTransformer
{
    private static readonly OpenApiSecurityRequirement BearerRequirement = new()
    {
        [new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = JwtBearerDefaults.AuthenticationScheme,
            },
        }] = [],
    };

    public Task TransformAsync(
        OpenApiOperation operation,
        OpenApiOperationTransformerContext context,
        CancellationToken cancellationToken)
    {
        var metadata = context.Description.ActionDescriptor.EndpointMetadata;
        if (metadata.OfType<IAllowAnonymous>().Any())
        {
            return Task.CompletedTask;
        }

        operation.Security = [BearerRequirement];

        // Only added where the action hasn't already described them itself, so a more specific
        // [ProducesResponseType] on an endpoint still wins.
        operation.Responses.TryAdd(
            StatusCodes.Status401Unauthorized.ToString(),
            new OpenApiResponse { Description = "The access token is missing, expired or invalid." });
        operation.Responses.TryAdd(
            StatusCodes.Status403Forbidden.ToString(),
            new OpenApiResponse { Description = "The caller is authenticated but lacks the required role." });

        return Task.CompletedTask;
    }
}
