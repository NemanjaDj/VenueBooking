using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using VenueBooking.Contracts.Enums;

namespace VenueBooking.Modules.Identity.Authorization;

public static class AuthorizationModuleExtensions
{
    /// <summary>
    /// Registers the policy catalogue described by <see cref="AuthorizationPolicies"/>, together
    /// with a fallback policy that makes the API closed by default.
    /// </summary>
    /// <remarks>
    /// The fallback is the important part: it applies to every endpoint carrying no authorization
    /// metadata of its own, so an endpoint added in a later epic is protected the moment it is
    /// mapped. Exposing one publicly then takes a deliberate <c>[AllowAnonymous]</c> — a line a
    /// reviewer can see — rather than being the consequence of a forgotten attribute.
    /// <para>
    /// This configures the catalogue only. Evaluating it against requests is the host's job
    /// (<c>AddAuthorization</c> + <c>UseAuthorization</c>), which is why the module needs no
    /// dependency on ASP.NET Core's hosting or middleware packages.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddRoleAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationCore(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();

            // RequireRole already rejects an anonymous caller, and the middleware turns that into
            // a 401 challenge rather than a 403 — so these policies don't restate
            // RequireAuthenticatedUser. An authenticated caller holding the wrong role still gets
            // the 403 it has earned.
            options.AddPolicy(AuthorizationPolicies.Customer, policy => policy.RequireRole(nameof(UserRole.Customer)));
            options.AddPolicy(AuthorizationPolicies.Organizer, policy => policy.RequireRole(nameof(UserRole.Organizer)));
            options.AddPolicy(AuthorizationPolicies.Admin, policy => policy.RequireRole(nameof(UserRole.Admin)));
            options.AddPolicy(
                AuthorizationPolicies.OrganizerOrAdmin,
                policy => policy.RequireRole(nameof(UserRole.Organizer), nameof(UserRole.Admin)));
        });

        return services;
    }
}
