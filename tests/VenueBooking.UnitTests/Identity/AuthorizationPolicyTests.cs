using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using VenueBooking.Contracts.Enums;
using VenueBooking.Modules.Identity.Authorization;

namespace VenueBooking.UnitTests.Identity;

/// <summary>
/// Pins the policy catalogue itself. The integration tests prove the middleware enforces what is
/// registered; these prove what is registered is what was meant — in particular that no policy
/// silently widens to admit a role it shouldn't, which is the kind of change that breaks nothing
/// visible.
/// </summary>
public sealed class AuthorizationPolicyTests
{
    private readonly IAuthorizationPolicyProvider _policyProvider = new ServiceCollection()
        .AddRoleAuthorization()
        .BuildServiceProvider()
        .GetRequiredService<IAuthorizationPolicyProvider>();

    public static TheoryData<string, string[]> PolicyRoles => new()
    {
        { AuthorizationPolicies.Customer, [nameof(UserRole.Customer)] },
        { AuthorizationPolicies.Organizer, [nameof(UserRole.Organizer)] },
        { AuthorizationPolicies.Admin, [nameof(UserRole.Admin)] },
        { AuthorizationPolicies.OrganizerOrAdmin, [nameof(UserRole.Organizer), nameof(UserRole.Admin)] },
    };

    [Theory]
    [MemberData(nameof(PolicyRoles))]
    public async Task Policy_AdmitsExactlyTheIntendedRoles(string policyName, string[] expectedRoles)
    {
        var policy = await _policyProvider.GetPolicyAsync(policyName);

        Assert.NotNull(policy);
        var requirement = Assert.Single(policy.Requirements.OfType<RolesAuthorizationRequirement>());
        Assert.Equal(expectedRoles.Order(), requirement.AllowedRoles.Order());
    }

    [Fact]
    public async Task FallbackPolicy_RequiresAnAuthenticatedCaller()
    {
        // Without this, an endpoint that forgets [Authorize] is public.
        var fallback = await _policyProvider.GetFallbackPolicyAsync();

        Assert.NotNull(fallback);
        Assert.Single(fallback.Requirements.OfType<DenyAnonymousAuthorizationRequirement>());
    }

    [Fact]
    public async Task EveryRole_HasAPolicyNamedAfterIt()
    {
        // A role added to the enum without a policy would be a role nothing can be authorized
        // against — easy to miss, since the code still compiles and the role still seeds.
        foreach (var role in Enum.GetNames<UserRole>())
        {
            Assert.NotNull(await _policyProvider.GetPolicyAsync(role));
        }
    }
}
