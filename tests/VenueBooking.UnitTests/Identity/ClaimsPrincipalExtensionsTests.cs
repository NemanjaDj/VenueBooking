using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using VenueBooking.Contracts.Enums;
using VenueBooking.Modules.Identity.Authentication;

namespace VenueBooking.UnitTests.Identity;

public sealed class ClaimsPrincipalExtensionsTests
{
    private static readonly Guid UserId = Guid.NewGuid();

    [Fact]
    public void GetUserId_ReadsTheMappedSubjectClaim()
    {
        // What a request principal looks like after the bearer handler's inbound claim map.
        var principal = PrincipalWith(new Claim(ClaimTypes.NameIdentifier, UserId.ToString()));

        Assert.Equal(UserId, principal.GetUserId());
    }

    [Fact]
    public void GetUserId_ReadsTheRawSubjectClaim()
    {
        // And what it looks like with the map turned off, or when built straight from the token.
        var principal = PrincipalWith(new Claim(JwtRegisteredClaimNames.Sub, UserId.ToString()));

        Assert.Equal(UserId, principal.GetUserId());
    }

    [Fact]
    public void TryGetUserId_ReturnsFalseForAnAnonymousPrincipal()
    {
        Assert.False(new ClaimsPrincipal(new ClaimsIdentity()).TryGetUserId(out _));
    }

    [Fact]
    public void TryGetUserId_ReturnsFalseWhenTheSubjectIsNotAGuid()
    {
        var principal = PrincipalWith(new Claim(ClaimTypes.NameIdentifier, "not-a-guid"));

        Assert.False(principal.TryGetUserId(out _));
    }

    [Fact]
    public void GetUserId_ThrowsWhenThereIsNoSubject()
    {
        Assert.Throws<InvalidOperationException>(() => new ClaimsPrincipal(new ClaimsIdentity()).GetUserId());
    }

    [Fact]
    public void GetRoles_ReturnsTheRolesOnThePrincipal()
    {
        var principal = PrincipalWith(
            new Claim(ClaimTypes.Role, nameof(UserRole.Customer)),
            new Claim(ClaimTypes.Role, nameof(UserRole.Organizer)));

        Assert.Equal([UserRole.Customer, UserRole.Organizer], principal.GetRoles());
    }

    [Fact]
    public void GetRoles_HonoursTheIdentitysOwnRoleClaimType()
    {
        // The same type IsInRole consults — reading ClaimTypes.Role directly would find nothing.
        var identity = new ClaimsIdentity(
            [new Claim("role", nameof(UserRole.Admin))],
            authenticationType: "Test",
            nameType: ClaimTypes.NameIdentifier,
            roleType: "role");

        Assert.Equal([UserRole.Admin], new ClaimsPrincipal(identity).GetRoles());
    }

    [Fact]
    public void GetRoles_IgnoresRolesThatNoLongerExist()
    {
        // A token issued while a role existed shouldn't fault every request it is presented on.
        var principal = PrincipalWith(
            new Claim(ClaimTypes.Role, "VenueOwner"),
            new Claim(ClaimTypes.Role, nameof(UserRole.Organizer)));

        Assert.Equal([UserRole.Organizer], principal.GetRoles());
    }

    [Fact]
    public void GetEmail_ReadsTheMappedEmailClaim()
    {
        var principal = PrincipalWith(new Claim(ClaimTypes.Email, "user@example.com"));

        Assert.Equal("user@example.com", principal.GetEmail());
    }

    [Fact]
    public void GetEmail_ReturnsNullWhenThePrincipalHasNone()
    {
        Assert.Null(new ClaimsPrincipal(new ClaimsIdentity()).GetEmail());
    }

    private static ClaimsPrincipal PrincipalWith(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, authenticationType: "Test"));
}
