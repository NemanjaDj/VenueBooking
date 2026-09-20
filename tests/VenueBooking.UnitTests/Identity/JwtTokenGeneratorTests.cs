using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using VenueBooking.Modules.Identity.Authentication;
using VenueBooking.Modules.Identity.Domain;

namespace VenueBooking.UnitTests.Identity;

public sealed class JwtTokenGeneratorTests
{
    private readonly JwtTokenGenerator _sut = new(Options.Create(new JwtOptions
    {
        Issuer = "VenueBooking.Tests",
        Audience = "VenueBooking.Tests",
        SigningKey = "unit-test-signing-key-at-least-32-bytes-long!!",
        AccessTokenMinutes = 15,
    }));

    [Fact]
    public void GenerateAccessToken_IncludesSubjectEmailAndRoleClaims()
    {
        var user = new ApplicationUser { Id = Guid.NewGuid(), Email = "user@example.com" };

        var (token, expiresAtUtc) = _sut.GenerateAccessToken(user, ["Organizer"]);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.Equal(user.Id.ToString(), jwt.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Sub).Value);
        Assert.Equal(user.Email, jwt.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Email).Value);
        Assert.Equal("Organizer", jwt.Claims.Single(c => c.Type == ClaimTypes.Role).Value);
        Assert.Equal(expiresAtUtc, jwt.ValidTo, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void GenerateAccessToken_ExpiresAccordingToConfiguredLifetime()
    {
        var user = new ApplicationUser { Id = Guid.NewGuid(), Email = "user@example.com" };
        var before = DateTime.UtcNow;

        var (_, expiresAtUtc) = _sut.GenerateAccessToken(user, []);

        Assert.InRange(expiresAtUtc, before.AddMinutes(15).AddSeconds(-2), before.AddMinutes(15).AddSeconds(2));
    }
}
