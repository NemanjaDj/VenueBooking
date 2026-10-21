using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using VenueBooking.Contracts.Enums;

namespace VenueBooking.IntegrationTests.Identity;

/// <summary>
/// Builds well-formed access tokens the API did not issue: right issuer, right audience, right
/// claims, wrong key. Claiming a role is not the same as holding one, and that is what signature
/// validation is there to decide.
/// </summary>
internal static class ForeignTokens
{
    private const string AttackerSigningKey = "a-different-signing-key-of-at-least-32-bytes!!";

    public static string SignedAs(UserRole role)
    {
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AttackerSigningKey)),
            SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: ApiFactory.Issuer,
            audience: ApiFactory.Audience,
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, role.ToString()),
            ],
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
