using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace VenueBooking.Modules.Identity.Authentication;

internal sealed class RefreshTokenGenerator : IRefreshTokenGenerator
{
    private const int TokenSizeInBytes = 32;

    public string GenerateToken() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(TokenSizeInBytes));

    public string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
