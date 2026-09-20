using System.ComponentModel.DataAnnotations;

namespace VenueBooking.Modules.Identity.Authentication;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    [Required]
    public required string Issuer { get; init; }

    [Required]
    public required string Audience { get; init; }

    /// <summary>
    /// HMAC-SHA256 signing key. Needs at least 32 bytes (256 bits) of entropy. Dev-only value
    /// lives in appsettings.Development.json; production reads it from Azure Key Vault (Epic 14).
    /// </summary>
    [Required, MinLength(32)]
    public required string SigningKey { get; init; }

    [Range(1, 1440)]
    public int AccessTokenMinutes { get; init; } = 15;

    [Range(1, 90)]
    public int RefreshTokenDays { get; init; } = 7;
}
