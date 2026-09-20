namespace VenueBooking.Modules.Identity.Domain;

/// <summary>
/// Server-side record of an issued refresh token. Only <see cref="TokenHash"/> is stored — never
/// the raw token — so a database leak doesn't hand out usable long-lived credentials, the same
/// principle as password hashing.
/// </summary>
public sealed class RefreshToken
{
    public required Guid Id { get; init; }
    public required Guid UserId { get; init; }
    public required string TokenHash { get; init; }
    public required DateTime ExpiresAtUtc { get; init; }
    public required DateTime CreatedAtUtc { get; init; }
    public DateTime? RevokedAtUtc { get; set; }

    public bool IsActive => RevokedAtUtc is null && ExpiresAtUtc > DateTime.UtcNow;
}
