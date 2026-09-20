namespace VenueBooking.Modules.Identity.Domain;

/// <summary>
/// Server-side record of an issued refresh token. Only <see cref="TokenHash"/> is stored — never
/// the raw token — so a database leak doesn't hand out usable long-lived credentials, the same
/// principle as password hashing.
/// </summary>
/// <remarks>
/// Tokens are single-use: refreshing rotates the presented token out (revoked, and pointed at its
/// successor via <see cref="ReplacedByTokenId"/>) and issues a fresh one. That leaves a traceable
/// chain and, crucially, makes replay detectable — a request presenting an already-revoked token
/// means the value leaked or was captured, and the whole family is then revoked.
/// </remarks>
public sealed class RefreshToken
{
    public required Guid Id { get; init; }
    public required Guid UserId { get; init; }
    public required string TokenHash { get; init; }
    public required DateTime ExpiresAtUtc { get; init; }
    public required DateTime CreatedAtUtc { get; init; }
    public DateTime? RevokedAtUtc { get; private set; }

    /// <summary>The token this one was rotated into, when it was consumed by a refresh.</summary>
    public Guid? ReplacedByTokenId { get; private set; }

    /// <summary>
    /// SQL Server <c>rowversion</c>, so two refreshes racing on the same token can't both rotate
    /// it — the loser gets a <see cref="Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException"/>.
    /// </summary>
    public byte[]? RowVersion { get; private set; }

    public bool IsRevoked => RevokedAtUtc is not null;

    public bool HasExpired(DateTime utcNow) => ExpiresAtUtc <= utcNow;

    public bool IsActive(DateTime utcNow) => !IsRevoked && !HasExpired(utcNow);

    /// <summary>
    /// Marks the token unusable. Idempotent, so revoking a family that partly overlaps an already
    /// revoked token is safe. <paramref name="replacedByTokenId"/> is set only for rotation —
    /// revocation for any other reason (reuse detected, sign-out) leaves it null.
    /// </summary>
    public void Revoke(DateTime utcNow, Guid? replacedByTokenId = null)
    {
        if (IsRevoked)
        {
            return;
        }

        RevokedAtUtc = utcNow;
        ReplacedByTokenId = replacedByTokenId;
    }
}
