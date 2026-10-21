namespace VenueBooking.Modules.Identity.Logging;

/// <summary>
/// Why a refresh token was turned away, for <see cref="IdentityLog.RefreshRejected"/>. The caller
/// sees the same undifferentiated error for all of these; only the log tells them apart.
/// </summary>
internal enum RefreshRejectionReason
{
    /// <summary>No stored token has this hash — mistyped, from another environment, or guessed.</summary>
    UnknownToken,

    ExpiredToken,

    /// <summary>The token is still valid but its user has since been deleted.</summary>
    UserNotFound,

    /// <summary>A parallel request rotated the same token first and won the RowVersion check.</summary>
    ConcurrentRotation,
}
