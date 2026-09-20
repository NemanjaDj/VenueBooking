using System.ComponentModel.DataAnnotations;

namespace VenueBooking.Contracts.Identity;

/// <summary>
/// Exchanges a still-valid refresh token for a new access token, so a session survives the short
/// access-token lifetime without the user re-entering credentials. The response is a
/// <see cref="LoginResponse"/>: refresh rotates the refresh token too, and the client must store
/// the new pair and discard the old one.
/// </summary>
public sealed class RefreshRequest
{
    [Required]
    public required string RefreshToken { get; init; }
}
