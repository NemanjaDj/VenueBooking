using System.ComponentModel.DataAnnotations;

namespace VenueBooking.Contracts.Identity;

public sealed class LoginRequest
{
    [Required, EmailAddress, MaxLength(256)]
    public required string Email { get; init; }

    [Required]
    public required string Password { get; init; }
}
