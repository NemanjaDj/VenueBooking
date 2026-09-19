using System.ComponentModel.DataAnnotations;
using VenueBooking.Contracts.Enums;

namespace VenueBooking.Contracts.Identity;

/// <summary>
/// Self-registration request. <see cref="UserRole.Admin"/> is deliberately excluded — admin
/// accounts are seeded/created manually, never through this endpoint.
/// </summary>
public sealed class RegisterRequest
{
    [Required, EmailAddress, MaxLength(256)]
    public required string Email { get; init; }

    [Required, MinLength(8), MaxLength(100)]
    public required string Password { get; init; }

    [Required]
    [Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
    public required string ConfirmPassword { get; init; }

    [Required]
    [DeniedValues(UserRole.Admin, ErrorMessage = "Admin accounts cannot be self-registered.")]
    public required UserRole Role { get; init; }
}
