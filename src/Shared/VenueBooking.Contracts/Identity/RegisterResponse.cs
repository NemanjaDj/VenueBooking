using VenueBooking.Contracts.Enums;

namespace VenueBooking.Contracts.Identity;

public sealed record RegisterResponse(Guid Id, string Email, UserRole Role);
