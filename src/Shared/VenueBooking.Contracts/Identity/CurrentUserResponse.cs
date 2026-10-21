using VenueBooking.Contracts.Enums;

namespace VenueBooking.Contracts.Identity;

/// <summary>
/// The identity the API sees behind the caller's access token. Clients use it to decide which
/// navigation and routes to offer; it is a convenience, never the authorization decision itself —
/// that one is made server-side on every request.
/// </summary>
public sealed record CurrentUserResponse(Guid UserId, string? Email, IReadOnlyCollection<UserRole> Roles);
