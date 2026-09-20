using VenueBooking.Modules.Identity.Domain;

namespace VenueBooking.Modules.Identity.Authentication;

public interface IJwtTokenGenerator
{
    (string Token, DateTime ExpiresAtUtc) GenerateAccessToken(ApplicationUser user, IEnumerable<string> roles);
}
