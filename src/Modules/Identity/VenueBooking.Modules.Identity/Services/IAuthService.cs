using VenueBooking.Contracts.Identity;

namespace VenueBooking.Modules.Identity.Services;

public interface IAuthService
{
    Task<AuthResult> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);
}
