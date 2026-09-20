using VenueBooking.Contracts.Identity;

namespace VenueBooking.Modules.Identity.Services;

public interface IAuthService
{
    Task<AuthResult<RegisterResponse>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    Task<AuthResult<LoginResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default);
}
