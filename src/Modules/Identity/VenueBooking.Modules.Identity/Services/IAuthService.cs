using VenueBooking.Contracts.Identity;

namespace VenueBooking.Modules.Identity.Services;

public interface IAuthService
{
    Task<AuthResult<RegisterResponse>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    Task<AuthResult<LoginResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exchanges a valid refresh token for a fresh access/refresh token pair, rotating the
    /// presented token out. Fails for a token that is unknown, expired or already used.
    /// </summary>
    Task<AuthResult<LoginResponse>> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken = default);
}
