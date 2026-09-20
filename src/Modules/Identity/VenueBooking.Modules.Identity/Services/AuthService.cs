using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using VenueBooking.Contracts.Identity;
using VenueBooking.Modules.Identity.Authentication;
using VenueBooking.Modules.Identity.Domain;
using VenueBooking.Modules.Identity.Persistence;

namespace VenueBooking.Modules.Identity.Services;

internal sealed class AuthService(
    UserManager<ApplicationUser> userManager,
    IJwtTokenGenerator jwtTokenGenerator,
    IRefreshTokenGenerator refreshTokenGenerator,
    IdentityDbContext db,
    IOptions<JwtOptions> jwtOptions) : IAuthService
{
    // Deliberately identical whether the email doesn't exist or the password is wrong, so the
    // response never reveals which emails are registered.
    private const string InvalidCredentialsError = "Invalid email or password.";

    public async Task<AuthResult<RegisterResponse>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
        };

        var createResult = await userManager.CreateAsync(user, request.Password);
        if (!createResult.Succeeded)
        {
            return AuthResult<RegisterResponse>.Failure(createResult.Errors.Select(e => e.Description));
        }

        var roleName = request.Role.ToString();
        var roleResult = await userManager.AddToRoleAsync(user, roleName);
        if (!roleResult.Succeeded)
        {
            // Don't leave behind a user with no role assigned.
            await userManager.DeleteAsync(user);
            return AuthResult<RegisterResponse>.Failure(roleResult.Errors.Select(e => e.Description));
        }

        return AuthResult<RegisterResponse>.Success(new RegisterResponse(user.Id, user.Email!, request.Role));
    }

    public async Task<AuthResult<LoginResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            return AuthResult<LoginResponse>.Failure([InvalidCredentialsError]);
        }

        if (await userManager.IsLockedOutAsync(user))
        {
            return AuthResult<LoginResponse>.Failure(["This account is temporarily locked due to repeated failed sign-in attempts."]);
        }

        if (!await userManager.CheckPasswordAsync(user, request.Password))
        {
            // Tracks toward the lockout threshold configured in IdentityModuleExtensions.
            await userManager.AccessFailedAsync(user);
            return AuthResult<LoginResponse>.Failure([InvalidCredentialsError]);
        }

        await userManager.ResetAccessFailedCountAsync(user);

        var roles = await userManager.GetRolesAsync(user);
        var (accessToken, expiresAtUtc) = jwtTokenGenerator.GenerateAccessToken(user, roles);

        var refreshToken = refreshTokenGenerator.GenerateToken();
        db.RefreshTokens.Add(new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = refreshTokenGenerator.Hash(refreshToken),
            CreatedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(jwtOptions.Value.RefreshTokenDays),
        });
        await db.SaveChangesAsync(cancellationToken);

        return AuthResult<LoginResponse>.Success(new LoginResponse(accessToken, refreshToken, expiresAtUtc));
    }
}
