using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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

    // Likewise undifferentiated: unknown, expired, revoked and replayed refresh tokens all look
    // the same to the caller, so a probe can't learn which of its guesses ever existed.
    private const string InvalidRefreshTokenError = "Invalid or expired refresh token.";

    private const string AccountLockedError = "This account is temporarily locked due to repeated failed sign-in attempts.";

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
            return AuthResult<LoginResponse>.Failure([AccountLockedError]);
        }

        if (!await userManager.CheckPasswordAsync(user, request.Password))
        {
            // Tracks toward the lockout threshold configured in IdentityModuleExtensions.
            await userManager.AccessFailedAsync(user);
            return AuthResult<LoginResponse>.Failure([InvalidCredentialsError]);
        }

        await userManager.ResetAccessFailedCountAsync(user);

        return AuthResult<LoginResponse>.Success(await IssueTokensAsync(user, rotatedFrom: null, cancellationToken));
    }

    public async Task<AuthResult<LoginResponse>> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken = default)
    {
        // Lookup is by hash, never by the raw value — the raw token exists only in the request
        // and in the client's own storage.
        var tokenHash = refreshTokenGenerator.Hash(request.RefreshToken);
        var storedToken = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken);
        if (storedToken is null)
        {
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }

        if (storedToken.IsRevoked)
        {
            // Tokens are single-use, so a revoked one coming back means the value was captured
            // and replayed (or a client replayed a stale copy of its own). Either way it is no
            // longer a secret: cut the whole family, forcing a fresh sign-in.
            await RevokeActiveTokensForUserAsync(storedToken.UserId, cancellationToken);
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }

        if (storedToken.HasExpired(DateTime.UtcNow))
        {
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }

        var user = await userManager.FindByIdAsync(storedToken.UserId.ToString());
        if (user is null)
        {
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }

        // A refresh must not become a way around a lockout applied after the token was issued.
        if (await userManager.IsLockedOutAsync(user))
        {
            return AuthResult<LoginResponse>.Failure([AccountLockedError]);
        }

        try
        {
            return AuthResult<LoginResponse>.Success(await IssueTokensAsync(user, storedToken, cancellationToken));
        }
        catch (DbUpdateConcurrencyException)
        {
            // Another request rotated this same token first and won the RowVersion check. Only
            // one of the two may walk away with a new pair.
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }
    }

    /// <summary>
    /// Issues an access token plus a refresh token and, when this is a rotation, revokes the
    /// token being replaced in the same <c>SaveChanges</c> — so a refresh can never leave two
    /// usable refresh tokens behind.
    /// </summary>
    private async Task<LoginResponse> IssueTokensAsync(ApplicationUser user, RefreshToken? rotatedFrom, CancellationToken cancellationToken)
    {
        var roles = await userManager.GetRolesAsync(user);
        var (accessToken, accessTokenExpiresAtUtc) = jwtTokenGenerator.GenerateAccessToken(user, roles);

        var rawRefreshToken = refreshTokenGenerator.GenerateToken();
        var issuedAtUtc = DateTime.UtcNow;

        var refreshToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = refreshTokenGenerator.Hash(rawRefreshToken),
            CreatedAtUtc = issuedAtUtc,
            // Sliding window: each refresh restarts the clock, so an active session stays alive
            // and an idle one lapses after RefreshTokenDays. An absolute session cap, if one is
            // ever wanted, belongs here as a floor on the new expiry.
            ExpiresAtUtc = issuedAtUtc.AddDays(jwtOptions.Value.RefreshTokenDays),
        };

        db.RefreshTokens.Add(refreshToken);
        rotatedFrom?.Revoke(issuedAtUtc, replacedByTokenId: refreshToken.Id);
        await db.SaveChangesAsync(cancellationToken);

        return new LoginResponse(accessToken, rawRefreshToken, accessTokenExpiresAtUtc);
    }

    private async Task RevokeActiveTokensForUserAsync(Guid userId, CancellationToken cancellationToken)
    {
        var revokedAtUtc = DateTime.UtcNow;
        var activeTokens = await db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAtUtc == null)
            .ToListAsync(cancellationToken);

        foreach (var token in activeTokens)
        {
            token.Revoke(revokedAtUtc);
        }

        await db.SaveChangesAsync(cancellationToken);
    }
}
