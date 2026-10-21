using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VenueBooking.Contracts.Identity;
using VenueBooking.Modules.Identity.Authentication;
using VenueBooking.Modules.Identity.Domain;
using VenueBooking.Modules.Identity.Logging;
using VenueBooking.Modules.Identity.Persistence;

namespace VenueBooking.Modules.Identity.Services;

/// <remarks>
/// Every outcome — success or each distinct kind of failure — is recorded through
/// <see cref="IdentityLog"/>. The responses stay deliberately vague to avoid revealing which
/// accounts exist; the log is where the real reason is kept, keyed by user id alone.
/// </remarks>
internal sealed class AuthService(
    UserManager<ApplicationUser> userManager,
    IJwtTokenGenerator jwtTokenGenerator,
    IRefreshTokenGenerator refreshTokenGenerator,
    IdentityDbContext db,
    IOptions<JwtOptions> jwtOptions,
    ILogger<AuthService> logger) : IAuthService
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

        var roleName = request.Role.ToString();

        var createResult = await userManager.CreateAsync(user, request.Password);
        if (!createResult.Succeeded)
        {
            IdentityLog.RegistrationRejected(logger, roleName, ErrorCodes(createResult));
            return AuthResult<RegisterResponse>.Failure(createResult.Errors.Select(e => e.Description));
        }

        var roleResult = await userManager.AddToRoleAsync(user, roleName);
        if (!roleResult.Succeeded)
        {
            IdentityLog.RegistrationRoleAssignmentFailed(logger, user.Id, roleName, ErrorCodes(roleResult));

            // Don't leave behind a user with no role assigned.
            var deleteResult = await userManager.DeleteAsync(user);
            if (!deleteResult.Succeeded)
            {
                IdentityLog.RegistrationRollbackFailed(logger, user.Id, ErrorCodes(deleteResult));
            }

            return AuthResult<RegisterResponse>.Failure(roleResult.Errors.Select(e => e.Description));
        }

        IdentityLog.UserRegistered(logger, user.Id, roleName);
        return AuthResult<RegisterResponse>.Success(new RegisterResponse(user.Id, user.Email!, request.Role));
    }

    public async Task<AuthResult<LoginResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            IdentityLog.LoginFailedUnknownAccount(logger);
            return AuthResult<LoginResponse>.Failure([InvalidCredentialsError]);
        }

        if (await userManager.IsLockedOutAsync(user))
        {
            IdentityLog.LoginRejectedLockedOut(logger, user.Id, await userManager.GetLockoutEndDateAsync(user));
            return AuthResult<LoginResponse>.Failure([AccountLockedError]);
        }

        if (!await userManager.CheckPasswordAsync(user, request.Password))
        {
            // Tracks toward the lockout threshold configured in IdentityModuleExtensions.
            await userManager.AccessFailedAsync(user);
            await LogFailedPasswordAsync(user);
            return AuthResult<LoginResponse>.Failure([InvalidCredentialsError]);
        }

        await userManager.ResetAccessFailedCountAsync(user);

        var tokens = await IssueTokensAsync(user, rotatedFrom: null, cancellationToken);
        IdentityLog.LoginSucceeded(logger, user.Id);
        return AuthResult<LoginResponse>.Success(tokens);
    }

    public async Task<AuthResult<LoginResponse>> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken = default)
    {
        // Lookup is by hash, never by the raw value — the raw token exists only in the request
        // and in the client's own storage.
        var tokenHash = refreshTokenGenerator.Hash(request.RefreshToken);
        var storedToken = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken);
        if (storedToken is null)
        {
            IdentityLog.RefreshRejected(logger, userId: null, RefreshRejectionReason.UnknownToken);
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }

        if (storedToken.IsRevoked)
        {
            // Tokens are single-use, so a revoked one coming back means the value was captured
            // and replayed (or a client replayed a stale copy of its own). Either way it is no
            // longer a secret: cut the whole family, forcing a fresh sign-in.
            var revokedCount = await RevokeActiveTokensForUserAsync(storedToken.UserId, cancellationToken);
            IdentityLog.RefreshTokenReuseDetected(logger, storedToken.UserId, revokedCount);
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }

        if (storedToken.HasExpired(DateTime.UtcNow))
        {
            IdentityLog.RefreshRejected(logger, storedToken.UserId, RefreshRejectionReason.ExpiredToken);
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }

        var user = await userManager.FindByIdAsync(storedToken.UserId.ToString());
        if (user is null)
        {
            IdentityLog.RefreshRejected(logger, storedToken.UserId, RefreshRejectionReason.UserNotFound);
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }

        // A refresh must not become a way around a lockout applied after the token was issued.
        if (await userManager.IsLockedOutAsync(user))
        {
            IdentityLog.RefreshRejectedLockedOut(logger, user.Id, await userManager.GetLockoutEndDateAsync(user));
            return AuthResult<LoginResponse>.Failure([AccountLockedError]);
        }

        try
        {
            var tokens = await IssueTokensAsync(user, storedToken, cancellationToken);
            IdentityLog.SessionRefreshed(logger, user.Id);
            return AuthResult<LoginResponse>.Success(tokens);
        }
        catch (DbUpdateConcurrencyException)
        {
            // Another request rotated this same token first and won the RowVersion check. Only
            // one of the two may walk away with a new pair.
            IdentityLog.RefreshRejected(logger, user.Id, RefreshRejectionReason.ConcurrentRotation);
            return AuthResult<LoginResponse>.Failure([InvalidRefreshTokenError]);
        }
    }

    /// <summary>
    /// Records a wrong password as either one more step toward lockout or the step that tripped
    /// it. Read back after <see cref="UserManager{TUser}.AccessFailedAsync"/>, because that call
    /// is what decides — and on lockout it also resets the counter to zero.
    /// </summary>
    private async Task LogFailedPasswordAsync(ApplicationUser user)
    {
        if (await userManager.IsLockedOutAsync(user))
        {
            IdentityLog.AccountLockedOut(logger, user.Id, await userManager.GetLockoutEndDateAsync(user));
            return;
        }

        IdentityLog.LoginFailedInvalidPassword(
            logger,
            user.Id,
            await userManager.GetAccessFailedCountAsync(user),
            userManager.Options.Lockout.MaxFailedAccessAttempts);
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

    /// <returns>How many tokens were still active and are now revoked.</returns>
    private async Task<int> RevokeActiveTokensForUserAsync(Guid userId, CancellationToken cancellationToken)
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
        return activeTokens.Count;
    }

    private static string[] ErrorCodes(IdentityResult result) => [.. result.Errors.Select(e => e.Code)];
}
