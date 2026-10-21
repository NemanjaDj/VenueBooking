using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;
using VenueBooking.Modules.Identity.Domain;
using VenueBooking.Modules.Identity.Logging;

namespace VenueBooking.UnitTests.Identity;

/// <summary>
/// The auth events <see cref="IdentityLog"/> promises: each outcome is recorded under its own
/// event id with the user's id, and nothing a caller must keep secret ever reaches the log.
/// </summary>
public sealed partial class AuthServiceTests
{
    // Mirrors the IdentityOptions default the fixture runs with (production sets the same value).
    private const int MaxFailedAccessAttempts = 5;

    [Fact]
    public async Task RegisterAsync_WhenSuccessful_LogsUserRegisteredWithIdAndRole()
    {
        var result = await _sut.RegisterAsync(RegisterRequest(role: UserRole.Organizer));

        var record = SingleEvent(1010);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(result.Value!.Id.ToString(), State(record, "UserId"));
        Assert.Equal(nameof(UserRole.Organizer), State(record, "Role"));
    }

    [Fact]
    public async Task RegisterAsync_WithDuplicateEmail_LogsTheRejectionByErrorCode()
    {
        var request = RegisterRequest();
        await _sut.RegisterAsync(request);
        _logger.Collector.Clear();

        await _sut.RegisterAsync(request);

        var record = SingleEvent(1011);
        // UserName is the email, so a duplicate trips this code whether or not RequireUniqueEmail is on.
        Assert.Contains("DuplicateUserName", record.Message);
        Assert.DoesNotContain(request.Email, record.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(_logger.Collector.GetSnapshot(), r => r.Id.Id == 1010);
    }

    [Fact]
    public async Task LoginAsync_WhenSuccessful_LogsLoginSucceededWithUserId()
    {
        var email = await RegisterUserAsync();
        var userId = await UserIdForAsync(email);

        await _sut.LoginAsync(new LoginRequest { Email = email, Password = Password });

        var record = SingleEvent(1020);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(userId.ToString(), State(record, "UserId"));
    }

    [Fact]
    public async Task LoginAsync_WithUnknownEmail_LogsAWarningThatCarriesNoIdentifier()
    {
        const string email = "nobody@example.com";

        await _sut.LoginAsync(new LoginRequest { Email = email, Password = Password });

        var record = SingleEvent(1021);
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.DoesNotContain(email, record.Message, StringComparison.OrdinalIgnoreCase);
        Assert.All(record.StructuredState ?? [], pair => Assert.DoesNotContain(email, pair.Value ?? string.Empty));
    }

    [Fact]
    public async Task LoginAsync_WithWrongPassword_LogsTheAttemptCountTowardLockout()
    {
        var email = await RegisterUserAsync();
        var userId = await UserIdForAsync(email);

        await _sut.LoginAsync(new LoginRequest { Email = email, Password = "WrongPassword1!" });

        var record = SingleEvent(1022);
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(userId.ToString(), State(record, "UserId"));
        Assert.Equal("1", State(record, "FailedAttempts"));
        Assert.Equal(MaxFailedAccessAttempts.ToString(), State(record, "MaxFailedAttempts"));
    }

    [Fact]
    public async Task LoginAsync_ReachingTheFailureThreshold_LogsTheLockoutOnceInsteadOfAFailedAttempt()
    {
        var email = await RegisterUserAsync();
        var userId = await UserIdForAsync(email);

        for (var attempt = 0; attempt < MaxFailedAccessAttempts; attempt++)
        {
            await _sut.LoginAsync(new LoginRequest { Email = email, Password = "WrongPassword1!" });
        }

        var events = _logger.Collector.GetSnapshot();
        Assert.Equal(MaxFailedAccessAttempts - 1, events.Count(r => r.Id.Id == 1022));
        var lockout = SingleEvent(1023);
        Assert.Equal(userId.ToString(), State(lockout, "UserId"));
        Assert.False(string.IsNullOrEmpty(State(lockout, "LockoutEndUtc")));
    }

    [Fact]
    public async Task LoginAsync_ForALockedOutAccount_LogsTheRejectionEvenWithTheRightPassword()
    {
        var email = await RegisterUserAsync();
        await LockOutAsync(email);
        _logger.Collector.Clear();

        await _sut.LoginAsync(new LoginRequest { Email = email, Password = Password });

        var record = SingleEvent(1024);
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.DoesNotContain(_logger.Collector.GetSnapshot(), r => r.Id.Id == 1020);
    }

    [Fact]
    public async Task RefreshAsync_WhenSuccessful_LogsAtDebugOnly()
    {
        var session = await LoginAsync();
        _logger.Collector.Clear();

        await _sut.RefreshAsync(new RefreshRequest { RefreshToken = session.RefreshToken });

        Assert.Equal(LogLevel.Debug, SingleEvent(1030).Level);
    }

    [Fact]
    public async Task RefreshAsync_WithUnknownToken_LogsTheRejectionReasonWithoutAUser()
    {
        await _sut.RefreshAsync(new RefreshRequest { RefreshToken = _refreshTokens.GenerateToken() });

        var record = SingleEvent(1031);
        Assert.Equal(nameof(RefreshRejectionReason.UnknownToken), State(record, "Reason"));
        Assert.True(string.IsNullOrEmpty(State(record, "UserId")));
    }

    [Fact]
    public async Task RefreshAsync_WithExpiredToken_LogsTheRejectionReasonAndUser()
    {
        var userId = await RegisterUserAndGetIdAsync();
        var expiredToken = await StoreRefreshTokenAsync(userId, expiresAtUtc: DateTime.UtcNow.AddMinutes(-1));

        await _sut.RefreshAsync(new RefreshRequest { RefreshToken = expiredToken });

        var record = SingleEvent(1031);
        Assert.Equal(nameof(RefreshRejectionReason.ExpiredToken), State(record, "Reason"));
        Assert.Equal(userId.ToString(), State(record, "UserId"));
    }

    [Fact]
    public async Task RefreshAsync_ReplayingARotatedToken_LogsReuseWithTheNumberOfTokensRevoked()
    {
        var session = await LoginAsync();
        await _sut.RefreshAsync(new RefreshRequest { RefreshToken = session.RefreshToken });
        _logger.Collector.Clear();

        await _sut.RefreshAsync(new RefreshRequest { RefreshToken = session.RefreshToken });

        var record = SingleEvent(1032);
        Assert.Equal(LogLevel.Warning, record.Level);
        // The replayed token was already revoked; only its successor was still outstanding.
        Assert.Equal("1", State(record, "RevokedTokenCount"));
    }

    [Fact]
    public async Task RefreshAsync_ForALockedOutAccount_LogsTheLockoutRejection()
    {
        var session = await LoginAsync();
        var userId = (await FindStoredTokenAsync(session.RefreshToken)).UserId;
        var userManager = _services.GetRequiredService<UserManager<ApplicationUser>>();
        await userManager.SetLockoutEndDateAsync((await userManager.FindByIdAsync(userId.ToString()))!, DateTimeOffset.UtcNow.AddMinutes(15));
        _logger.Collector.Clear();

        await _sut.RefreshAsync(new RefreshRequest { RefreshToken = session.RefreshToken });

        var record = SingleEvent(1033);
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(userId.ToString(), State(record, "UserId"));
    }

    [Fact]
    public async Task AuthFlows_NeverWritePasswordsTokensOrEmailsToTheLog()
    {
        // Drives every path that touches a secret — registration, good and bad logins, a lockout,
        // a rotation and a replay — then searches everything that was logged for any of them.
        var request = RegisterRequest();
        await _sut.RegisterAsync(request);
        await _sut.RegisterAsync(request);
        await _sut.LoginAsync(new LoginRequest { Email = "nobody@example.com", Password = Password });
        var login = await _sut.LoginAsync(new LoginRequest { Email = request.Email, Password = Password });
        var refreshed = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = login.Value!.RefreshToken });
        await _sut.RefreshAsync(new RefreshRequest { RefreshToken = login.Value.RefreshToken });
        await LockOutAsync(request.Email);

        string[] secrets =
        [
            Password,
            "WrongPassword1!",
            request.Email,
            "nobody@example.com",
            login.Value.AccessToken,
            login.Value.RefreshToken,
            refreshed.Value!.AccessToken,
            refreshed.Value.RefreshToken,
            _refreshTokens.Hash(login.Value.RefreshToken),
        ];

        var records = _logger.Collector.GetSnapshot();
        Assert.NotEmpty(records);
        foreach (var record in records)
        {
            var logged = (record.StructuredState ?? []).Select(pair => pair.Value).Append(record.Message);
            foreach (var secret in secrets)
            {
                Assert.DoesNotContain(logged, text => text?.Contains(secret, StringComparison.OrdinalIgnoreCase) is true);
            }
        }
    }

    private FakeLogRecord SingleEvent(int eventId) =>
        Assert.Single(_logger.Collector.GetSnapshot(), record => record.Id.Id == eventId);

    private static string? State(FakeLogRecord record, string key) => record.GetStructuredStateValue(key);

    private async Task<Guid> UserIdForAsync(string email)
    {
        var user = await _services.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email);
        return user!.Id;
    }

    private async Task LockOutAsync(string email)
    {
        for (var attempt = 0; attempt < MaxFailedAccessAttempts; attempt++)
        {
            await _sut.LoginAsync(new LoginRequest { Email = email, Password = "WrongPassword1!" });
        }
    }
}
