using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;
using VenueBooking.Modules.Identity.Authentication;
using VenueBooking.Modules.Identity.Domain;
using VenueBooking.Modules.Identity.Persistence;
using VenueBooking.Modules.Identity.Services;

namespace VenueBooking.UnitTests.Identity;

public sealed class AuthServiceTests : IDisposable
{
    private const string Password = "Passw0rd!";
    private const string InvalidRefreshTokenError = "Invalid or expired refresh token.";

    private readonly ServiceProvider _services;
    private readonly RefreshTokenGenerator _refreshTokens = new();
    private readonly AuthService _sut;

    public AuthServiceTests()
    {
        var collection = new ServiceCollection();

        collection.AddDbContext<IdentityDbContext>(options =>
            options.UseInMemoryDatabase(Guid.NewGuid().ToString()));

        collection
            .AddIdentityCore<ApplicationUser>(options =>
            {
                options.Password.RequiredLength = 8;
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddRoles<IdentityRole<Guid>>()
            .AddEntityFrameworkStores<IdentityDbContext>();

        _services = collection.BuildServiceProvider();

        // The Customer/Organizer/Admin roles must exist before AddToRoleAsync can assign them —
        // mirrors IdentityModuleExtensions.SeedIdentityRolesAsync at production startup.
        var roleManager = _services.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        foreach (var role in Enum.GetNames<UserRole>())
        {
            roleManager.CreateAsync(new IdentityRole<Guid>(role)).GetAwaiter().GetResult();
        }

        var jwtOptions = Options.Create(new JwtOptions
        {
            Issuer = "VenueBooking.Tests",
            Audience = "VenueBooking.Tests",
            SigningKey = "unit-test-signing-key-at-least-32-bytes-long!!",
            AccessTokenMinutes = 15,
            RefreshTokenDays = 7,
        });

        _sut = new AuthService(
            _services.GetRequiredService<UserManager<ApplicationUser>>(),
            new JwtTokenGenerator(jwtOptions),
            _refreshTokens,
            _services.GetRequiredService<IdentityDbContext>(),
            jwtOptions);
    }

    [Fact]
    public async Task RegisterAsync_WithValidRequest_CreatesUserWithRequestedRole()
    {
        var request = RegisterRequest(role: UserRole.Organizer);

        var result = await _sut.RegisterAsync(request);

        Assert.True(result.Succeeded);
        Assert.Equal(request.Email, result.Value!.Email);
        Assert.Equal(UserRole.Organizer, result.Value.Role);

        var userManager = _services.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync(request.Email);
        Assert.NotNull(user);
        Assert.True(await userManager.IsInRoleAsync(user!, nameof(UserRole.Organizer)));
    }

    [Fact]
    public async Task RegisterAsync_WithDuplicateEmail_Fails()
    {
        var request = RegisterRequest();
        await _sut.RegisterAsync(request);

        var result = await _sut.RegisterAsync(request);

        Assert.False(result.Succeeded);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public async Task LoginAsync_WithValidCredentials_ReturnsAccessAndRefreshTokens()
    {
        var email = await RegisterUserAsync();

        var result = await _sut.LoginAsync(new LoginRequest { Email = email, Password = Password });

        Assert.True(result.Succeeded);
        Assert.False(string.IsNullOrWhiteSpace(result.Value!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(result.Value.RefreshToken));
        Assert.True(result.Value.AccessTokenExpiresAtUtc > DateTime.UtcNow);
    }

    [Fact]
    public async Task LoginAsync_PersistsOnlyTheRefreshTokenHash_NotTheRawToken()
    {
        var email = await RegisterUserAsync();

        var result = await _sut.LoginAsync(new LoginRequest { Email = email, Password = Password });

        var stored = await Db.RefreshTokens.SingleAsync();
        Assert.NotEqual(result.Value!.RefreshToken, stored.TokenHash);
        Assert.Equal(_refreshTokens.Hash(result.Value.RefreshToken), stored.TokenHash);
    }

    [Fact]
    public async Task LoginAsync_WithWrongPassword_ReturnsGenericError()
    {
        var email = await RegisterUserAsync();

        var result = await _sut.LoginAsync(new LoginRequest { Email = email, Password = "WrongPassword1!" });

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid email or password.", Assert.Single(result.Errors));
    }

    [Fact]
    public async Task LoginAsync_WithUnknownEmail_ReturnsTheSameGenericErrorAsWrongPassword()
    {
        // Regression guard: must not let an attacker distinguish "no such account" from "wrong
        // password" by comparing error messages (user-enumeration prevention).
        var result = await _sut.LoginAsync(new LoginRequest { Email = "nobody@example.com", Password = Password });

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid email or password.", Assert.Single(result.Errors));
    }

    [Fact]
    public async Task RefreshAsync_WithValidToken_ReturnsANewTokenPairWithoutCredentials()
    {
        var session = await LoginAsync();

        var result = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = session.RefreshToken });

        Assert.True(result.Succeeded);
        Assert.False(string.IsNullOrWhiteSpace(result.Value!.AccessToken));
        Assert.NotEqual(session.AccessToken, result.Value.AccessToken);
        Assert.NotEqual(session.RefreshToken, result.Value.RefreshToken);
        Assert.True(result.Value.AccessTokenExpiresAtUtc > DateTime.UtcNow);
    }

    [Fact]
    public async Task RefreshAsync_RotatesThePresentedToken_RevokingItAndLinkingItsSuccessor()
    {
        var session = await LoginAsync();

        var result = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = session.RefreshToken });

        var presented = await FindStoredTokenAsync(session.RefreshToken);
        var successor = await FindStoredTokenAsync(result.Value!.RefreshToken);
        Assert.True(presented.IsRevoked);
        Assert.Equal(successor.Id, presented.ReplacedByTokenId);
        Assert.True(successor.IsActive(DateTime.UtcNow));
    }

    [Fact]
    public async Task RefreshAsync_CanBeRepeated_SoASessionSurvivesSuccessiveRenewals()
    {
        var session = await LoginAsync();

        var refreshToken = session.RefreshToken;
        for (var renewal = 0; renewal < 3; renewal++)
        {
            var result = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = refreshToken });

            Assert.True(result.Succeeded);
            refreshToken = result.Value!.RefreshToken;
        }
    }

    [Fact]
    public async Task RefreshAsync_WithUnknownToken_Fails()
    {
        var result = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = _refreshTokens.GenerateToken() });

        Assert.False(result.Succeeded);
        Assert.Equal(InvalidRefreshTokenError, Assert.Single(result.Errors));
    }

    [Fact]
    public async Task RefreshAsync_WithExpiredToken_Fails()
    {
        var userId = await RegisterUserAndGetIdAsync();
        var expiredToken = await StoreRefreshTokenAsync(userId, expiresAtUtc: DateTime.UtcNow.AddMinutes(-1));

        var result = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = expiredToken });

        Assert.False(result.Succeeded);
        Assert.Equal(InvalidRefreshTokenError, Assert.Single(result.Errors));
    }

    [Fact]
    public async Task RefreshAsync_ReplayingAnAlreadyRotatedToken_FailsAndRevokesTheWholeFamily()
    {
        var session = await LoginAsync();
        var rotated = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = session.RefreshToken });

        // The rotated-out token coming back a second time means it leaked — the successor that a
        // thief would be holding has to die with it, even though it was still valid a moment ago.
        var replay = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = session.RefreshToken });

        Assert.False(replay.Succeeded);
        Assert.Equal(InvalidRefreshTokenError, Assert.Single(replay.Errors));
        Assert.All(await Db.RefreshTokens.ToListAsync(), token => Assert.True(token.IsRevoked));

        var successorAfterReplay = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = rotated.Value!.RefreshToken });
        Assert.False(successorAfterReplay.Succeeded);
    }

    [Fact]
    public async Task RefreshAsync_ForALockedOutAccount_Fails()
    {
        // A refresh token issued before the lockout must not keep the session alive through it.
        var session = await LoginAsync();
        var userManager = _services.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByIdAsync((await FindStoredTokenAsync(session.RefreshToken)).UserId.ToString());
        await userManager.SetLockoutEndDateAsync(user!, DateTimeOffset.UtcNow.AddMinutes(15));

        var result = await _sut.RefreshAsync(new RefreshRequest { RefreshToken = session.RefreshToken });

        Assert.False(result.Succeeded);
        Assert.NotEmpty(result.Errors);
    }

    private IdentityDbContext Db => _services.GetRequiredService<IdentityDbContext>();

    private async Task<LoginResponse> LoginAsync()
    {
        var email = await RegisterUserAsync();
        var result = await _sut.LoginAsync(new LoginRequest { Email = email, Password = Password });
        Assert.True(result.Succeeded);
        return result.Value!;
    }

    private async Task<string> RegisterUserAsync()
    {
        var request = RegisterRequest();
        var result = await _sut.RegisterAsync(request);
        Assert.True(result.Succeeded);
        return request.Email;
    }

    private async Task<Guid> RegisterUserAndGetIdAsync()
    {
        var email = await RegisterUserAsync();
        var user = await _services.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email);
        return user!.Id;
    }

    /// <summary>
    /// Plants a refresh token directly, so tests can arrange states (an expired one, say) that
    /// the service itself would never produce.
    /// </summary>
    private async Task<string> StoreRefreshTokenAsync(Guid userId, DateTime expiresAtUtc)
    {
        var rawToken = _refreshTokens.GenerateToken();

        Db.RefreshTokens.Add(new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = _refreshTokens.Hash(rawToken),
            CreatedAtUtc = DateTime.UtcNow.AddDays(-8),
            ExpiresAtUtc = expiresAtUtc,
        });
        await Db.SaveChangesAsync();

        return rawToken;
    }

    private Task<RefreshToken> FindStoredTokenAsync(string rawToken)
    {
        var tokenHash = _refreshTokens.Hash(rawToken);
        return Db.RefreshTokens.SingleAsync(t => t.TokenHash == tokenHash);
    }

    private static RegisterRequest RegisterRequest(string? email = null, UserRole role = UserRole.Customer) => new()
    {
        Email = email ?? $"{Guid.NewGuid():N}@example.com",
        Password = Password,
        ConfirmPassword = Password,
        Role = role,
    };

    public void Dispose() => _services.Dispose();
}
