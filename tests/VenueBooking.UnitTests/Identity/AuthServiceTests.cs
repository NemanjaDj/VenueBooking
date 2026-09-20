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

    private readonly ServiceProvider _services;
    private readonly AuthService _sut;

    public AuthServiceTests()
    {
        var collection = new ServiceCollection();

        collection.AddDbContext<IdentityDbContext>(options =>
            options.UseInMemoryDatabase(Guid.NewGuid().ToString()));

        collection
            .AddIdentityCore<ApplicationUser>(options => options.Password.RequiredLength = 8)
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
            new RefreshTokenGenerator(),
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

        var db = _services.GetRequiredService<IdentityDbContext>();
        var stored = await db.RefreshTokens.SingleAsync();
        Assert.NotEqual(result.Value!.RefreshToken, stored.TokenHash);
        Assert.Equal(new RefreshTokenGenerator().Hash(result.Value.RefreshToken), stored.TokenHash);
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

    private async Task<string> RegisterUserAsync()
    {
        var request = RegisterRequest();
        var result = await _sut.RegisterAsync(request);
        Assert.True(result.Succeeded);
        return request.Email;
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
