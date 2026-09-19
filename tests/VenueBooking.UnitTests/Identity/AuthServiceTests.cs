using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;
using VenueBooking.Modules.Identity.Domain;
using VenueBooking.Modules.Identity.Persistence;
using VenueBooking.Modules.Identity.Services;

namespace VenueBooking.UnitTests.Identity;

public sealed class AuthServiceTests : IDisposable
{
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

        _sut = new AuthService(_services.GetRequiredService<UserManager<ApplicationUser>>());
    }

    [Fact]
    public async Task RegisterAsync_WithValidRequest_CreatesUserWithRequestedRole()
    {
        var request = ValidRequest(role: UserRole.Organizer);

        var result = await _sut.RegisterAsync(request);

        Assert.True(result.Succeeded);
        Assert.Equal(request.Email, result.User!.Email);
        Assert.Equal(UserRole.Organizer, result.User.Role);

        var userManager = _services.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync(request.Email);
        Assert.NotNull(user);
        Assert.True(await userManager.IsInRoleAsync(user!, nameof(UserRole.Organizer)));
    }

    [Fact]
    public async Task RegisterAsync_WithDuplicateEmail_Fails()
    {
        var request = ValidRequest();
        await _sut.RegisterAsync(request);

        var result = await _sut.RegisterAsync(request);

        Assert.False(result.Succeeded);
        Assert.NotEmpty(result.Errors);
    }

    private static RegisterRequest ValidRequest(string? email = null, UserRole role = UserRole.Customer) => new()
    {
        Email = email ?? $"{Guid.NewGuid():N}@example.com",
        Password = "Passw0rd!",
        ConfirmPassword = "Passw0rd!",
        Role = role,
    };

    public void Dispose() => _services.Dispose();
}
