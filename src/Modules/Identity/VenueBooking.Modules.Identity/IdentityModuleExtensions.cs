using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using VenueBooking.Contracts.Enums;
using VenueBooking.Modules.Identity.Domain;
using VenueBooking.Modules.Identity.Persistence;
using VenueBooking.Modules.Identity.Services;

namespace VenueBooking.Modules.Identity;

public static class IdentityModuleExtensions
{
    public static IServiceCollection AddIdentityModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<IdentityDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("Default")));

        services
            .AddIdentityCore<ApplicationUser>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.Password.RequiredLength = 8;
            })
            .AddRoles<IdentityRole<Guid>>()
            .AddEntityFrameworkStores<IdentityDbContext>();

        services.AddScoped<IAuthService, AuthService>();

        return services;
    }

    /// <summary>
    /// Ensures the fixed set of <see cref="UserRole"/> roles exists. Must run before any
    /// registration request, since registration assigns a role by name. Admin *users* are still
    /// created manually — this only guarantees the Admin role itself is available to assign.
    /// </summary>
    public static async Task SeedIdentityRolesAsync(this IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

        foreach (var role in Enum.GetNames<UserRole>())
        {
            if (await roleManager.RoleExistsAsync(role))
            {
                continue;
            }

            var result = await roleManager.CreateAsync(new IdentityRole<Guid>(role));
            if (!result.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to seed role '{role}': {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }
        }
    }
}
