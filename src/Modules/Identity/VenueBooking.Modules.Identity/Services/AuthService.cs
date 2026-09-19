using Microsoft.AspNetCore.Identity;
using VenueBooking.Contracts.Identity;
using VenueBooking.Modules.Identity.Domain;

namespace VenueBooking.Modules.Identity.Services;

internal sealed class AuthService(UserManager<ApplicationUser> userManager) : IAuthService
{
    public async Task<AuthResult> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
        };

        var createResult = await userManager.CreateAsync(user, request.Password);
        if (!createResult.Succeeded)
        {
            return AuthResult.Failure(createResult.Errors.Select(e => e.Description));
        }

        var roleName = request.Role.ToString();
        var roleResult = await userManager.AddToRoleAsync(user, roleName);
        if (!roleResult.Succeeded)
        {
            // Don't leave behind a user with no role assigned.
            await userManager.DeleteAsync(user);
            return AuthResult.Failure(roleResult.Errors.Select(e => e.Description));
        }

        return AuthResult.Success(new RegisterResponse(user.Id, user.Email!, request.Role));
    }
}
