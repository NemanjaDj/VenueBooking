using Microsoft.AspNetCore.Mvc;
using VenueBooking.Contracts.Identity;
using VenueBooking.Modules.Identity.Services;

namespace VenueBooking.Api.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(IAuthService authService) : ControllerBase
{
    [HttpPost("register")]
    [ProducesResponseType(typeof(RegisterResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken cancellationToken)
    {
        var result = await authService.RegisterAsync(request, cancellationToken);

        return result.Succeeded
            ? StatusCode(StatusCodes.Status201Created, result.Value)
            : ToValidationProblem(result.Errors);
    }

    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken cancellationToken)
    {
        var result = await authService.LoginAsync(request, cancellationToken);

        return result.Succeeded
            ? Ok(result.Value)
            : ToUnauthorizedProblem(result.Errors, fallbackTitle: "Invalid email or password.");
    }

    /// <summary>
    /// Renews an expiring session from the refresh token alone. Anonymous by design: the caller's
    /// access token has usually expired by the time it gets here, which is the whole point.
    /// </summary>
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh(RefreshRequest request, CancellationToken cancellationToken)
    {
        var result = await authService.RefreshAsync(request, cancellationToken);

        return result.Succeeded
            ? Ok(result.Value)
            : ToUnauthorizedProblem(result.Errors, fallbackTitle: "Invalid or expired refresh token.");
    }

    private ActionResult ToValidationProblem(IEnumerable<string> errors)
    {
        foreach (var error in errors)
        {
            ModelState.AddModelError(string.Empty, error);
        }

        return ValidationProblem(ModelState);
    }

    private UnauthorizedObjectResult ToUnauthorizedProblem(IReadOnlyCollection<string> errors, string fallbackTitle) =>
        Unauthorized(new ProblemDetails
        {
            Status = StatusCodes.Status401Unauthorized,
            Title = errors.FirstOrDefault() ?? fallbackTitle,
        });
}
