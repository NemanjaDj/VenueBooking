using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VenueBooking.Contracts.Identity;
using VenueBooking.Modules.Identity.Authentication;
using VenueBooking.Modules.Identity.Services;

namespace VenueBooking.Api.Controllers;

/// <summary>
/// The endpoints a caller uses before it has a session, plus the one that reports what the
/// session it ended up with actually is.
/// </summary>
/// <remarks>
/// The API runs with a fallback policy requiring an authenticated caller, so the three
/// credential-exchange endpoints here opt out explicitly with <see cref="AllowAnonymousAttribute"/>
/// — they are the only way to obtain a token in the first place. Every other endpoint in the
/// system is protected whether or not it says so.
/// </remarks>
[ApiController]
[Route("api/auth")]
public sealed class AuthController(IAuthService authService) : ControllerBase
{
    [AllowAnonymous]
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

    [AllowAnonymous]
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
    [AllowAnonymous]
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

    /// <summary>
    /// Reports the identity behind the caller's access token, so a client can render the right
    /// navigation without decoding the JWT itself — and so "which roles do I actually have here?"
    /// has an answer that comes from the server that will be enforcing them.
    /// </summary>
    [Authorize]
    [HttpGet("me")]
    [ProducesResponseType(typeof(CurrentUserResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public IActionResult Me()
    {
        if (!User.TryGetUserId(out var userId))
        {
            // A token that validated but carries no usable subject is not one this API issued in
            // the shape it expects. Better to treat the caller as signed out than to invent an
            // identity for them.
            return ToUnauthorizedProblem([], fallbackTitle: "The access token carries no usable subject claim.");
        }

        return Ok(new CurrentUserResponse(userId, User.GetEmail(), User.GetRoles()));
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
