using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VenueBooking.Modules.Identity.Authorization;

namespace VenueBooking.IntegrationTests.Identity;

/// <summary>
/// One endpoint per way of being protected, so the authorization rules can be exercised against
/// the real pipeline before any business endpoint exists to carry them.
/// </summary>
/// <remarks>
/// It lives in the test assembly and is contributed to the host as an MVC application part by
/// <see cref="ApiFactory"/>, so these routes exist only under test and can never be deployed.
/// Testing through purpose-built probes rather than through whichever business endpoint happens
/// to carry a given attribute also keeps the guarantees stable: the rules stay covered as the
/// real endpoints around them come and go.
/// </remarks>
[ApiController]
[Route("api/test-probes/authorization")]
public sealed class AuthorizationProbeController : ControllerBase
{
    /// <summary>Says nothing about authorization — the fallback policy should still protect it.</summary>
    [HttpGet("unattributed")]
    public IActionResult Unattributed() => Ok();

    [AllowAnonymous]
    [HttpGet("anonymous")]
    public IActionResult Anonymous() => Ok();

    [Authorize]
    [HttpGet("authenticated")]
    public IActionResult Authenticated() => Ok();

    [Authorize(Policy = AuthorizationPolicies.Customer)]
    [HttpGet("customer")]
    public IActionResult CustomerOnly() => Ok();

    [Authorize(Policy = AuthorizationPolicies.Organizer)]
    [HttpGet("organizer")]
    public IActionResult OrganizerOnly() => Ok();

    [Authorize(Policy = AuthorizationPolicies.Admin)]
    [HttpGet("admin")]
    public IActionResult AdminOnly() => Ok();

    [Authorize(Policy = AuthorizationPolicies.OrganizerOrAdmin)]
    [HttpGet("organizer-or-admin")]
    public IActionResult OrganizerOrAdmin() => Ok();
}
