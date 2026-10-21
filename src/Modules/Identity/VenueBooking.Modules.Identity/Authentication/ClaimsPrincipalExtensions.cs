using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using VenueBooking.Contracts.Enums;

namespace VenueBooking.Modules.Identity.Authentication;

/// <summary>
/// Reads the claims written by <see cref="JwtTokenGenerator"/> back off a validated principal.
/// Centralised so that callers ask "who is this?" rather than naming claim types, and so the
/// token's shape is known in exactly the two places that decide it.
/// </summary>
public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// The caller's user id, for a principal that came from one of our access tokens.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The principal carries no parsable subject claim. Use <see cref="TryGetUserId"/> at a trust
    /// boundary; this overload is for code that already knows the request was authorized.
    /// </exception>
    public static Guid GetUserId(this ClaimsPrincipal principal) =>
        principal.TryGetUserId(out var userId)
            ? userId
            : throw new InvalidOperationException("The current principal carries no usable subject claim.");

    /// <summary>
    /// Attempts to read the caller's user id, returning <see langword="false"/> rather than
    /// throwing for an anonymous or unexpectedly shaped principal.
    /// </summary>
    public static bool TryGetUserId(this ClaimsPrincipal principal, out Guid userId)
    {
        // The token is issued with a "sub" claim, but JwtSecurityTokenHandler's inbound claim map
        // renames it to ClaimTypes.NameIdentifier during validation — so that is what a principal
        // in a request actually holds. Both are checked: a principal built straight from the raw
        // token (tests, or a host that turns the map off) still resolves.
        var value = principal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? principal.FindFirstValue(JwtRegisteredClaimNames.Sub);

        return Guid.TryParse(value, out userId);
    }

    /// <summary>The caller's email address, or <see langword="null"/> if the principal has none.</summary>
    public static string? GetEmail(this ClaimsPrincipal principal) =>
        principal.FindFirstValue(ClaimTypes.Email) ?? principal.FindFirstValue(JwtRegisteredClaimNames.Email);

    /// <summary>
    /// The caller's roles. Values that don't correspond to a <see cref="UserRole"/> are dropped
    /// rather than faulting the request: a role removed from the enum shouldn't break every
    /// still-valid token that was issued while it existed.
    /// </summary>
    public static IReadOnlyCollection<UserRole> GetRoles(this ClaimsPrincipal principal) =>
    [
        // Each identity names its own role claim type, which is what IsInRole honours — reading
        // ClaimTypes.Role directly would quietly return nothing if that type were ever changed.
        .. principal.Identities
            .SelectMany(identity => identity.FindAll(identity.RoleClaimType))
            .Select(claim => Enum.TryParse<UserRole>(claim.Value, ignoreCase: false, out var role) ? role : (UserRole?)null)
            .Where(role => role is not null)
            .Select(role => role!.Value)
            .Distinct()
    ];
}
