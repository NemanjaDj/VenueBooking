using VenueBooking.Contracts.Enums;

namespace VenueBooking.Modules.Identity.Authorization;

/// <summary>
/// The names of every authorization policy in the system. Endpoints reference these constants
/// instead of spelling out <c>[Authorize(Roles = "Organizer")]</c>, so a role rename is a compiler
/// error rather than a silently unenforced endpoint, and the full list of who-may-do-what is
/// readable in one place — <see cref="AuthorizationModuleExtensions.AddRoleAuthorization"/>.
/// </summary>
/// <remarks>
/// The single-role policies are named after the <see cref="UserRole"/> they admit, and admit only
/// that role: <see cref="Admin"/> is not implicitly an Organizer. An administrator who needs to
/// reach an organizer's endpoint gets there through a policy that says so — <see
/// cref="OrganizerOrAdmin"/> — which keeps "who can actually call this" answerable by reading the
/// attribute, and keeps ownership checks (Epic 2 onwards) from having to special-case a role that
/// quietly passes every policy.
/// </remarks>
public static class AuthorizationPolicies
{
    /// <summary>Booking the seats an Organizer laid out.</summary>
    public const string Customer = nameof(UserRole.Customer);

    /// <summary>Authoring events and their layouts.</summary>
    public const string Organizer = nameof(UserRole.Organizer);

    /// <summary>Platform administration: role assignment, moderation, operational tooling.</summary>
    public const string Admin = nameof(UserRole.Admin);

    /// <summary>
    /// Event administration that an owning Organizer and a platform Admin may both perform —
    /// moderating or cancelling an event, for instance. Being in this policy still says nothing
    /// about <em>which</em> events: that is an ownership check inside the handler, not a role.
    /// </summary>
    public const string OrganizerOrAdmin = nameof(OrganizerOrAdmin);
}
