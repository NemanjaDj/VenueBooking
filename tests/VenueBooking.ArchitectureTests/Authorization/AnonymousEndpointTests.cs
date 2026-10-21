using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using VenueBooking.Api.Controllers;

namespace VenueBooking.ArchitectureTests.Authorization;

/// <summary>
/// The API is closed by default, so the interesting list is the short one: the endpoints that are
/// deliberately open. Asserting it exactly means widening the public surface takes an edit here
/// too — a reviewable moment rather than an attribute nobody notices.
/// </summary>
public sealed class AnonymousEndpointTests
{
    /// <summary>
    /// The endpoints a caller must be able to reach before it holds a token. Everything else is
    /// behind the fallback policy or an explicit role policy.
    /// </summary>
    private static readonly string[] IntentionallyAnonymousEndpoints =
    [
        "AuthController.Register",
        "AuthController.Login",
        "AuthController.Refresh",
    ];

    [Fact]
    public void OnlyTheExpectedEndpointsAllowAnonymousCallers()
    {
        var anonymous = typeof(AuthController).Assembly
            .GetTypes()
            .Where(type => typeof(ControllerBase).IsAssignableFrom(type) && !type.IsAbstract)
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(IsEndpoint)
            .Where(AllowsAnonymous)
            .Select(action => $"{action.DeclaringType!.Name}.{action.Name}")
            .Order()
            .ToArray();

        Assert.Equal(IntentionallyAnonymousEndpoints.Order(), anonymous);
    }

    private static bool IsEndpoint(MethodInfo action) =>
        action.GetCustomAttributes<HttpMethodAttribute>(inherit: true).Any();

    // Inherited from the controller as well as declared on the action, because [AllowAnonymous]
    // at the class level opens every endpoint underneath it.
    private static bool AllowsAnonymous(MethodInfo action) =>
        action.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any()
        || action.DeclaringType!.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any();
}
