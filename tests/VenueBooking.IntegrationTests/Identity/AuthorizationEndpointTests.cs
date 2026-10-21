using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using VenueBooking.Contracts.Enums;

namespace VenueBooking.IntegrationTests.Identity;

/// <summary>
/// Exercises the authorization rules through the real pipeline — token validation, policy
/// evaluation and all — against <see cref="AuthorizationProbeController"/>.
/// </summary>
public sealed class AuthorizationEndpointTests(ApiFactory factory) : IClassFixture<ApiFactory>, IAsyncLifetime
{
    private const string ProbeRoute = "/api/test-probes/authorization";

    private readonly HttpClient _anonymousClient = factory.CreateClient();

    public Task InitializeAsync() => factory.SeedRolesAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task EndpointWithoutAnAuthorizeAttribute_IsStillClosedToAnonymousCallers()
    {
        // The fallback policy is what makes forgetting [Authorize] safe rather than silent.
        var response = await _anonymousClient.GetAsync($"{ProbeRoute}/unattributed");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task EndpointMarkedAllowAnonymous_IsReachableWithoutAToken()
    {
        var response = await _anonymousClient.GetAsync($"{ProbeRoute}/anonymous");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData(UserRole.Customer)]
    [InlineData(UserRole.Organizer)]
    [InlineData(UserRole.Admin)]
    public async Task EndpointRequiringOnlyAuthentication_AdmitsEveryRole(UserRole role)
    {
        var client = await factory.SignInAsync(role);

        var response = await client.GetAsync($"{ProbeRoute}/authenticated");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    public static TheoryData<string, UserRole, HttpStatusCode> RoleMatrix => new()
    {
        { "customer", UserRole.Customer, HttpStatusCode.OK },
        { "customer", UserRole.Organizer, HttpStatusCode.Forbidden },
        // An Admin is not implicitly a Customer: the roles describe different jobs, and a booking
        // made by "the admin role" would have no owner the Booking module could reason about.
        { "customer", UserRole.Admin, HttpStatusCode.Forbidden },

        { "organizer", UserRole.Organizer, HttpStatusCode.OK },
        { "organizer", UserRole.Customer, HttpStatusCode.Forbidden },
        { "organizer", UserRole.Admin, HttpStatusCode.Forbidden },

        { "admin", UserRole.Admin, HttpStatusCode.OK },
        { "admin", UserRole.Customer, HttpStatusCode.Forbidden },
        { "admin", UserRole.Organizer, HttpStatusCode.Forbidden },

        { "organizer-or-admin", UserRole.Organizer, HttpStatusCode.OK },
        { "organizer-or-admin", UserRole.Admin, HttpStatusCode.OK },
        { "organizer-or-admin", UserRole.Customer, HttpStatusCode.Forbidden },
    };

    [Theory]
    [MemberData(nameof(RoleMatrix))]
    public async Task RoleProtectedEndpoint_AdmitsExactlyTheRolesItsPolicyNames(
        string endpoint,
        UserRole role,
        HttpStatusCode expected)
    {
        var client = await factory.SignInAsync(role);

        var response = await client.GetAsync($"{ProbeRoute}/{endpoint}");

        Assert.Equal(expected, response.StatusCode);
    }

    [Theory]
    [InlineData("customer")]
    [InlineData("organizer")]
    [InlineData("admin")]
    [InlineData("organizer-or-admin")]
    public async Task RoleProtectedEndpoint_ChallengesAnAnonymousCallerRatherThanForbiddingThem(string endpoint)
    {
        // 401, not 403: the caller hasn't failed a role check, it hasn't presented a token at all,
        // and the difference tells a client whether to sign in or to give up.
        var response = await _anonymousClient.GetAsync($"{ProbeRoute}/{endpoint}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithAMalformedToken_ReturnsUnauthorized()
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, "not.a.real.token");

        var response = await client.GetAsync($"{ProbeRoute}/authenticated");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithATokenSignedByAnotherKey_ReturnsUnauthorized()
    {
        // Same claims, wrong signature — the shape of a forged token.
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            JwtBearerDefaults.AuthenticationScheme,
            ForeignTokens.SignedAs(UserRole.Admin));

        var response = await client.GetAsync($"{ProbeRoute}/admin");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Unauthorized_IsReportedAsProblemDetails()
    {
        var response = await _anonymousClient.GetAsync($"{ProbeRoute}/authenticated");

        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Forbidden_IsReportedAsProblemDetails()
    {
        var client = await factory.SignInAsync(UserRole.Customer);

        var response = await client.GetAsync($"{ProbeRoute}/admin");

        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }
}
