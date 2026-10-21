using System.Net;
using System.Net.Http.Json;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;

namespace VenueBooking.IntegrationTests.Identity;

public sealed class CurrentUserEndpointTests(ApiFactory factory) : IClassFixture<ApiFactory>, IAsyncLifetime
{
    public Task InitializeAsync() => factory.SeedRolesAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Me_WithoutAToken_ReturnsUnauthorized()
    {
        var response = await factory.CreateClient().GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(UserRole.Customer)]
    [InlineData(UserRole.Organizer)]
    [InlineData(UserRole.Admin)]
    public async Task Me_ReturnsTheRoleTheTokenCarries(UserRole role)
    {
        var client = await factory.SignInAsync(role);

        var response = await client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<CurrentUserResponse>();
        Assert.Equal([role], body!.Roles);
        Assert.NotEqual(Guid.Empty, body.UserId);
        Assert.False(string.IsNullOrWhiteSpace(body.Email));
    }

    [Fact]
    public async Task Me_ReportsTheSameUserAcrossRequests()
    {
        var client = await factory.SignInAsync(UserRole.Customer);

        var first = await client.GetFromJsonAsync<CurrentUserResponse>("/api/auth/me");
        var second = await client.GetFromJsonAsync<CurrentUserResponse>("/api/auth/me");

        Assert.Equal(first!.UserId, second!.UserId);
    }
}
