using System.Net;
using System.Net.Http.Json;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;

namespace VenueBooking.IntegrationTests.Identity;

public sealed class RefreshEndpointTests(ApiFactory factory) : IClassFixture<ApiFactory>, IAsyncLifetime
{
    private const string Password = "Passw0rd!";

    private readonly HttpClient _client = factory.CreateClient();

    public Task InitializeAsync() => factory.SeedRolesAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Refresh_WithTokenFromLogin_ReturnsOkWithANewTokenPair()
    {
        var session = await LoginAsync();

        var response = await _client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest { RefreshToken = session.RefreshToken });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.False(string.IsNullOrWhiteSpace(body!.AccessToken));
        Assert.NotEqual(session.RefreshToken, body.RefreshToken);
        Assert.True(body.AccessTokenExpiresAtUtc > DateTime.UtcNow);
    }

    [Fact]
    public async Task Refresh_WithTheRotatedToken_KeepsTheSessionGoing()
    {
        var session = await LoginAsync();

        var renewed = await RefreshAsync(session.RefreshToken);
        var response = await _client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest { RefreshToken = renewed.RefreshToken });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_ReusingAConsumedToken_ReturnsUnauthorized()
    {
        var session = await LoginAsync();
        await RefreshAsync(session.RefreshToken);

        var response = await _client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest { RefreshToken = session.RefreshToken });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_WithUnknownToken_ReturnsUnauthorized()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/auth/refresh",
            new RefreshRequest { RefreshToken = Convert.ToBase64String(Guid.NewGuid().ToByteArray()) });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_WithoutAToken_ReturnsBadRequest()
    {
        // A missing token is a malformed request, not a rejected credential — model validation
        // should catch it before the service ever runs.
        var response = await _client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest { RefreshToken = string.Empty });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private async Task<LoginResponse> LoginAsync()
    {
        var email = $"{Guid.NewGuid():N}@example.com";
        var registerResponse = await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest
        {
            Email = email,
            Password = Password,
            ConfirmPassword = Password,
            Role = UserRole.Customer,
        });
        Assert.Equal(HttpStatusCode.Created, registerResponse.StatusCode);

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = Password });
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        return (await loginResponse.Content.ReadFromJsonAsync<LoginResponse>())!;
    }

    private async Task<LoginResponse> RefreshAsync(string refreshToken)
    {
        var response = await _client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest { RefreshToken = refreshToken });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<LoginResponse>())!;
    }
}
