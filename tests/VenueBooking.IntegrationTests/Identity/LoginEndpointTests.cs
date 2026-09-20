using System.Net;
using System.Net.Http.Json;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;

namespace VenueBooking.IntegrationTests.Identity;

public sealed class LoginEndpointTests(ApiFactory factory) : IClassFixture<ApiFactory>, IAsyncLifetime
{
    private const string Password = "Passw0rd!";

    private readonly HttpClient _client = factory.CreateClient();

    public Task InitializeAsync() => factory.SeedRolesAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Login_WithValidCredentials_ReturnsOkWithTokens()
    {
        var email = await RegisterUserAsync();

        var response = await _client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = Password });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.False(string.IsNullOrWhiteSpace(body!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(body.RefreshToken));
        Assert.True(body.AccessTokenExpiresAtUtc > DateTime.UtcNow);
    }

    [Fact]
    public async Task Login_WithWrongPassword_ReturnsUnauthorized()
    {
        var email = await RegisterUserAsync();

        var response = await _client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "WrongPassword1!" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_WithUnknownEmail_ReturnsUnauthorized()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/auth/login",
            new LoginRequest { Email = $"{Guid.NewGuid():N}@example.com", Password = Password });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private async Task<string> RegisterUserAsync()
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
        return email;
    }
}
