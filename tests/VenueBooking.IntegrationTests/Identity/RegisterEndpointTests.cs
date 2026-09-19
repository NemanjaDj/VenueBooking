using System.Net;
using System.Net.Http.Json;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;

namespace VenueBooking.IntegrationTests.Identity;

public sealed class RegisterEndpointTests(ApiFactory factory) : IClassFixture<ApiFactory>, IAsyncLifetime
{
    private readonly HttpClient _client = factory.CreateClient();

    public Task InitializeAsync() => factory.SeedRolesAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Register_WithValidCustomerRequest_ReturnsCreated()
    {
        var request = ValidRequest(role: UserRole.Customer);

        var response = await _client.PostAsJsonAsync("/api/auth/register", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.Equal(request.Email, body!.Email);
        Assert.Equal(UserRole.Customer, body.Role);
    }

    [Fact]
    public async Task Register_WithAdminRole_ReturnsBadRequest()
    {
        var request = ValidRequest(role: UserRole.Admin);

        var response = await _client.PostAsJsonAsync("/api/auth/register", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_WithAlreadyRegisteredEmail_ReturnsBadRequest()
    {
        var request = ValidRequest();
        await _client.PostAsJsonAsync("/api/auth/register", request);

        var response = await _client.PostAsJsonAsync("/api/auth/register", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static RegisterRequest ValidRequest(UserRole role = UserRole.Customer) => new()
    {
        Email = $"{Guid.NewGuid():N}@example.com",
        Password = "Passw0rd!",
        ConfirmPassword = "Passw0rd!",
        Role = role,
    };
}
