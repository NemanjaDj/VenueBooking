using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;

namespace VenueBooking.IntegrationTests.Identity;

internal static class TestSession
{
    public const string Password = "Passw0rd!";

    /// <summary>
    /// Creates a user in <paramref name="role"/> and returns a client that presents a real access
    /// token for it — issued by the login endpoint rather than hand-built, so these tests exercise
    /// the same token the API will meet in production, role claims and all.
    /// </summary>
    public static async Task<HttpClient> SignInAsync(this ApiFactory factory, UserRole role)
    {
        var email = $"{Guid.NewGuid():N}@example.com";
        await factory.CreateUserAsync(email, Password, role);

        var client = factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = Password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var session = (await response.Content.ReadFromJsonAsync<LoginResponse>())!;
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, session.AccessToken);

        return client;
    }
}
