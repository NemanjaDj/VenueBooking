using System.Net;
using System.Text.Json;

namespace VenueBooking.IntegrationTests.Identity;

/// <summary>
/// The generated document is how an API consumer learns that this API needs a token and which
/// endpoints need one. It is derived from each endpoint's own authorization metadata, so these
/// tests also catch a document that has drifted away from what the pipeline enforces.
/// </summary>
public sealed class OpenApiSecurityDocumentTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task Document_IsReadableWithoutAToken()
    {
        var response = await factory.CreateClient().GetAsync("/openapi/v1.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Document_DeclaresTheBearerScheme()
    {
        var document = await GetDocumentAsync();

        var scheme = document.RootElement
            .GetProperty("components")
            .GetProperty("securitySchemes")
            .GetProperty("Bearer");

        Assert.Equal("http", scheme.GetProperty("type").GetString());
        Assert.Equal("bearer", scheme.GetProperty("scheme").GetString());
    }

    [Theory]
    [InlineData("/api/auth/me", "get")]
    [InlineData("/api/test-probes/authorization/unattributed", "get")]
    public async Task ProtectedOperation_IsDocumentedAsRequiringABearerToken(string path, string method)
    {
        var operation = await GetOperationAsync(path, method);

        var requirement = Assert.Single(operation.GetProperty("security").EnumerateArray());
        Assert.True(requirement.TryGetProperty("Bearer", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("401", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("403", out _));
    }

    [Theory]
    [InlineData("/api/auth/login", "post")]
    [InlineData("/api/auth/register", "post")]
    [InlineData("/api/auth/refresh", "post")]
    public async Task AnonymousOperation_IsNotDocumentedAsRequiringTheBearerScheme(string path, string method)
    {
        var operation = await GetOperationAsync(path, method);

        Assert.False(operation.TryGetProperty("security", out _));
    }

    private async Task<JsonElement> GetOperationAsync(string path, string method)
    {
        var document = await GetDocumentAsync();

        return document.RootElement.GetProperty("paths").GetProperty(path).GetProperty(method);
    }

    private async Task<JsonDocument> GetDocumentAsync() =>
        JsonDocument.Parse(await factory.CreateClient().GetStringAsync("/openapi/v1.json"));
}
