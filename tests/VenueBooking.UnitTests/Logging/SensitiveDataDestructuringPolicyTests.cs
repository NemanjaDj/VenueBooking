using Serilog;
using Serilog.Core;
using Serilog.Events;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;
using VenueBooking.Logging;

namespace VenueBooking.UnitTests.Logging;

public sealed class SensitiveDataDestructuringPolicyTests
{
    private readonly SensitiveDataDestructuringPolicy _sut = new();

    [Fact]
    public void TryDestructure_MasksSecretsAndPersonalData()
    {
        var request = new LoginRequest { Email = "someone@example.com", Password = "Passw0rd!" };

        Assert.True(_sut.TryDestructure(request, new ScalarValueFactory(), out var result));

        var properties = PropertiesOf(result);
        Assert.Equal(SensitiveDataDestructuringPolicy.RedactedValue, properties["Password"]);
        Assert.Equal(SensitiveDataDestructuringPolicy.RedactedValue, properties["Email"]);
    }

    [Fact]
    public void TryDestructure_KeepsPropertiesThatAreSafeToLog()
    {
        // The whole object isn't dropped — the identifiers that make a log entry useful survive.
        var response = new RegisterResponse(Guid.NewGuid(), "someone@example.com", UserRole.Organizer);

        Assert.True(_sut.TryDestructure(response, new ScalarValueFactory(), out var result));

        var properties = PropertiesOf(result);
        Assert.Equal(response.Id, properties["Id"]);
        Assert.Equal(UserRole.Organizer, properties["Role"]);
        Assert.Equal(SensitiveDataDestructuringPolicy.RedactedValue, properties["Email"]);
    }

    [Theory]
    [InlineData("ConfirmPassword")]
    [InlineData("RefreshToken")]
    [InlineData("TokenHash")]
    [InlineData("SigningKey")]
    public void TryDestructure_MatchesSensitiveNamesAsSubstrings(string propertyName)
    {
        // Compound names are the ones that slip through a whole-word match, and they carry
        // exactly the same secrets as the bare name does.
        var value = new CompoundNameSample { ConfirmPassword = "x", RefreshToken = "x", TokenHash = "x", SigningKey = "x" };

        Assert.True(_sut.TryDestructure(value, new ScalarValueFactory(), out var result));

        Assert.Equal(SensitiveDataDestructuringPolicy.RedactedValue, PropertiesOf(result)[propertyName]);
    }

    [Fact]
    public void TryDestructure_LeavesTypesOutsideTheSolutionToSerilog()
    {
        Assert.False(_sut.TryDestructure(new Uri("https://example.com"), new ScalarValueFactory(), out _));
    }

    [Fact]
    public void WhenConfiguredOnALogger_ASecretNeverReachesTheSink()
    {
        // End-to-end proof through a real logger: this is the accident the policy exists to catch,
        // a whole request object destructured into a log event.
        var sink = new CollectingSink();
        using var logger = new LoggerConfiguration()
            .Destructure.With(_sut)
            .WriteTo.Sink(sink)
            .CreateLogger();

        logger.Information(
            "Login attempted {@Request}",
            new LoginRequest { Email = "someone@example.com", Password = "Passw0rd!" });

        var rendered = Assert.Single(sink.Events).RenderMessage();
        Assert.DoesNotContain("Passw0rd!", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("someone@example.com", rendered, StringComparison.Ordinal);
        Assert.Contains(SensitiveDataDestructuringPolicy.RedactedValue, rendered, StringComparison.Ordinal);
    }

    private static Dictionary<string, object?> PropertiesOf(LogEventPropertyValue? value)
    {
        var structure = Assert.IsType<StructureValue>(value);
        return structure.Properties.ToDictionary(
            property => property.Name,
            property => (property.Value as ScalarValue)?.Value);
    }

    private sealed class CompoundNameSample
    {
        public required string ConfirmPassword { get; init; }
        public required string RefreshToken { get; init; }
        public required string TokenHash { get; init; }
        public required string SigningKey { get; init; }
    }

    /// <summary>Stands in for Serilog's factory: every value becomes a scalar, so assertions can
    /// read property values directly.</summary>
    private sealed class ScalarValueFactory : ILogEventPropertyValueFactory
    {
        public LogEventPropertyValue CreatePropertyValue(object? value, bool destructureObjects = false) =>
            new ScalarValue(value);
    }

    private sealed class CollectingSink : ILogEventSink
    {
        public List<LogEvent> Events { get; } = [];

        public void Emit(LogEvent logEvent) => Events.Add(logEvent);
    }
}
