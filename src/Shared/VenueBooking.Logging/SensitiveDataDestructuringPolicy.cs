using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Serilog.Core;
using Serilog.Events;

namespace VenueBooking.Logging;

/// <summary>
/// Masks secrets and personal data when an object is destructured into a log event — the
/// <c>logger.LogInformation("Received {@Request}", request)</c> shape, which otherwise writes
/// every property of that object, passwords and tokens included.
/// </summary>
/// <remarks>
/// This is a backstop, not a licence to log request objects: the rule is still to log identifiers
/// (a user's <see cref="Guid"/>) rather than the data itself. It also cannot help when a secret is
/// passed as a plain argument — <c>LogInformation("Token {Token}", rawToken)</c> has no property
/// name to inspect on the way in and will be written verbatim.
/// </remarks>
public sealed class SensitiveDataDestructuringPolicy : IDestructuringPolicy
{
    public const string RedactedValue = "[REDACTED]";

    /// <summary>
    /// Matched as a case-insensitive substring of the property name, so <c>ConfirmPassword</c>,
    /// <c>TokenHash</c> and <c>SigningKey</c> are all caught. Deliberately broad: over-redacting a
    /// harmless property is a cosmetic problem, while under-redacting one is a breach.
    /// </summary>
    private static readonly string[] SensitiveNameFragments =
    [
        "password",
        "token",
        "secret",
        "key",
        "credential",
        "authorization",
        "signature",
        // Personal data. Log the user's id instead — it identifies the account in support
        // scenarios without putting contact details in a log file or an APM tool.
        "email",
        "phone",
        "address",
    ];

    public bool TryDestructure(
        object value,
        ILogEventPropertyValueFactory propertyValueFactory,
        [NotNullWhen(true)] out LogEventPropertyValue? result)
    {
        var type = value.GetType();

        // Only our own types are rewritten. Framework and third-party objects keep Serilog's
        // default handling, so this policy can't distort types it knows nothing about.
        if (type.Namespace?.StartsWith("VenueBooking", StringComparison.Ordinal) is not true)
        {
            result = null;
            return false;
        }

        var properties = new List<LogEventProperty>();

        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (!property.CanRead || property.GetIndexParameters().Length > 0)
            {
                continue;
            }

            if (IsSensitive(property.Name))
            {
                properties.Add(new LogEventProperty(property.Name, new ScalarValue(RedactedValue)));
                continue;
            }

            object? propertyValue;
            try
            {
                propertyValue = property.GetValue(value);
            }
            catch (TargetInvocationException)
            {
                // A computed property that throws must not take the whole log event down with it.
                continue;
            }

            properties.Add(new LogEventProperty(
                property.Name,
                propertyValueFactory.CreatePropertyValue(propertyValue, destructureObjects: true)));
        }

        result = new StructureValue(properties, type.Name);
        return true;
    }

    private static bool IsSensitive(string propertyName) =>
        SensitiveNameFragments.Any(fragment => propertyName.Contains(fragment, StringComparison.OrdinalIgnoreCase));
}
