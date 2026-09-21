using System.Reflection;

namespace VenueBooking.ArchitectureTests.Logging;

/// <summary>
/// Modules log through <c>Microsoft.Extensions.Logging</c> abstractions; the host alone decides
/// what the sinks are. Keeping Serilog out of the modules is what lets that decision change —
/// adding Application Insights, swapping the file sink — without touching business code, and it
/// stops the static <c>Serilog.Log</c> entry point creeping in as an ambient dependency.
/// </summary>
public sealed class ModuleLoggingDependencyTests
{
    public static TheoryData<string> ModuleAssemblyNames =>
    [
        "VenueBooking.SharedKernel",
        "VenueBooking.Contracts",
        "VenueBooking.Modules.Identity",
        "VenueBooking.Modules.Venue",
        "VenueBooking.Modules.Event",
        "VenueBooking.Modules.Layout",
        "VenueBooking.Modules.Scheduling",
        "VenueBooking.Modules.Booking",
        "VenueBooking.Modules.Payment",
        "VenueBooking.Modules.Notification",
    ];

    [Theory]
    [MemberData(nameof(ModuleAssemblyNames))]
    public void Modules_DoNotDependOnALoggingImplementation(string assemblyName)
    {
        var referenced = Assembly.Load(assemblyName)
            .GetReferencedAssemblies()
            .Select(reference => reference.Name)
            .Where(name => name is not null && name.StartsWith("Serilog", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            referenced.Count == 0,
            $"{assemblyName} references {string.Join(", ", referenced)}. Modules should depend on " +
            "ILogger<T> from Microsoft.Extensions.Logging.Abstractions instead, and leave sink " +
            "configuration to VenueBooking.Api.");
    }
}
