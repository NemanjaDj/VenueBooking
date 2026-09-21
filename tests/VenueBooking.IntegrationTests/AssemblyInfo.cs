// Each test class boots its own WebApplicationFactory, and WebApplicationFactory finds the host
// by invoking Program's entry point and watching a process-wide DiagnosticListener. Two entry
// points running at once race over that listener, and a factory can end up never seeing the host
// it built ("The entry point exited without ever building an IHost"). Booting hosts one at a time
// removes the race while keeping each class its own isolated database.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
