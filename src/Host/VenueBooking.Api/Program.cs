using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using VenueBooking.Api.Diagnostics;
using VenueBooking.Api.OpenApi;
using VenueBooking.Logging;
using VenueBooking.Modules.Identity;
using VenueBooking.Modules.Identity.Authentication;
using VenueBooking.Modules.Identity.Authorization;

// Two-stage initialisation. The bootstrap logger covers the window before the host exists, so a
// failure in configuration itself — a malformed Serilog section, a JwtOptions value that fails
// ValidateOnStart — is reported rather than swallowed by a process that just exits.
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Sinks are read from the "Serilog" configuration section rather than set in code, so the
    // Application Insights sink at deployment (Epic 14) is a package reference plus an entry in
    // appsettings.Production.json — this file does not change. Locally the same mechanism writes
    // JSON lines under logs/, which is the queryable record when there is no APM service.
    builder.Services.AddSerilog((services, loggerConfiguration) => loggerConfiguration
        .ReadFrom.Configuration(builder.Configuration)
        .ReadFrom.Services(services)
        .Destructure.With(new SensitiveDataDestructuringPolicy()));

    builder.Services.AddControllers();
    // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
    builder.Services.AddOpenApi(options =>
    {
        options.AddDocumentTransformer<BearerSecuritySchemeTransformer>();
        options.AddOperationTransformer<BearerSecurityRequirementTransformer>();
    });

    builder.Services.AddProblemDetails();
    builder.Services.AddExceptionHandler<UnhandledExceptionLogger>();

    builder.Services.AddIdentityModule(builder.Configuration);

    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer();

    builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
        .Configure<IOptions<JwtOptions>>((bearerOptions, jwtOptions) =>
        {
            var jwt = jwtOptions.Value;
            bearerOptions.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwt.Issuer,
                ValidateAudience = true,
                ValidAudience = jwt.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30),

                // Stated rather than left to the defaults, because this is the seam between the
                // claims JwtTokenGenerator writes and what [Authorize(Policy = ...)] reads back.
                // "sub" and the role claims land under these types once the bearer handler's
                // inbound claim map has run; naming them here means a change on either side of
                // the seam surfaces as a failing authorization test rather than as an endpoint
                // that quietly admits everyone.
                NameClaimType = ClaimTypes.NameIdentifier,
                RoleClaimType = ClaimTypes.Role,
            };
        });

    // AddAuthorization supplies the policy evaluation UseAuthorization performs; AddRoleAuthorization
    // supplies what it evaluates. MVC happens to register the former as well, but relying on that
    // would leave the pipeline's security depending on a side effect of AddControllers.
    builder.Services.AddAuthorization();
    builder.Services.AddRoleAuthorization();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        // Exempted from the fallback policy: the document is how an API consumer finds out where
        // to get a token, so requiring one to read it would close the loop on itself.
        app.MapOpenApi().AllowAnonymous();
    }

    // Ahead of request logging, so a failure is already reflected in the status code by the time
    // the request summary is written.
    app.UseExceptionHandler();

    // 401s and 403s come from the authentication/authorization middleware as a bare status code
    // with no body. This gives them the same ProblemDetails shape as every other error the API
    // returns, so a client has one response format to parse rather than two.
    app.UseStatusCodePages();

    app.UseSerilogRequestLogging(RequestLogging.Configure);

    app.UseHttpsRedirection();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    await app.Services.SeedIdentityRolesAsync();

    app.Run();

    await Log.CloseAndFlushAsync();
    return 0;
}
// `dotnet ef` and WebApplicationFactory both stop the host on purpose once the service provider
// exists — EF throws HostAbortedException, the test host an internal StopTheHostException (hence
// the name check). Neither is a crash, and both have to keep propagating so the tooling receives
// the host it asked for. Flushing is deliberately not in a `finally` for the same reason: it
// would tear down the logger the test host is about to use.
catch (Exception exception) when (exception.GetType().Name is not ("HostAbortedException" or "StopTheHostException"))
{
    Log.Fatal(exception, "VenueBooking API terminated unexpectedly");

    await Log.CloseAndFlushAsync();
    return 1;
}

// Exposed for WebApplicationFactory<Program> in integration tests.
public partial class Program;
