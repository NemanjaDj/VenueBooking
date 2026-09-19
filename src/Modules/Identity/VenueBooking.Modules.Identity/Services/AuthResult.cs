using VenueBooking.Contracts.Identity;

namespace VenueBooking.Modules.Identity.Services;

public sealed class AuthResult
{
    public bool Succeeded { get; }
    public RegisterResponse? User { get; }
    public IReadOnlyCollection<string> Errors { get; }

    private AuthResult(bool succeeded, RegisterResponse? user, IReadOnlyCollection<string> errors)
    {
        Succeeded = succeeded;
        User = user;
        Errors = errors;
    }

    public static AuthResult Success(RegisterResponse user) => new(true, user, []);

    public static AuthResult Failure(IEnumerable<string> errors) => new(false, null, [.. errors]);
}
