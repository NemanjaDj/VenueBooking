namespace VenueBooking.Modules.Identity.Services;

public sealed class AuthResult<T>
{
    public bool Succeeded { get; }
    public T? Value { get; }
    public IReadOnlyCollection<string> Errors { get; }

    private AuthResult(bool succeeded, T? value, IReadOnlyCollection<string> errors)
    {
        Succeeded = succeeded;
        Value = value;
        Errors = errors;
    }

    public static AuthResult<T> Success(T value) => new(true, value, []);

    public static AuthResult<T> Failure(IEnumerable<string> errors) => new(false, default, [.. errors]);
}
