using System.ComponentModel.DataAnnotations;
using VenueBooking.Contracts.Enums;
using VenueBooking.Contracts.Identity;

namespace VenueBooking.UnitTests.Identity;

public sealed class RegisterRequestValidationTests
{
    [Fact]
    public void Validate_WithAdminRole_Fails()
    {
        var request = Build(role: UserRole.Admin);

        var results = Validate(request);

        Assert.Contains(results, r => r.MemberNames.Contains(nameof(RegisterRequest.Role)));
    }

    [Theory]
    [InlineData(UserRole.Customer)]
    [InlineData(UserRole.Organizer)]
    public void Validate_WithSelfRegisterableRole_Succeeds(UserRole role)
    {
        var request = Build(role: role);

        var results = Validate(request);

        Assert.Empty(results);
    }

    [Fact]
    public void Validate_WithMismatchedConfirmPassword_Fails()
    {
        var request = Build(confirmPassword: "SomethingElse1!");

        var results = Validate(request);

        Assert.Contains(results, r => r.MemberNames.Contains(nameof(RegisterRequest.ConfirmPassword)));
    }

    private static RegisterRequest Build(string? confirmPassword = null, UserRole role = UserRole.Customer)
    {
        const string password = "Passw0rd!";
        return new RegisterRequest
        {
            Email = "user@example.com",
            Password = password,
            ConfirmPassword = confirmPassword ?? password,
            Role = role,
        };
    }

    private static List<ValidationResult> Validate(RegisterRequest request)
    {
        var context = new ValidationContext(request);
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(request, context, results, validateAllProperties: true);
        return results;
    }
}
