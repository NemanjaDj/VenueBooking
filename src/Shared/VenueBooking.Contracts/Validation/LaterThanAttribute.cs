using System.ComponentModel.DataAnnotations;

namespace VenueBooking.Contracts.Validation;

/// <summary>
/// Validates that a <see cref="DateTime"/> property is later than another named property on the same object
/// (e.g. an Event's end datetime must be later than its start datetime).
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class LaterThanAttribute(string otherPropertyName) : ValidationAttribute
{
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        var otherProperty = validationContext.ObjectType.GetProperty(otherPropertyName);
        if (otherProperty is null)
        {
            return new ValidationResult($"Unknown property '{otherPropertyName}'.");
        }

        var otherValue = otherProperty.GetValue(validationContext.ObjectInstance);

        if (value is not DateTime dateTime || otherValue is not DateTime otherDateTime)
        {
            return ValidationResult.Success;
        }

        return dateTime > otherDateTime
            ? ValidationResult.Success
            : new ValidationResult(
                ErrorMessage ?? $"{validationContext.MemberName} must be later than {otherPropertyName}.",
                [validationContext.MemberName ?? string.Empty]);
    }
}
