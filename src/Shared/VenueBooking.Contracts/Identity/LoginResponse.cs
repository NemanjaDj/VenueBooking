namespace VenueBooking.Contracts.Identity;

public sealed record LoginResponse(string AccessToken, string RefreshToken, DateTime AccessTokenExpiresAtUtc);
