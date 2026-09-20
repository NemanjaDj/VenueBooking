namespace VenueBooking.Modules.Identity.Authentication;

public interface IRefreshTokenGenerator
{
    /// <summary>Generates a new high-entropy opaque token to hand to the client.</summary>
    string GenerateToken();

    /// <summary>Deterministic hash of a raw token, for storage/lookup — never store the raw token.</summary>
    string Hash(string token);
}
