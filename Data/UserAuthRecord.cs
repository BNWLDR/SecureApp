namespace SecureApp.Data;

public sealed record UserAuthRecord(int UserId, string Username, string PasswordHash, string Role);