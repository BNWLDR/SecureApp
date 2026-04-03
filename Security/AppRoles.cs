namespace SecureApp.Security;

public static class AppRoles
{
    public const string Admin = "Admin";
    public const string User = "User";

    public static bool IsSupported(string role)
    {
        return string.Equals(role, Admin, StringComparison.Ordinal) ||
               string.Equals(role, User, StringComparison.Ordinal);
    }
}