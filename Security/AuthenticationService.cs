using SecureApp.Data;

namespace SecureApp.Security;

public class AuthenticationService(IUserRepository userRepository, IPasswordHasher passwordHasher) : IAuthenticationService
{
    public async Task<bool> AuthenticateAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        // Fetch by username and verify a bcrypt hash; never compare plaintext passwords.
        var user = await userRepository.GetUserAuthByUsernameAsync(username, cancellationToken);
        if (user is null || string.IsNullOrWhiteSpace(user.PasswordHash))
        {
            return false;
        }

        return passwordHasher.VerifyPassword(password, user.PasswordHash);
    }

    public async Task RegisterAsync(string username, string email, string password, CancellationToken cancellationToken = default)
    {
        var existingUser = await userRepository.GetUserAuthByUsernameAsync(username, cancellationToken);
        if (existingUser is not null)
        {
            throw new InvalidOperationException("Username is already registered.");
        }

        // Bootstrap rule: first account becomes Admin so the app has an initial operator.
        var currentUserCount = await userRepository.CountUsersAsync(cancellationToken);
        var assignedRole = currentUserCount == 0 ? AppRoles.Admin : AppRoles.User;

        var passwordHash = passwordHasher.HashPassword(password);
        await userRepository.CreateUserWithPasswordHashAsync(username, email, passwordHash, assignedRole, cancellationToken);
    }

    public async Task<string?> GetRoleForUserAsync(string username, CancellationToken cancellationToken = default)
    {
        return await userRepository.GetRoleByUsernameAsync(username, cancellationToken);
    }

    public async Task AssignRoleAsync(string username, string role, CancellationToken cancellationToken = default)
    {
        if (!AppRoles.IsSupported(role))
        {
            throw new InvalidOperationException("Unsupported role.");
        }

        var updated = await userRepository.UpdateUserRoleAsync(username, role, cancellationToken);
        if (updated == 0)
        {
            throw new InvalidOperationException("User not found.");
        }
    }
}