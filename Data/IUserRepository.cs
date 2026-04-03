namespace SecureApp.Data;

public interface IUserRepository
{
    Task<int> CreateUserAsync(string username, string email, CancellationToken cancellationToken = default);
    Task<int> CreateUserWithPasswordHashAsync(string username, string email, string passwordHash, string role, CancellationToken cancellationToken = default);
    Task<UserRecord?> GetUserByEmailAsync(string email, CancellationToken cancellationToken = default);
    Task<UserAuthRecord?> GetUserAuthByUsernameAsync(string username, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<UserRecord>> SearchUsersByUsernameAsync(string searchTerm, CancellationToken cancellationToken = default);
    Task<int> CountUsersAsync(CancellationToken cancellationToken = default);
    Task<string?> GetRoleByUsernameAsync(string username, CancellationToken cancellationToken = default);
    Task<int> UpdateUserRoleAsync(string username, string role, CancellationToken cancellationToken = default);
}