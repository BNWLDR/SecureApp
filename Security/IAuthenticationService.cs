namespace SecureApp.Security;

public interface IAuthenticationService
{
    Task<bool> AuthenticateAsync(string username, string password, CancellationToken cancellationToken = default);
    Task RegisterAsync(string username, string email, string password, CancellationToken cancellationToken = default);
    Task<string?> GetRoleForUserAsync(string username, CancellationToken cancellationToken = default);
    Task AssignRoleAsync(string username, string role, CancellationToken cancellationToken = default);
}