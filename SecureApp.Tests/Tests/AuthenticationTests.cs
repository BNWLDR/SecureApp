using Microsoft.Data.Sqlite;
using SecureApp.Data;
using SecureApp.Security;

namespace SecureApp.Tests.Tests;

[TestFixture]
public class AuthenticationTests
{
    [Test]
    public void PasswordHasher_HashesAndVerifiesPassword()
    {
        var hasher = new BcryptPasswordHasher();
        var password = "Sup3rSecure!Pass";

        var hash = hasher.HashPassword(password);

        Assert.That(hash, Is.Not.EqualTo(password));
        Assert.That(hasher.VerifyPassword(password, hash), Is.True);
        Assert.That(hasher.VerifyPassword("wrong-password", hash), Is.False);
    }

    [Test]
    public async Task Authenticate_ReturnsTrueForValidCredentials()
    {
        var (_, authService) = await CreateAuthServiceAsync();
        await authService.RegisterAsync("loginUser", "login@example.com", "Pa$$w0rd123");

        var isAuthenticated = await authService.AuthenticateAsync("loginUser", "Pa$$w0rd123");

        Assert.That(isAuthenticated, Is.True);
    }

    [Test]
    public async Task Authenticate_ReturnsFalseForInvalidPassword()
    {
        var (_, authService) = await CreateAuthServiceAsync();
        await authService.RegisterAsync("loginUser", "login@example.com", "Pa$$w0rd123");

        var isAuthenticated = await authService.AuthenticateAsync("loginUser", "wrong-password");

        Assert.That(isAuthenticated, Is.False);
    }

    [Test]
    public async Task Register_StoresBcryptHash_NotPlaintext()
    {
        var (repository, authService) = await CreateAuthServiceAsync();
        const string password = "Pa$$w0rd123";

        await authService.RegisterAsync("hashUser", "hash@example.com", password);
        var stored = await repository.GetUserAuthByUsernameAsync("hashUser");

        Assert.That(stored, Is.Not.Null);
        Assert.That(stored!.PasswordHash, Is.Not.EqualTo(password));
        Assert.That(stored.PasswordHash.StartsWith("$2"), Is.True);
    }

    [Test]
    public async Task FirstRegisteredUser_IsAssignedAdminRole()
    {
        var (_, authService) = await CreateAuthServiceAsync();

        await authService.RegisterAsync("firstUser", "first@example.com", "Pa$$w0rd123");
        var role = await authService.GetRoleForUserAsync("firstUser");

        Assert.That(role, Is.EqualTo(AppRoles.Admin));
    }

    [Test]
    public async Task SecondRegisteredUser_IsAssignedUserRole()
    {
        var (_, authService) = await CreateAuthServiceAsync();

        await authService.RegisterAsync("firstUser", "first@example.com", "Pa$$w0rd123");
        await authService.RegisterAsync("secondUser", "second@example.com", "Pa$$w0rd123");
        var role = await authService.GetRoleForUserAsync("secondUser");

        Assert.That(role, Is.EqualTo(AppRoles.User));
    }

    [Test]
    public async Task AssignRole_UpdatesUserRole()
    {
        var (_, authService) = await CreateAuthServiceAsync();

        await authService.RegisterAsync("firstUser", "first@example.com", "Pa$$w0rd123");
        await authService.RegisterAsync("member", "member@example.com", "Pa$$w0rd123");

        await authService.AssignRoleAsync("member", AppRoles.Admin);
        var role = await authService.GetRoleForUserAsync("member");

        Assert.That(role, Is.EqualTo(AppRoles.Admin));
    }

    private static async Task<(UserRepository Repository, AuthenticationService AuthService)> CreateAuthServiceAsync()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"safevault-auth-{Guid.NewGuid():N}.db");
        var factory = new TestSqliteConnectionFactory($"Data Source={databasePath}");
        var initializer = new DatabaseInitializer(factory);
        await initializer.InitializeAsync();

        var repository = new UserRepository(factory);
        var authService = new AuthenticationService(repository, new BcryptPasswordHasher());
        return (repository, authService);
    }

    private sealed class TestSqliteConnectionFactory(string connectionString) : ISqliteConnectionFactory
    {
        public SqliteConnection CreateConnection()
        {
            return new SqliteConnection(connectionString);
        }
    }
}