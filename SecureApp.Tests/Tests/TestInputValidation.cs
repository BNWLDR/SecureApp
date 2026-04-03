using System.ComponentModel.DataAnnotations;
using Microsoft.Data.Sqlite;
using SecureApp.Data;
using SecureApp.Models;
using SecureApp.Security;

namespace SecureApp.Tests.Tests;

[TestFixture]
public class TestInputValidation
{
    private readonly InputSanitizer _sanitizer = new();
    private static readonly string[] SqlInjectionPayloads =
    [
        "attacker'; DROP TABLE Users;--",
        "' OR 1=1 --",
        "admin' UNION SELECT 1,2,3 --",
        "'; UPDATE Users SET Email='hacked@example.com' WHERE '1'='1"
    ];

    private static readonly string[] XssPayloads =
    [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert('xss')"
    ];

    [TestCaseSource(nameof(SqlInjectionPayloads))]
    public async Task TestForSQLInjection(string payload)
    {
        var (factory, repository) = await CreateInitializedRepositoryAsync();
        await repository.CreateUserAsync(payload, "attacker@example.com");

        await using var connection = factory.CreateConnection();
        await connection.OpenAsync();

        await using var tableCheckCommand = connection.CreateCommand();
        tableCheckCommand.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='Users';";
        var tableCount = Convert.ToInt32(await tableCheckCommand.ExecuteScalarAsync());

        await using var rowCheckCommand = connection.CreateCommand();
        rowCheckCommand.CommandText = "SELECT COUNT(*) FROM Users WHERE Username = @username;";
        rowCheckCommand.Parameters.Add(new SqliteParameter("@username", payload));
        var rowCount = Convert.ToInt32(await rowCheckCommand.ExecuteScalarAsync());

        Assert.That(tableCount, Is.EqualTo(1));
        Assert.That(rowCount, Is.EqualTo(1));
    }

    [TestCaseSource(nameof(XssPayloads))]
    public void TestForXSS(string payload)
    {
        var model = new UserInputModel
        {
            Username = payload,
            Email = "safe@example.com"
        };

        var validationContext = new ValidationContext(model);
        var validationResults = new List<ValidationResult>();
        var isValid = Validator.TryValidateObject(model, validationContext, validationResults, validateAllProperties: true);

        Assert.That(isValid, Is.False);
        Assert.That(validationResults.Any(r => r.MemberNames.Contains(nameof(UserInputModel.Username))), Is.True);
    }

    [Test]
    public void Sanitizer_RemovesHarmfulCharacters()
    {
        var sanitizedUsername = _sanitizer.SanitizeUsername("<script>alert('x')</script>admin--");
        var sanitizedEmail = _sanitizer.SanitizeEmail("evil\"@example.com;\n");

        Assert.That(sanitizedUsername, Is.EqualTo("scriptalertxscriptadmin--"));
        Assert.That(sanitizedEmail, Is.EqualTo("evil@example.com"));
    }

    [Test]
    public void Sanitizer_PreservesCleanInput()
    {
        var username = "safe.user-01";
        var email = "safe.user@example.com";

        Assert.That(_sanitizer.SanitizeUsername(username), Is.EqualTo(username));
        Assert.That(_sanitizer.SanitizeEmail(email), Is.EqualTo(email));
    }

    [Test]
    public void Sanitizer_EscapesHtmlForSafeOutput()
    {
        var payload = "<script>alert('xss')</script>";

        var escaped = _sanitizer.EscapeForHtml(payload);

        Assert.That(escaped, Is.EqualTo("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"));
    }

    [Test]
    public async Task GetUserByEmail_UsesParameterPlaceholder()
    {
        var (_, repository) = await CreateInitializedRepositoryAsync();
        await repository.CreateUserAsync("normalUser", "normal@example.com");

        var hostileEmail = "normal@example.com' OR 1=1 --";
        var notFound = await repository.GetUserByEmailAsync(hostileEmail);
        var found = await repository.GetUserByEmailAsync("normal@example.com");

        Assert.That(notFound, Is.Null);
        Assert.That(found, Is.Not.Null);
        Assert.That(found!.Username, Is.EqualTo("normalUser"));
    }

    [Test]
    public async Task SearchUsers_WithHostileInput_DoesNotBreakQueryOrSchema()
    {
        var (factory, repository) = await CreateInitializedRepositoryAsync();
        await repository.CreateUserAsync("alice", "alice@example.com");
        await repository.CreateUserAsync("bob", "bob@example.com");

        var hostileSearch = "' ; DROP TABLE Users; --";
        var searchResults = await repository.SearchUsersByUsernameAsync(hostileSearch);

        await using var connection = factory.CreateConnection();
        await connection.OpenAsync();
        await using var tableCheckCommand = connection.CreateCommand();
        tableCheckCommand.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='Users';";
        var tableCount = Convert.ToInt32(await tableCheckCommand.ExecuteScalarAsync());

        Assert.That(searchResults, Is.Empty);
        Assert.That(tableCount, Is.EqualTo(1));
    }

    [Test]
    public async Task SearchUsers_EscapesLikeWildcards()
    {
        var (_, repository) = await CreateInitializedRepositoryAsync();
        await repository.CreateUserAsync("john_1", "john1@example.com");
        await repository.CreateUserAsync("johnx1", "johnx1@example.com");

        var exactUnderscoreSearch = await repository.SearchUsersByUsernameAsync("john_1");

        Assert.That(exactUnderscoreSearch.Count, Is.EqualTo(1));
        Assert.That(exactUnderscoreSearch[0].Username, Is.EqualTo("john_1"));
    }

    [TestCaseSource(nameof(SqlInjectionPayloads))]
    public async Task LoginStyleEmailLookup_WithInjectionPayload_DoesNotAuthenticate(string payload)
    {
        var (_, repository) = await CreateInitializedRepositoryAsync();
        await repository.CreateUserAsync("validUser", "valid@example.com");

        var lookup = await repository.GetUserByEmailAsync(payload);
        Assert.That(lookup, Is.Null);
    }

    private static async Task<(ISqliteConnectionFactory Factory, UserRepository Repository)> CreateInitializedRepositoryAsync()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"safevault-{Guid.NewGuid():N}.db");
        var factory = new TestSqliteConnectionFactory($"Data Source={databasePath}");
        var initializer = new DatabaseInitializer(factory);
        var repository = new UserRepository(factory);

        await initializer.InitializeAsync();

        return (factory, repository);
    }

    private sealed class TestSqliteConnectionFactory(string connectionString) : ISqliteConnectionFactory
    {
        public SqliteConnection CreateConnection()
        {
            return new SqliteConnection(connectionString);
        }
    }
}