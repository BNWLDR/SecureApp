using Microsoft.Data.Sqlite;

namespace SecureApp.Data;

public class UserRepository(ISqliteConnectionFactory connectionFactory) : IUserRepository
{
    public async Task<int> CreateUserAsync(string username, string email, CancellationToken cancellationToken = default)
    {
        return await CreateUserWithPasswordHashAsync(username, email, string.Empty, "User", cancellationToken);
    }

    public async Task<int> CreateUserWithPasswordHashAsync(string username, string email, string passwordHash, string role, CancellationToken cancellationToken = default)
    {
        await using var connection = connectionFactory.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        // Always use parameters for user-controlled values to prevent SQL injection.
        command.CommandText = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@username, @email, @passwordHash, @role);";
        command.Parameters.Add(new SqliteParameter("@username", username));
        command.Parameters.Add(new SqliteParameter("@email", email));
        command.Parameters.Add(new SqliteParameter("@passwordHash", passwordHash));
        command.Parameters.Add(new SqliteParameter("@role", role));

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<UserRecord?> GetUserByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        await using var connection = connectionFactory.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Email = @email LIMIT 1;";
        command.Parameters.Add(new SqliteParameter("@email", email));

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new UserRecord(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.GetString(2));
    }

    public async Task<IReadOnlyList<UserRecord>> SearchUsersByUsernameAsync(string searchTerm, CancellationToken cancellationToken = default)
    {
        await using var connection = connectionFactory.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        // Escape SQL LIKE wildcards so searching remains literal and predictable.
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username LIKE @search ESCAPE '\\' ORDER BY UserID;";
        command.Parameters.Add(new SqliteParameter("@search", $"%{EscapeLikePattern(searchTerm)}%"));

        var results = new List<UserRecord>();

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new UserRecord(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2)));
        }

        return results;
    }

    private static string EscapeLikePattern(string input)
    {
        // Escape the wildcard/control characters recognized by SQL LIKE.
        return input
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("%", "\\%", StringComparison.Ordinal)
            .Replace("_", "\\_", StringComparison.Ordinal);
    }

    public async Task<UserAuthRecord?> GetUserAuthByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        await using var connection = connectionFactory.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, PasswordHash, Role FROM Users WHERE Username = @username LIMIT 1;";
        command.Parameters.Add(new SqliteParameter("@username", username));

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new UserAuthRecord(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
            reader.IsDBNull(3) ? "User" : reader.GetString(3));
    }

    public async Task<int> CountUsersAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = connectionFactory.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM Users;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
    }

    public async Task<string?> GetRoleByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        await using var connection = connectionFactory.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT Role FROM Users WHERE Username = @username LIMIT 1;";
        command.Parameters.Add(new SqliteParameter("@username", username));

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result?.ToString();
    }

    public async Task<int> UpdateUserRoleAsync(string username, string role, CancellationToken cancellationToken = default)
    {
        await using var connection = connectionFactory.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET Role = @role WHERE Username = @username;";
        command.Parameters.Add(new SqliteParameter("@role", role));
        command.Parameters.Add(new SqliteParameter("@username", username));

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }
}