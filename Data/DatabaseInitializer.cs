namespace SecureApp.Data;

public class DatabaseInitializer(ISqliteConnectionFactory connectionFactory) : IDatabaseInitializer
{
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = connectionFactory.CreateConnection();
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL,
                Email TEXT NOT NULL,
                PasswordHash TEXT NOT NULL DEFAULT '',
                Role TEXT NOT NULL DEFAULT 'User'
            );
            """;

        await command.ExecuteNonQueryAsync(cancellationToken);

        await using var pragmaCommand = connection.CreateCommand();
        pragmaCommand.CommandText = "PRAGMA table_info(Users);";

        var hasPasswordHashColumn = false;
        var hasRoleColumn = false;
        await using (var reader = await pragmaCommand.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var columnName = reader.GetString(1);
                if (string.Equals(columnName, "PasswordHash", StringComparison.OrdinalIgnoreCase))
                {
                    hasPasswordHashColumn = true;
                }

                if (string.Equals(columnName, "Role", StringComparison.OrdinalIgnoreCase))
                {
                    hasRoleColumn = true;
                }
            }
        }

        if (!hasPasswordHashColumn)
        {
            await using var alterCommand = connection.CreateCommand();
            alterCommand.CommandText = "ALTER TABLE Users ADD COLUMN PasswordHash TEXT NOT NULL DEFAULT '';";
            await alterCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        if (!hasRoleColumn)
        {
            await using var alterRoleCommand = connection.CreateCommand();
            alterRoleCommand.CommandText = "ALTER TABLE Users ADD COLUMN Role TEXT NOT NULL DEFAULT 'User';";
            await alterRoleCommand.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}