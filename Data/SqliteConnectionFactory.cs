using Microsoft.Data.Sqlite;

namespace SecureApp.Data;

public class SqliteConnectionFactory(IConfiguration configuration) : ISqliteConnectionFactory
{
    private readonly string _connectionString =
        configuration.GetConnectionString("DefaultConnection") ?? "Data Source=safevault.db";

    public SqliteConnection CreateConnection()
    {
        return new SqliteConnection(_connectionString);
    }
}