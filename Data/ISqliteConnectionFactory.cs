using Microsoft.Data.Sqlite;

namespace SecureApp.Data;

public interface ISqliteConnectionFactory
{
    SqliteConnection CreateConnection();
}