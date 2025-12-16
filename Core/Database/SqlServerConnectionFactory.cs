using System;
using System.Data;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Dapper;
using Microsoft.Data.SqlClient;

namespace KeiroGenesis.API.Core.Database
{
    public class SqlServerConnectionFactory : IDbConnectionFactory
    {
        private readonly string _connectionString;
        private readonly ILogger<SqlServerConnectionFactory> _logger;

        static SqlServerConnectionFactory()
        {
            // Configure Dapper for SQL Server if needed
            DefaultTypeMap.MatchNamesWithUnderscores = true;
        }

        public SqlServerConnectionFactory(IConfiguration configuration, ILogger<SqlServerConnectionFactory> logger)
        {
            _logger = logger;

            // Try to get connection string first
            _connectionString = configuration.GetConnectionString("DefaultConnection");

            // If not found, build from DatabaseSettings
            if (string.IsNullOrEmpty(_connectionString))
            {
                var settings = configuration.GetSection("DatabaseSettings");
                var builder = new SqlConnectionStringBuilder
                {
                    DataSource = $"{settings["Host"]},{settings["Port"]}",
                    InitialCatalog = settings["Database"],
                    UserID = settings["Username"],
                    Password = settings["Password"],
                    TrustServerCertificate = bool.Parse(settings["TrustServerCertificate"] ?? "true"),
                    Encrypt = bool.Parse(settings["Encrypt"] ?? "true")
                };
                _connectionString = builder.ConnectionString;
            }

            if (string.IsNullOrEmpty(_connectionString))
                throw new InvalidOperationException("SQL Server connection string not configured");

            _logger.LogInformation("SQL Server connection factory initialized");
        }

        public IDbConnection CreateConnection()
        {
            return new SqlConnection(_connectionString);
        }

        public async Task<IDbConnection> CreateConnectionAsync()
        {
            var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();
            return connection;
        }
    }
}
