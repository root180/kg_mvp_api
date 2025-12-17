using System;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Npgsql;
using Pgvector;
using Pgvector.Npgsql;

namespace KeiroGenesis.API.Core.Database
{
    public interface IDbConnectionFactory
    {
        IDbConnection CreateConnection();
        Task<IDbConnection> CreateConnectionAsync();
    }

    public sealed class PostgreSqlConnectionFactory : IDbConnectionFactory
    {
        private readonly NpgsqlDataSource _dataSource;
        private readonly ILogger<PostgreSqlConnectionFactory> _logger;

        static PostgreSqlConnectionFactory()
        {
            DefaultTypeMap.MatchNamesWithUnderscores = true;
        }

        public PostgreSqlConnectionFactory(
            IConfiguration configuration,
            ILogger<PostgreSqlConnectionFactory> logger)
        {
            _logger = logger;

            string connectionString;

            // PRIORITY 1: Check for ConnectionStrings.PostgreSQL (appsettings.json)
            var connStr = configuration.GetConnectionString("PostgreSQL");

            if (!string.IsNullOrEmpty(connStr))
            {
                connectionString = connStr;
                _logger.LogInformation("Using connection string from ConnectionStrings:PostgreSQL");
            }
            else
            {
                // PRIORITY 2: Fall back to DatabaseSettings (appsettings.Development.json, etc.)
                var db = configuration.GetSection("DatabaseSettings");
                if (!db.Exists())
                {
                    throw new InvalidOperationException(
                        "Neither ConnectionStrings:PostgreSQL nor DatabaseSettings section found in configuration");
                }

                var csb = new NpgsqlConnectionStringBuilder
                {
                    Host = db["Host"],
                    Port = int.Parse(db["Port"] ?? "5432"),
                    Database = db["Database"],
                    Username = db["Username"],
                    Password = db["Password"],
                    Pooling = true
                };

                // Only set SSL if explicitly configured in DatabaseSettings
                var sslMode = db["SslMode"];
                if (!string.IsNullOrEmpty(sslMode) && Enum.TryParse<SslMode>(sslMode, out var mode))
                {
                    csb.SslMode = mode;
                }

                connectionString = csb.ConnectionString;

                _logger.LogInformation(
                    "Using connection string from DatabaseSettings: {Host}:{Port}/{Database}",
                    csb.Host, csb.Port, csb.Database);
            }

            var builder = new NpgsqlDataSourceBuilder(connectionString);
            builder.UseVector();

            _dataSource = builder.Build();

            // 🔍 Fail fast — prove connectivity at startup
            try
            {
                using var conn = _dataSource.OpenConnection();
                _logger.LogInformation("PostgreSQL connection test succeeded");
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "PostgreSQL connection test FAILED - {Message}", ex.Message);
                throw;
            }
        }

        public IDbConnection CreateConnection()
        {
            return _dataSource.OpenConnection();
        }

        public async Task<IDbConnection> CreateConnectionAsync()
        {
            return await _dataSource.OpenConnectionAsync();
        }
    }

    public sealed class VectorTypeHandler : SqlMapper.TypeHandler<Vector>
    {
        public override Vector Parse(object value) => (Vector)value;

        public override void SetValue(IDbDataParameter parameter, Vector value)
        {
            parameter.Value = value;
        }
    }
}