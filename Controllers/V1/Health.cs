// ==========================================================================
// HEALTH MODULE — Health Check Endpoint
// Single file: Repository + Service + Controller
// Enhanced Service with error handling, logging, and enrichment
// ==========================================================================

using System;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

// ==========================================================================
#region Repository
// ==========================================================================
namespace KeiroGenesis.API.Repositories
{
    public class HealthRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<HealthRepository> _logger;

        public HealthRepository(IDbConnectionFactory db, ILogger<HealthRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<dynamic?> HealthCheckAsync()
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync("SELECT * FROM core.fn_health_check()");
        }
    }
}
#endregion

// ==========================================================================
#region Service
// ==========================================================================
namespace KeiroGenesis.API.Services
{
    public class HealthService
    {
        private readonly HealthRepository _repo;
        private readonly ILogger<HealthService> _logger;

        public HealthService(HealthRepository repo, ILogger<HealthService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<object> HealthCheckAsync()
        {
            try
            {
                var dbCheck = await _repo.HealthCheckAsync();

                // Successful health check
                _logger.LogInformation("Health check passed - Database connected");

                return new
                {
                    status = "healthy",
                    database = dbCheck != null ? "connected" : "disconnected",
                    timestamp = DateTime.UtcNow,
                    version = "1.0.0",
                    environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"
                };
            }
            catch (Exception ex)
            {
                // Log the error
                _logger.LogError(ex, "Health check failed - Database connection error");

                return new
                {
                    status = "unhealthy",
                    database = "error",
                    error = ex.Message,
                    timestamp = DateTime.UtcNow,
                    version = "1.0.0"
                };
            }
        }
    }
}
#endregion

// ==========================================================================
#region Controller
// ==========================================================================
namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
    [Route("api/v1/health")]
    public class HealthController : ControllerBase
    {
        private readonly HealthService _service;
        private readonly ILogger<HealthController> _logger;

        public HealthController(HealthService service, ILogger<HealthController> logger)
        {
            _service = service;
            _logger = logger;
        }

        /// <summary>
        /// Health check endpoint - verifies API and database connectivity
        /// </summary>
        /// <returns>Health status including database connectivity and timestamp</returns>
        [HttpGet]
        [ProducesResponseType(200)]
        [ProducesResponseType(503)]
        public async Task<IActionResult> Check()
        {
            var result = await _service.HealthCheckAsync();

            // Return 503 Service Unavailable if unhealthy
            var resultDict = result as dynamic;
            if (resultDict?.status == "unhealthy")
            {
                _logger.LogWarning("Health check returned unhealthy status");
                return StatusCode(503, result);
            }

            return Ok(result);
        }
    }
}
#endregion