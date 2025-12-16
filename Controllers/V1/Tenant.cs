// ==========================================================================
// TENANT MODULE — Tenant CRUD Operations
// Single file: Repository + Service + Controller
// ==========================================================================

using System;
using System.Threading.Tasks;
using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

#region Repository
namespace KeiroGenesis.API.Repositories
{
    public class TenantRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<TenantRepository> _logger;

        public TenantRepository(IDbConnectionFactory db, ILogger<TenantRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<dynamic?> GetTenantAsync(Guid tenantId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM core.tenants WHERE tenant_id = @tenant_id",
                new { tenant_id = tenantId }
            );
        }
    }
}
#endregion

#region Service
namespace KeiroGenesis.API.Services
{
    public class TenantService
    {
        private readonly TenantRepository _repo;
        private readonly ILogger<TenantService> _logger;

        public TenantService(TenantRepository repo, ILogger<TenantService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public Task<dynamic?> GetTenantAsync(Guid tenantId) => _repo.GetTenantAsync(tenantId);
    }
}
#endregion

#region Controller
namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
    [Route("api/v1/[controller]")]
    [Authorize]
    public class TenantController : ControllerBase
    {
        private readonly TenantService _service;

        public TenantController(TenantService service)
        {
            _service = service;
        }

        [HttpGet("get-tenant")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetTenant()
        {
            var tenantId = GetTenantId();
            var tenant = await _service.GetTenantAsync(tenantId);
            return tenant != null ? Ok(tenant) : NotFound();
        }

        private Guid GetTenantId()
        {
            var claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var tenantId))
                throw new UnauthorizedAccessException("Invalid tenant claim");
            return tenantId;
        }
    }
}
#endregion
