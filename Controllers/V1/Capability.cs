// ==========================================================================
// CAPABILITY MODULE — Capability System (Placeholder)
// Single file: Repository + Service + Controller
// Full implementation to be added based on capability schema
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
    public class CapabilityRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<CapabilityRepository> _logger;

        public CapabilityRepository(IDbConnectionFactory db, ILogger<CapabilityRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<bool> CheckCapabilityAsync(Guid tenantId, Guid userId, string capabilityCode)
        {
            using var conn = _db.CreateConnection();
            // Placeholder - implement based on your capability schema
            return await Task.FromResult(true);
        }
    }
}
#endregion

#region Service
namespace KeiroGenesis.API.Services
{
    public class CapabilityService
    {
        private readonly CapabilityRepository _repo;
        private readonly ILogger<CapabilityService> _logger;

        public CapabilityService(CapabilityRepository repo, ILogger<CapabilityService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public Task<bool> CheckCapabilityAsync(Guid tenantId, Guid userId, string capabilityCode)
            => _repo.CheckCapabilityAsync(tenantId, userId, capabilityCode);
    }
}
#endregion

#region Controller
namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
    [Route("api/v1/[controller]")]
    [Authorize]
    public class CapabilityController : ControllerBase
    {
        private readonly CapabilityService _service;

        public CapabilityController(CapabilityService service)
        {
            _service = service;
        }

        [HttpGet("check")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> CheckCapability(string capabilityCode)
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();
            var hasCapability = await _service.CheckCapabilityAsync(tenantId, userId, capabilityCode);
            return Ok(new { has_capability = hasCapability });
        }

        private Guid GetTenantId()
        {
            var claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var tenantId))
                throw new UnauthorizedAccessException("Invalid tenant claim");
            return tenantId;
        }

        private Guid GetCurrentUserId()
        {
            var claim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                     ?? User.FindFirst("sub")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var userId))
                throw new UnauthorizedAccessException("Invalid user claim");
            return userId;
        }
    }
}
#endregion
