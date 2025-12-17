// ==========================================================================
// ACTOR MODULE — Actor Abstraction (Universal Social Identity)
// Single file: Repository + Service + Controller
// Bridges Users/Clones to unified Actor for social operations
// ==========================================================================

using System;
using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

// ==========================================================================
#region Repository
// ==========================================================================
namespace KeiroGenesis.API.Repositories
{
    public class ActorRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<ActorRepository> _logger;

        public ActorRepository(IDbConnectionFactory db, ILogger<ActorRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<dynamic?> GetActorAsync(Guid tenantId, Guid actorId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM actor.fn_get_actor(@p_tenant_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_actor_id = actorId }
            );
        }

        public async Task<dynamic?> GetActorByHandleAsync(Guid tenantId, string handle)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM actor.fn_get_actor_by_handle(@p_tenant_id, @p_handle)",
                new { p_tenant_id = tenantId, p_handle = handle }
            );
        }

        public async Task<Guid?> GetActorIdForUserAsync(Guid tenantId, Guid userId)
        {
            using var conn = _db.CreateConnection();
            return await conn.ExecuteScalarAsync<Guid?>(
                "SELECT actor.fn_get_actor_id_for_user(@p_tenant_id, @p_user_id)",
                new { p_tenant_id = tenantId, p_user_id = userId }
            );
        }

        public async Task<Guid?> GetActorIdForCloneAsync(Guid tenantId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();
            return await conn.ExecuteScalarAsync<Guid?>(
                "SELECT actor.fn_get_actor_id_for_clone(@p_tenant_id, @p_clone_id)",
                new { p_tenant_id = tenantId, p_clone_id = cloneId }
            );
        }

        public async Task<dynamic> SyncHumanActorAsync(
            Guid tenantId, Guid userId, string displayName, string? handle, string? avatarUrl)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                @"SELECT * FROM actor.fn_sync_human_actor(
                    @p_tenant_id, @p_user_id, @p_display_name, @p_handle, @p_avatar_url
                )",
                new
                {
                    p_tenant_id = tenantId,
                    p_user_id = userId,
                    p_display_name = displayName,
                    p_handle = handle ?? (object)DBNull.Value,
                    p_avatar_url = avatarUrl ?? (object)DBNull.Value
                }
            );
        }

        public async Task<dynamic> SyncCloneActorAsync(
            Guid tenantId, Guid cloneId, Guid ownerUserId, string displayName,
            string? handle, string? avatarUrl, bool isMemorial, string autonomyLevel)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                @"SELECT * FROM actor.fn_sync_clone_actor(
                    @p_tenant_id, @p_clone_id, @p_owner_user_id, @p_display_name,
                    @p_handle, @p_avatar_url, @p_is_memorial, @p_autonomy_level
                )",
                new
                {
                    p_tenant_id = tenantId,
                    p_clone_id = cloneId,
                    p_owner_user_id = ownerUserId,
                    p_display_name = displayName,
                    p_handle = handle ?? (object)DBNull.Value,
                    p_avatar_url = avatarUrl ?? (object)DBNull.Value,
                    p_is_memorial = isMemorial,
                    p_autonomy_level = autonomyLevel
                }
            );
        }

        public async Task UpdateActorStatusAsync(Guid tenantId, Guid actorId, string status)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "CALL actor.sp_update_actor_status(@p_tenant_id, @p_actor_id, @p_status)",
                new { p_tenant_id = tenantId, p_actor_id = actorId, p_status = status }
            );
        }

        public async Task<dynamic?> GetActorStatsAsync(Guid tenantId, Guid actorId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM actor.fn_get_actor_stats(@p_tenant_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_actor_id = actorId }
            );
        }

        public async Task<List<dynamic>> SearchActorsAsync(
            Guid tenantId, string? searchTerm, string? actorType, int limit, int offset)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                @"SELECT * FROM actor.fn_search_actors(
                    @p_tenant_id, @p_search_term, @p_actor_type, @p_limit, @p_offset
                )",
                new
                {
                    p_tenant_id = tenantId,
                    p_search_term = searchTerm ?? (object)DBNull.Value,
                    p_actor_type = actorType ?? (object)DBNull.Value,
                    p_limit = limit,
                    p_offset = offset
                }
            );
            return rows.AsList();
        }

        public async Task<List<dynamic>> GetUserActorsAsync(Guid tenantId, Guid userId)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM actor.fn_get_user_actors(@p_tenant_id, @p_user_id)",
                new { p_tenant_id = tenantId, p_user_id = userId }
            );
            return rows.AsList();
        }

        public async Task ActivateActorMemorialAsync(Guid tenantId, Guid actorId)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "CALL actor.sp_activate_memorial(@p_tenant_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_actor_id = actorId }
            );
        }
    }
}
#endregion

// ==========================================================================
#region Service
// ==========================================================================
namespace KeiroGenesis.API.Services
{
    public class ActorService
    {
        private readonly ActorRepository _repo;
        private readonly ILogger<ActorService> _logger;

        public ActorService(ActorRepository repo, ILogger<ActorService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public Task<dynamic?> GetActorAsync(Guid tenantId, Guid actorId)
            => _repo.GetActorAsync(tenantId, actorId);

        public Task<dynamic?> GetActorByHandleAsync(Guid tenantId, string handle)
            => _repo.GetActorByHandleAsync(tenantId, handle);

        public Task<Guid?> GetActorIdForUserAsync(Guid tenantId, Guid userId)
            => _repo.GetActorIdForUserAsync(tenantId, userId);

        public Task<Guid?> GetActorIdForCloneAsync(Guid tenantId, Guid cloneId)
            => _repo.GetActorIdForCloneAsync(tenantId, cloneId);

        public async Task<dynamic> EnsureHumanActorAsync(
            Guid tenantId, Guid userId, string displayName, string? handle, string? avatarUrl)
        {
            var result = await _repo.SyncHumanActorAsync(tenantId, userId, displayName, handle, avatarUrl);
            _logger.LogInformation("Synced human actor for user {UserId}", userId);
            return result;
        }

        public async Task<dynamic> EnsureCloneActorAsync(
            Guid tenantId, Guid cloneId, Guid ownerUserId, string displayName,
            string? handle, string? avatarUrl, bool isMemorial = false, string autonomyLevel = "supervised")
        {
            var result = await _repo.SyncCloneActorAsync(
                tenantId, cloneId, ownerUserId, displayName, handle, avatarUrl, isMemorial, autonomyLevel
            );
            _logger.LogInformation("Synced clone actor for clone {CloneId}", cloneId);
            return result;
        }

        public async Task UpdateActorStatusAsync(Guid tenantId, Guid actorId, string status)
        {
            await _repo.UpdateActorStatusAsync(tenantId, actorId, status);
            _logger.LogInformation("Updated actor {ActorId} status to {Status}", actorId, status);
        }

        public Task<dynamic?> GetActorStatsAsync(Guid tenantId, Guid actorId)
            => _repo.GetActorStatsAsync(tenantId, actorId);

        public Task<List<dynamic>> SearchActorsAsync(
            Guid tenantId, string? searchTerm, string? actorType, int limit = 20, int offset = 0)
            => _repo.SearchActorsAsync(tenantId, searchTerm, actorType, limit, offset);

        public Task<List<dynamic>> GetUserActorsAsync(Guid tenantId, Guid userId)
            => _repo.GetUserActorsAsync(tenantId, userId);

        public async Task ActivateActorMemorialAsync(Guid tenantId, Guid actorId)
        {
            await _repo.ActivateActorMemorialAsync(tenantId, actorId);
            _logger.LogInformation("Activated memorial for actor {ActorId}", actorId);
        }

        public async Task<Guid?> ResolveActorAsync(Guid tenantId, Guid userId, Guid? cloneId)
        {
            if (cloneId.HasValue)
                return await _repo.GetActorIdForCloneAsync(tenantId, cloneId.Value);
            return await _repo.GetActorIdForUserAsync(tenantId, userId);
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
    [Route("api/v1/[controller]")]
    [Authorize]
    public class ActorController : ControllerBase
    {
        private readonly ActorService _service;

        public ActorController(ActorService service)
        {
            _service = service;
        }

        [HttpGet("get-actor-by-id")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetActorById(Guid actorId)
        {
            var tenantId = GetTenantId();
            var actor = await _service.GetActorAsync(tenantId, actorId);
            return actor != null ? Ok(actor) : NotFound();
        }

        [HttpGet("get-actor-by-handle")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetActorByHandle(string handle)
        {
            var tenantId = GetTenantId();
            var actor = await _service.GetActorByHandleAsync(tenantId, handle);
            return actor != null ? Ok(actor) : NotFound();
        }

        [HttpGet("my-actors")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetMyActors()
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();
            var actors = await _service.GetUserActorsAsync(tenantId, userId);
            return Ok(actors);
        }

        [HttpGet("get-actor-stats")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetActorStats(Guid actorId)
        {
            var tenantId = GetTenantId();
            var stats = await _service.GetActorStatsAsync(tenantId, actorId);
            return stats != null ? Ok(stats) : NotFound();
        }

        [HttpGet("search")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> SearchActors(
            [FromQuery] string? q,
            [FromQuery] string? type,
            [FromQuery] int limit = 20,
            [FromQuery] int offset = 0)
        {
            var tenantId = GetTenantId();
            var actors = await _service.SearchActorsAsync(tenantId, q, type, limit, offset);
            return Ok(actors);
        }

        [HttpPut("update-status")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> UpdateActorStatus(Guid actorId, [FromBody] UpdateActorStatusRequest request)
        {
            var tenantId = GetTenantId();
            await _service.UpdateActorStatusAsync(tenantId, actorId, request.Status);
            return Ok(new { success = true });
        }

        [HttpPost("activate-memorial")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> ActivateMemorial(Guid actorId)
        {
            var tenantId = GetTenantId();
            await _service.ActivateActorMemorialAsync(tenantId, actorId);
            return Ok(new { success = true });
        }

        [HttpPost("sync-human")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> SyncHumanActor([FromBody] SyncHumanActorRequest request)
        {
            var tenantId = GetTenantId();
            var result = await _service.EnsureHumanActorAsync(
                tenantId, request.UserId, request.DisplayName, request.Handle, request.AvatarUrl
            );
            return Ok(result);
        }

        [HttpPost("sync-clone")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> SyncCloneActor([FromBody] SyncCloneActorRequest request)
        {
            var tenantId = GetTenantId();
            var result = await _service.EnsureCloneActorAsync(
                tenantId, request.CloneId, request.OwnerUserId, request.DisplayName,
                request.Handle, request.AvatarUrl, request.IsMemorial, request.AutonomyLevel ?? "supervised"
            );
            return Ok(result);
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

    public class UpdateActorStatusRequest
    {
        public string Status { get; set; } = string.Empty;
    }

    public class SyncHumanActorRequest
    {
        public Guid UserId { get; set; }
        public string DisplayName { get; set; } = string.Empty;
        public string? Handle { get; set; }
        public string? AvatarUrl { get; set; }
    }

    public class SyncCloneActorRequest
    {
        public Guid CloneId { get; set; }
        public Guid OwnerUserId { get; set; }
        public string DisplayName { get; set; } = string.Empty;
        public string? Handle { get; set; }
        public string? AvatarUrl { get; set; }
        public bool IsMemorial { get; set; }
        public string? AutonomyLevel { get; set; }
    }
}
#endregion
