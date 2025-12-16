// ==========================================================================
// ACTOR MODULE — Runtime Execution Identity
// ==========================================================================
// 
// Actor Domain Contract:
// - Actors represent runtime identities that can speak, remember, and act.
// - Actors may correspond to clones, humans, or system entities.
// - Clone lifecycle defines WHEN an actor should exist.
// - Actor services ensure execution capability, not ownership or governance.
// - Actor records are safe to ensure idempotently at any time.
// 
// Separation of Concerns:
// - Clone Module: Owns creation, lifecycle, and governance decisions
// - Actor Module: Owns runtime execution, social identity, and interaction
// 
// Key Principle:
// Actors must never be ambiguous at runtime. Every operation should
// explicitly identify whether it's operating as a human or clone.
// 
// ==========================================================================

using System;
using System.Collections.Generic;
using System.Data;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

// ==========================================================================
#region DTOs - API Boundary Only
// ==========================================================================
// DTO Policy:
// - DTOs ONLY at API boundaries (Controller requests/responses)
// - Intent-named, not entity-named
// - One DTO = One use case
// - Flat, boring, honest (no behavior, no inheritance, no mapping logic)
// - If it crosses a boundary → DTO. If it stays inside → don't.
// ==========================================================================

namespace KeiroGenesis.API.DTOs.Actor
{
    // Request: Ensure human actor exists (idempotent)
    public sealed class EnsureHumanActorRequest
    {
        [JsonPropertyName("userId")]
        public Guid UserId { get; init; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; init; } = string.Empty;

        [JsonPropertyName("handle")]
        public string? Handle { get; init; }

        [JsonPropertyName("avatarUrl")]
        public string? AvatarUrl { get; init; }
    }

    // Request: Ensure clone actor exists (idempotent)
    public sealed class EnsureCloneActorRequest
    {
        [JsonPropertyName("cloneId")]
        public Guid CloneId { get; init; }

        [JsonPropertyName("ownerUserId")]
        public Guid OwnerUserId { get; init; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; init; } = string.Empty;

        [JsonPropertyName("handle")]
        public string? Handle { get; init; }

        [JsonPropertyName("avatarUrl")]
        public string? AvatarUrl { get; init; }

        [JsonPropertyName("isMemorial")]
        public bool IsMemorial { get; init; }

        [JsonPropertyName("autonomyLevel")]
        public string? AutonomyLevel { get; init; }
    }

    // Request: Update actor runtime status
    public sealed class UpdateActorStatusRequest
    {
        [JsonPropertyName("status")]
        public string Status { get; init; } = string.Empty;
    }

    // Response: Actor resolution result
    public sealed class ActorResolutionResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("actorId")]
        public Guid? ActorId { get; init; }

        [JsonPropertyName("actorType")]
        public string? ActorType { get; init; }

        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;
    }

    // Response: Actor runtime statistics
    public sealed class ActorRuntimeStatsResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("actorId")]
        public Guid ActorId { get; init; }

        [JsonPropertyName("followerCount")]
        public int FollowerCount { get; init; }

        [JsonPropertyName("followingCount")]
        public int FollowingCount { get; init; }

        [JsonPropertyName("postCount")]
        public int PostCount { get; init; }

        [JsonPropertyName("totalConversations")]
        public int TotalConversations { get; init; }

        [JsonPropertyName("totalMessages")]
        public int TotalMessages { get; init; }
    }

    // Response: Actor profile
    public sealed class ActorProfileResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("actorId")]
        public Guid ActorId { get; init; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; init; } = string.Empty;

        [JsonPropertyName("handle")]
        public string? Handle { get; init; }

        [JsonPropertyName("avatarUrl")]
        public string? AvatarUrl { get; init; }

        [JsonPropertyName("status")]
        public string Status { get; init; } = string.Empty;

        [JsonPropertyName("actorType")]
        public string ActorType { get; init; } = string.Empty;

        [JsonPropertyName("createdAt")]
        public DateTime CreatedAt { get; init; }
    }

    // Response: Actor search results
    public sealed class ActorSearchResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("actors")]
        public List<ActorSearchResult> Actors { get; init; } = new();

        [JsonPropertyName("total")]
        public int Total { get; init; }
    }

    public sealed class ActorSearchResult
    {
        [JsonPropertyName("actorId")]
        public Guid ActorId { get; init; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; init; } = string.Empty;

        [JsonPropertyName("handle")]
        public string? Handle { get; init; }

        [JsonPropertyName("avatarUrl")]
        public string? AvatarUrl { get; init; }

        [JsonPropertyName("actorType")]
        public string ActorType { get; init; } = string.Empty;
    }

    // Response: User's actors list
    public sealed class UserActorsResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("actors")]
        public List<UserActorSummary> Actors { get; init; } = new();

        [JsonPropertyName("total")]
        public int Total { get; init; }
    }

    public sealed class UserActorSummary
    {
        [JsonPropertyName("actorId")]
        public Guid ActorId { get; init; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; init; } = string.Empty;

        [JsonPropertyName("handle")]
        public string? Handle { get; init; }

        [JsonPropertyName("avatarUrl")]
        public string? AvatarUrl { get; init; }

        [JsonPropertyName("actorType")]
        public string ActorType { get; init; } = string.Empty;

        [JsonPropertyName("status")]
        public string Status { get; init; } = string.Empty;
    }

    // Response: Generic success
    public sealed class ActorOperationResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;

        [JsonPropertyName("actorId")]
        public Guid? ActorId { get; init; }
    }
}
#endregion

// ==========================================================================
#region Repository
// ==========================================================================
// Repository uses dynamic for DB results - NO DTOs here
// DTOs are ONLY for API boundaries
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
// Service uses DTOs ONLY when returning to Controller
// Internal operations use dynamic DB results
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
            _logger.LogInformation("Ensured human actor for user {UserId}", userId);
            return result;
        }

        public async Task<dynamic> EnsureCloneActorAsync(
            Guid tenantId, Guid cloneId, Guid ownerUserId, string displayName,
            string? handle, string? avatarUrl, bool isMemorial = false, string autonomyLevel = "supervised")
        {
            var result = await _repo.SyncCloneActorAsync(
                tenantId, cloneId, ownerUserId, displayName, handle, avatarUrl, isMemorial, autonomyLevel
            );
            _logger.LogInformation("Ensured clone actor for clone {CloneId}", cloneId);
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

        // Explicit runtime identity resolution
        public async Task<Guid?> ResolveHumanActorAsync(Guid tenantId, Guid userId)
        {
            return await _repo.GetActorIdForUserAsync(tenantId, userId);
        }

        public async Task<Guid?> ResolveCloneActorAsync(Guid tenantId, Guid cloneId)
        {
            return await _repo.GetActorIdForCloneAsync(tenantId, cloneId);
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
// Controller is the DTO boundary
// All requests IN are DTOs
// All responses OUT are DTOs
// ==========================================================================

namespace KeiroGenesis.API.Controllers.V1
{
    using DTOs.Actor;

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
        [ProducesResponseType(typeof(ActorProfileResponse), 200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetActorById(Guid actorId)
        {
            var tenantId = GetTenantId();
            var actor = await _service.GetActorAsync(tenantId, actorId);

            if (actor == null)
                return NotFound();

            // Map to DTO at boundary
            var response = new ActorProfileResponse
            {
                Success = true,
                ActorId = actor.actor_id,
                DisplayName = actor.display_name ?? "",
                Handle = actor.handle,
                AvatarUrl = actor.avatar_url,
                Status = actor.status ?? "",
                ActorType = actor.actor_type ?? "",
                CreatedAt = actor.created_at
            };

            return Ok(response);
        }

        [HttpGet("get-actor-by-handle")]
        [ProducesResponseType(typeof(ActorProfileResponse), 200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetActorByHandle(string handle)
        {
            var tenantId = GetTenantId();
            var actor = await _service.GetActorByHandleAsync(tenantId, handle);

            if (actor == null)
                return NotFound();

            var response = new ActorProfileResponse
            {
                Success = true,
                ActorId = actor.actor_id,
                DisplayName = actor.display_name ?? "",
                Handle = actor.handle,
                AvatarUrl = actor.avatar_url,
                Status = actor.status ?? "",
                ActorType = actor.actor_type ?? "",
                CreatedAt = actor.created_at
            };

            return Ok(response);
        }

        [HttpGet("my-actors")]
        [ProducesResponseType(typeof(UserActorsResponse), 200)]
        public async Task<IActionResult> GetMyActors()
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();
            var actors = await _service.GetUserActorsAsync(tenantId, userId);

            var response = new UserActorsResponse
            {
                Success = true,
                Actors = actors.Select(a => new UserActorSummary
                {
                    ActorId = a.actor_id,
                    DisplayName = a.display_name ?? "",
                    Handle = a.handle,
                    AvatarUrl = a.avatar_url,
                    ActorType = a.actor_type ?? "",
                    Status = a.status ?? ""
                }).ToList(),
                Total = actors.Count
            };

            return Ok(response);
        }

        [HttpGet("get-actor-stats")]
        [ProducesResponseType(typeof(ActorRuntimeStatsResponse), 200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetActorStats(Guid actorId)
        {
            var tenantId = GetTenantId();
            var stats = await _service.GetActorStatsAsync(tenantId, actorId);

            if (stats == null)
                return NotFound();

            var response = new ActorRuntimeStatsResponse
            {
                Success = true,
                ActorId = stats.actor_id,
                FollowerCount = stats.follower_count,
                FollowingCount = stats.following_count,
                PostCount = stats.post_count,
                TotalConversations = stats.total_conversations,
                TotalMessages = stats.total_messages
            };

            return Ok(response);
        }

        [HttpGet("search")]
        [ProducesResponseType(typeof(ActorSearchResponse), 200)]
        public async Task<IActionResult> SearchActors(
            [FromQuery] string? q,
            [FromQuery] string? type,
            [FromQuery] int limit = 20,
            [FromQuery] int offset = 0)
        {
            var tenantId = GetTenantId();
            var actors = await _service.SearchActorsAsync(tenantId, q, type, limit, offset);

            var response = new ActorSearchResponse
            {
                Success = true,
                Actors = actors.Select(a => new ActorSearchResult
                {
                    ActorId = a.actor_id,
                    DisplayName = a.display_name ?? "",
                    Handle = a.handle,
                    AvatarUrl = a.avatar_url,
                    ActorType = a.actor_type ?? ""
                }).ToList(),
                Total = actors.Count
            };

            return Ok(response);
        }

        [HttpPut("update-status")]
        [ProducesResponseType(typeof(ActorOperationResponse), 200)]
        public async Task<IActionResult> UpdateActorStatus(Guid actorId, [FromBody] UpdateActorStatusRequest request)
        {
            var tenantId = GetTenantId();
            await _service.UpdateActorStatusAsync(tenantId, actorId, request.Status);

            return Ok(new ActorOperationResponse
            {
                Success = true,
                Message = "Actor status updated",
                ActorId = actorId
            });
        }

        [HttpPost("activate-memorial")]
        [ProducesResponseType(typeof(ActorOperationResponse), 200)]
        public async Task<IActionResult> ActivateMemorial(Guid actorId)
        {
            var tenantId = GetTenantId();
            await _service.ActivateActorMemorialAsync(tenantId, actorId);

            return Ok(new ActorOperationResponse
            {
                Success = true,
                Message = "Memorial activated",
                ActorId = actorId
            });
        }

        [HttpPost("sync-human")]
        [ProducesResponseType(typeof(ActorOperationResponse), 200)]
        public async Task<IActionResult> SyncHumanActor([FromBody] EnsureHumanActorRequest request)
        {
            var tenantId = GetTenantId();
            var result = await _service.EnsureHumanActorAsync(
                tenantId, request.UserId, request.DisplayName, request.Handle, request.AvatarUrl
            );

            return Ok(new ActorOperationResponse
            {
                Success = true,
                Message = "Human actor ensured",
                ActorId = result.actor_id
            });
        }

        [HttpPost("sync-clone")]
        [ProducesResponseType(typeof(ActorOperationResponse), 200)]
        public async Task<IActionResult> SyncCloneActor([FromBody] EnsureCloneActorRequest request)
        {
            var tenantId = GetTenantId();
            var result = await _service.EnsureCloneActorAsync(
                tenantId, request.CloneId, request.OwnerUserId, request.DisplayName,
                request.Handle, request.AvatarUrl, request.IsMemorial, request.AutonomyLevel ?? "supervised"
            );

            return Ok(new ActorOperationResponse
            {
                Success = true,
                Message = "Clone actor ensured",
                ActorId = result.actor_id
            });
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
            var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                     ?? User.FindFirst("sub")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var userId))
                throw new UnauthorizedAccessException("Invalid user claim");
            return userId;
        }
    }
}
#endregion