// ==========================================================================
// ACTOR RUNTIME - ENSURE CLONE ACTOR ENDPOINT
// ==========================================================================
// Single file: Repository + Service + Controller
// Purpose: Ensure actor runtime exists for a clone (idempotent)
// Pattern: User owns Clone, Clone spawns Actor
// Authorization: C# verifies ownership, Database enforces integrity
// ==========================================================================

using System;
using System.Linq;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Dapper;
using KeiroGenesis.API.Core.Database;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

// ==========================================================================
#region DTOs
// ==========================================================================

namespace KeiroGenesis.API.DTOs.ActorRuntime
{
    // Response: Actor runtime information
    public sealed class ActorRuntimeResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("actorId")]
        public Guid ActorId { get; init; }

        [JsonPropertyName("cloneId")]
        public Guid CloneId { get; init; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; init; } = string.Empty;

        [JsonPropertyName("handle")]
        public string Handle { get; init; } = string.Empty;

        [JsonPropertyName("actorType")]
        public string ActorType { get; init; } = string.Empty;

        [JsonPropertyName("status")]
        public string Status { get; init; } = string.Empty;

        [JsonPropertyName("autonomyLevel")]
        public string AutonomyLevel { get; init; } = string.Empty;

        [JsonPropertyName("isNew")]
        public bool IsNew { get; init; }

        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;
    }
}

#endregion

// ==========================================================================
#region Repository
// ==========================================================================

namespace KeiroGenesis.API.Repositories
{
    public class ActorRuntimeRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<ActorRuntimeRepository> _logger;

        public ActorRuntimeRepository(
            IDbConnectionFactory db,
            ILogger<ActorRuntimeRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        // Verify clone ownership (C# authorization layer)
        public async Task<bool> CloneBelongsToUserAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            bool exists = await conn.ExecuteScalarAsync<bool>(
                @"SELECT EXISTS (
                    SELECT 1
                    FROM clone.clones
                    WHERE clone_id = @clone_id
                      AND tenant_id = @tenant_id
                      AND user_id = @user_id
                      AND deleted_at IS NULL
                )",
                new { clone_id = cloneId, tenant_id = tenantId, user_id = userId }
            );

            return exists;
        }

        // Ensure actor runtime (idempotent - get existing or create new)
        public async Task<dynamic?> EnsureCloneActorAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                @"SELECT * FROM actor.fn_ensure_clone_actor(
                    @p_tenant_id, @p_user_id, @p_clone_id
                )",
                new
                {
                    p_tenant_id = tenantId,
                    p_user_id = userId,
                    p_clone_id = cloneId
                }
            );

            return result.FirstOrDefault();
        }
    }
}

#endregion

// ==========================================================================
#region Service
// ==========================================================================

namespace KeiroGenesis.API.Services
{
    public class ActorRuntimeService
    {
        private readonly Repositories.ActorRuntimeRepository _repo;
        private readonly ILogger<ActorRuntimeService> _logger;

        public ActorRuntimeService(
            Repositories.ActorRuntimeRepository repo,
            ILogger<ActorRuntimeService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<DTOs.ActorRuntime.ActorRuntimeResponse> EnsureRuntimeAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            try
            {
                // ============================================================
                // STEP 1: Authorization - Verify clone ownership in C#
                // ============================================================

                bool ownsClone = await _repo.CloneBelongsToUserAsync(
                    tenantId, userId, cloneId);

                if (!ownsClone)
                {
                    _logger.LogWarning(
                        "User {UserId} attempted to create actor for clone {CloneId} (unauthorized)",
                        userId, cloneId);

                    return new DTOs.ActorRuntime.ActorRuntimeResponse
                    {
                        Success = false,
                        ActorId = Guid.Empty,
                        CloneId = cloneId,
                        Message = "You do not own this clone"
                    };
                }

                // ============================================================
                // STEP 2: Ensure actor runtime (idempotent)
                // ============================================================

                dynamic? actor = await _repo.EnsureCloneActorAsync(
                    tenantId, userId, cloneId);

                if (actor == null)
                {
                    _logger.LogError(
                        "Failed to ensure actor runtime for clone {CloneId}",
                        cloneId);

                    return new DTOs.ActorRuntime.ActorRuntimeResponse
                    {
                        Success = false,
                        ActorId = Guid.Empty,
                        CloneId = cloneId,
                        Message = "Failed to create actor runtime"
                    };
                }

                // ============================================================
                // STEP 3: Return actor information
                // ============================================================

                bool isNew = actor.is_new ?? false;

                _logger.LogInformation(
                    "Actor runtime ensured for clone {CloneId}: actor_id={ActorId}, is_new={IsNew}",
                    cloneId, (Guid)actor.actor_id, isNew);

                return new DTOs.ActorRuntime.ActorRuntimeResponse
                {
                    Success = true,
                    ActorId = actor.actor_id,
                    CloneId = actor.clone_id,
                    DisplayName = actor.display_name ?? "",
                    Handle = actor.handle ?? "",
                    ActorType = actor.actor_type ?? "clone",
                    Status = actor.status ?? "active",
                    AutonomyLevel = actor.autonomy_level ?? "supervised",
                    IsNew = isNew,
                    Message = isNew
                        ? "Actor runtime created successfully"
                        : "Actor runtime already exists"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error ensuring actor runtime for clone {CloneId}",
                    cloneId);

                return new DTOs.ActorRuntime.ActorRuntimeResponse
                {
                    Success = false,
                    ActorId = Guid.Empty,
                    CloneId = cloneId,
                    Message = $"Error: {ex.Message}"
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
    /// <summary>
    /// Actor Runtime - Ensure actor execution context for clones
    /// </summary>
    [Route("api/v1/actors")]
    [ApiController]
    [Authorize]
    public class ActorRuntimeController : ControllerBase
    {
        private readonly Services.ActorRuntimeService _service;
        private readonly ILogger<ActorRuntimeController> _logger;

        public ActorRuntimeController(
            Services.ActorRuntimeService service,
            ILogger<ActorRuntimeController> logger)
        {
            _service = service;
            _logger = logger;
        }

        private Guid GetTenantId()
        {
            string? claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out Guid tenantId))
                throw new UnauthorizedAccessException("Invalid tenant claim");
            return tenantId;
        }

        private Guid GetCurrentUserId()
        {
            string? claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                         ?? User.FindFirst("sub")?.Value;
            if (claim == null || !Guid.TryParse(claim, out Guid userId))
                throw new UnauthorizedAccessException("Invalid user claim");
            return userId;
        }

        /// <summary>
        /// Ensure actor runtime exists for a clone (idempotent)
        /// </summary>
        /// <param name="cloneId">Clone ID to instantiate actor from</param>
        /// <returns>Actor runtime information (existing or newly created)</returns>
        /// <remarks>
        /// This endpoint ensures an actor runtime exists for the specified clone.
        /// 
        /// **Behavior:**
        /// - If actor already exists → returns existing actor
        /// - If actor doesn't exist → creates new actor → returns new actor
        /// - Idempotent: safe to call multiple times
        /// 
        /// **MVP Rule:** One actor per clone
        /// 
        /// **Architecture:**
        /// - User owns Clone
        /// - Clone spawns Actor
        /// - Actor is runtime execution context
        /// 
        /// **Authorization:**
        /// - Verified in C# (controller layer)
        /// - User must own the clone
        /// - Clone must be active
        /// </remarks>
        [HttpPost("ensure-runtime/{cloneId}")]
        [ProducesResponseType(typeof(DTOs.ActorRuntime.ActorRuntimeResponse), 200)]
        [ProducesResponseType(403)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> EnsureRuntime(Guid cloneId)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation(
                "Ensuring actor runtime for clone {CloneId}, user {UserId}",
                cloneId, userId);

            var result = await _service.EnsureRuntimeAsync(
                tenantId, userId, cloneId);

            if (!result.Success)
            {
                if (result.Message.Contains("do not own"))
                    return StatusCode(403, result);

                return StatusCode(500, result);
            }

            return Ok(result);
        }
    }
}

#endregion