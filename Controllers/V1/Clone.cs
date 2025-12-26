// ==========================================================================
// CLONE MODULE — Clone Management (CORRECTED - Uses Functions)
// Single file: Repository + Service + Controller
// ==========================================================================

using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.DTO.Clone;
using KeiroGenesis.API.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

#region Repository
namespace KeiroGenesis.API.Repositories
{
    public class CloneRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<CloneRepository> _logger;

        public CloneRepository(IDbConnectionFactory db, ILogger<CloneRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        // Get user's clones - ✅ USES FUNCTION
        public async Task<IEnumerable<dynamic>> GetUserClonesAsync(Guid tenantId, Guid userId)
        {
            using var conn = _db.CreateConnection();

            return await conn.QueryAsync(
                "SELECT * FROM clone.fn_get_user_clones(@tenant_id, @user_id)",
                new { tenant_id = tenantId, user_id = userId }
            );
        }

        // Get single clone by ID - ✅ USES FUNCTION + ADDED user_id PARAMETER
        public async Task<dynamic?> GetCloneByIdAsync(Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                "SELECT * FROM clone.fn_get_clone_by_id(@tenant_id, @user_id, @clone_id)",
                new { tenant_id = tenantId, user_id = userId, clone_id = cloneId }
            );

            return result.FirstOrDefault();
        }
  
        // Update clone - ✅ USES FUNCTION + ADDED user_id PARAMETER
        public async Task<bool> UpdateCloneAsync(
            Guid tenantId,
            Guid userId,        // ✅ ADDED
            Guid cloneId,
            string? displayName,
            string? tagline,
            string? bio,
            string? avatarUrl,
            string? visibility)
        {
            using var conn = _db.CreateConnection();

            bool result = await conn.ExecuteScalarAsync<bool>(
                @"SELECT clone.fn_update_clone(
                    @tenant_id, 
                    @user_id,
                    @clone_id, 
                    @display_name,
                    @tagline,
                    @bio, 
                    @avatar_url,
                    @visibility
                )",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    clone_id = cloneId,
                    display_name = displayName,
                    tagline = tagline,
                    bio = bio,
                    avatar_url = avatarUrl,
                    visibility = visibility
                }
            );

            return result;
        }

        // Delete clone (soft delete) - ✅ USES FUNCTION + ADDED user_id PARAMETER
        public async Task<bool> DeleteCloneAsync(Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            bool result = await conn.ExecuteScalarAsync<bool>(
                "SELECT clone.fn_delete_clone(@tenant_id, @user_id, @clone_id)",
                new { tenant_id = tenantId, user_id = userId, clone_id = cloneId }
            );

            return result;
        }


        // =========================================================
        // GET CLONE STATUS (FUNCTION)
        // =========================================================
        public async Task<dynamic?> GetCloneStatusAsync(
            Guid tenantId,
            Guid userId,
            Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            return await conn.QueryFirstOrDefaultAsync(
                @"SELECT * 
              FROM clone.fn_get_clone_status(
                  @tenantId,
                  @userId,
                  @cloneId
              )",
                new
                {
                    tenantId,
                    userId,
                    cloneId
                });
        }


        public async Task<bool> UpdateCloneStatusAsync(
        Guid tenantId,
        Guid userId,
        Guid cloneId,
        string status)
        {
            using var conn = _db.CreateConnection();

            try
            {
                await conn.ExecuteAsync(
                    @"CALL clone.sp_update_clone_status(
                @tenantId,
                @userId,
                @cloneId,
                @status
            )",
                    new
                    {
                        tenantId,
                        userId,
                        cloneId,
                        status
                    });

                return true;
            }
            catch (Npgsql.PostgresException ex) when (ex.SqlState == "23514")
            {
                // Check constraint violation (actor doesn't exist)
                _logger.LogWarning(
                    "Activation blocked for clone {CloneId}: {Message}",
                    cloneId, ex.MessageText);
                throw new InvalidOperationException(ex.MessageText, ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error updating clone status for {CloneId} to {Status}",
                    cloneId, status);
                return false;
            }
        }

        public async Task<(bool canActivate, string reason)> CanCloneActivateAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryFirstOrDefaultAsync(
                @"SELECT can_activate, reason 
          FROM clone.fn_can_clone_activate(
              @tenant_id, @user_id, @clone_id
          )",
                new { tenant_id = tenantId, user_id = userId, clone_id = cloneId }
            );

            if (result == null)
                return (false, "Unable to verify activation readiness");

            return ((bool)result.can_activate, (string)result.reason);
        }

       
        // Get actor for a clone
        public async Task<dynamic?> GetCloneActorAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                @"SELECT 
            a.actor_id,
            a.display_name,
            a.handle,
            a.actor_type,
            a.status,
            a.avatar_url,
            ca.autonomy_level,
            ca.is_memorial,
            ca.owner_actor_id,
            ca.created_at as linked_at
          FROM actor.actors a
          JOIN actor.clone_actors ca ON ca.actor_id = a.actor_id
          JOIN clone.clones c ON c.clone_id = ca.clone_id
          WHERE ca.clone_id = @clone_id
            AND c.tenant_id = @tenant_id
            AND c.user_id = @user_id
            AND c.deleted_at IS NULL",
                new { clone_id = cloneId, tenant_id = tenantId, user_id = userId }
            );

            return result.FirstOrDefault();
        }


        // *** NEW: Get activation readiness details ***
        public async Task<dynamic?> GetActivationCheckAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                @"SELECT * FROM clone.fn_get_activation_readiness(
            @tenant_id, @user_id, @clone_id
        )",
                new { tenant_id = tenantId, user_id = userId, clone_id = cloneId }
            );

            return result.FirstOrDefault();
        }

        // Get comprehensive clone review for pre-activation check
        public async Task<dynamic?> GetCloneReviewAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            // Use a stored function to get all review data
            var result = await conn.QueryAsync(
                @"SELECT * FROM clone.fn_get_clone_review(
            @tenant_id, @user_id, @clone_id
        )",
                new { tenant_id = tenantId, user_id = userId, clone_id = cloneId }
            );

            return result.FirstOrDefault();
        }


    }



}

#endregion

#region Service
namespace KeiroGenesis.API.Services
{
    public class CloneService
    {
        private readonly CloneRepository _repo;
        private readonly ILogger<CloneService> _logger;

        public CloneService(CloneRepository repo, ILogger<CloneService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<ClonesListResponse> GetUserClonesAsync(Guid tenantId, Guid userId)
        {
            try
            {
                var clones = await _repo.GetUserClonesAsync(tenantId, userId);

                return new ClonesListResponse
                {
                    Success = true,
                    Clones = clones.Select(c => new CloneDto
                    {
                        CloneId = c.clone_id,
                        TenantId = c.tenant_id,
                        UserId = c.user_id,
                        CloneSlug = c.clone_slug,
                        DisplayName = c.display_name,
                        Tagline = c.tagline ?? "",
                        Bio = c.bio ?? "",
                        AvatarUrl = c.avatar_url ?? "",
                        Visibility = c.visibility ?? "private",
                        Status = c.status ?? "draft",
                        CreatedAt = c.created_at,
                        UpdatedAt = c.updated_at
                    }).ToList()
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting clones for user {UserId}", userId);
                return new ClonesListResponse
                {
                    Success = false,
                    Message = $"Failed to retrieve clones: {ex.Message}",
                    Clones = new List<CloneDto>()
                };
            }
        }

        public async Task<CloneResponse> GetCloneAsync(Guid tenantId, Guid userId, Guid cloneId)
        {
            try
            {
                var clone = await _repo.GetCloneByIdAsync(tenantId, userId, cloneId);

                if (clone == null)
                {
                    return new CloneResponse
                    {
                        Success = false,
                        Message = "Clone not found or you do not have permission to view it"
                    };
                }

                return new CloneResponse
                {
                    Success = true,
                    Clone = new CloneDto
                    {
                        CloneId = clone.clone_id,
                        TenantId = clone.tenant_id,
                        UserId = clone.user_id,
                        CloneSlug = clone.clone_slug,
                        DisplayName = clone.display_name,
                        Tagline = clone.tagline ?? "",
                        Bio = clone.bio ?? "",
                        AvatarUrl = clone.avatar_url ?? "",
                        Visibility = clone.visibility ?? "private",
                        Status = clone.status ?? "draft",
                        CreatedAt = clone.created_at,
                        UpdatedAt = clone.updated_at
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting clone {CloneId}", cloneId);
                return new CloneResponse
                {
                    Success = false,
                    Message = $"Failed to retrieve clone: {ex.Message}"
                };
            }
        }

        public async Task<CloneResponse> UpdateCloneAsync(
       Guid tenantId,
       Guid userId,
       Guid cloneId,
       UpdateCloneRequest request)
        {
            try
            {
                // *** NEW: Check activation gate if status change requested ***
                if (!string.IsNullOrEmpty(request.Status) &&
                    request.Status.ToLower() == "active")
                {
                    var (canActivate, reason) = await _repo.CanCloneActivateAsync(
                        tenantId, userId, cloneId);

                    if (!canActivate)
                    {
                        _logger.LogWarning(
                            "Clone {CloneId} cannot be activated: {Reason}",
                            cloneId, reason);

                        return new CloneResponse
                        {
                            Success = false,
                            Message = reason
                        };
                    }
                }

                bool success = await _repo.UpdateCloneAsync(
                    tenantId,
                    userId,
                    cloneId,
                    request.DisplayName,
                    request.Tagline,
                    request.Bio,
                    request.AvatarUrl,
                    request.Visibility
                );

                if (!success)
                {
                    return new CloneResponse
                    {
                        Success = false,
                        Message = "Clone not found or you do not have permission to update it"
                    };
                }

                // Get updated clone
                var clone = await _repo.GetCloneByIdAsync(tenantId, userId, cloneId);

                return new CloneResponse
                {
                    Success = true,
                    Message = "Clone updated successfully",
                    Clone = new CloneDto
                    {
                        CloneId = clone.clone_id,
                        TenantId = clone.tenant_id,
                        UserId = clone.user_id,
                        CloneSlug = clone.clone_slug,
                        DisplayName = clone.display_name,
                        Tagline = clone.tagline ?? "",
                        Bio = clone.bio ?? "",
                        AvatarUrl = clone.avatar_url ?? "",
                        Visibility = clone.visibility ?? "private",
                        Status = clone.status ?? "draft",
                        CreatedAt = clone.created_at,
                        UpdatedAt = clone.updated_at
                    }
                };
            }
            catch (InvalidOperationException ex)
            {
                // Catch actor enforcement exception from repository
                _logger.LogWarning(ex,
                    "Clone update failed for {CloneId}: {Message}",
                    cloneId, ex.Message);

                return new CloneResponse
                {
                    Success = false,
                    Message = ex.Message
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating clone {CloneId}", cloneId);
                return new CloneResponse
                {
                    Success = false,
                    Message = $"Failed to update clone: {ex.Message}"
                };
            }
        }

        public async Task<CloneStatusResponse> GetCloneStatusAsync(
          Guid tenantId,
          Guid userId,
          Guid cloneId)
        {
            try
            {
                var status = await _repo.GetCloneStatusAsync(tenantId, userId, cloneId);

                if (status == null)
                {
                    return new CloneStatusResponse
                    {
                        Success = false,
                        Message = "Clone not found"
                    };
                }

                return new CloneStatusResponse
                {
                    Success = true,
                    Message = "Status retrieved successfully",
                    CloneId = status.clone_id,
                    DisplayName = status.display_name,
                    Status = status.status,
                    IsActive = status.is_active,
                    IsPaused = status.is_paused,
                    TotalInteractions = status.total_interactions,
                    TotalMessages = status.total_messages,
                    LastActiveAt = status.last_active_at,
                    CreatedAt = status.created_at,
                    HealthStatus = status.health_status,
                    ResponseTimeMs = status.response_time_ms
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting clone status for {CloneId}", cloneId);
                return new CloneStatusResponse
                {
                    Success = false,
                    Message = "Failed to get clone status"
                };
            }
        }

        public async Task<CloneStatusResponse> UpdateCloneStatusAsync(
            Guid tenantId,
            Guid userId,
            Guid cloneId,
            string status)
        {
            try
            {
                // *** ACTIVATION GATE: Check if actor exists before allowing activation ***
                if (status.ToLower() == "active")
                {
                    var (canActivate, reason) = await _repo.CanCloneActivateAsync(
                        tenantId, userId, cloneId);

                    if (!canActivate)
                    {
                        _logger.LogWarning(
                            "Clone {CloneId} cannot be activated: {Reason}",
                            cloneId, reason);

                        return new CloneStatusResponse
                        {
                            Success = false,
                            CloneId = cloneId,
                            Message = reason
                        };
                    }
                }

                var updated = await _repo.UpdateCloneStatusAsync(
                    tenantId, userId, cloneId, status);

                if (!updated)
                {
                    return new CloneStatusResponse
                    {
                        Success = false,
                        Message = "Failed to update status"
                    };
                }

                // Fetch full status after update
                var fullStatus = await _repo.GetCloneStatusAsync(
                    tenantId, userId, cloneId);

                if (fullStatus == null)
                {
                    return new CloneStatusResponse
                    {
                        Success = true,
                        Message = "Status updated successfully",
                        Status = status,
                        CloneId = cloneId
                    };
                }

                return new CloneStatusResponse
                {
                    Success = true,
                    Message = "Status updated successfully",
                    CloneId = fullStatus.clone_id,
                    DisplayName = fullStatus.display_name,
                    Status = fullStatus.status,
                    IsActive = fullStatus.is_active,
                    IsPaused = fullStatus.is_paused,
                    TotalInteractions = fullStatus.total_interactions,
                    TotalMessages = fullStatus.total_messages,
                    LastActiveAt = fullStatus.last_active_at,
                    CreatedAt = fullStatus.created_at,
                    HealthStatus = fullStatus.health_status,
                    ResponseTimeMs = fullStatus.response_time_ms
                };
            }
            catch (InvalidOperationException ex)
            {
                // Actor enforcement exception from repository
                _logger.LogWarning(ex,
                    "Clone activation failed for {CloneId}: {Message}",
                    cloneId, ex.Message);

                return new CloneStatusResponse
                {
                    Success = false,
                    CloneId = cloneId,
                    Message = ex.Message
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating clone status");
                return new CloneStatusResponse
                {
                    Success = false,
                    Message = "Failed to update clone status"
                };
            }
        }
        // *** NEW: Check activation readiness ***
        public async Task<ActivationReadinessResponse> GetActivationCheckAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            try
            {
                var readiness = await _repo.GetActivationCheckAsync(
                    tenantId, userId, cloneId);

                if (readiness == null)
                {
                    return new ActivationReadinessResponse
                    {
                        Success = false,
                        CloneId = cloneId,
                        Message = "Clone not found or access denied"
                    };
                }

                // Parse blockers and next_steps arrays
                var blockers = new List<string>();
                var nextSteps = new List<string>();

                if (readiness.activation_blockers != null)
                {
                    string[] blockersArray = readiness.activation_blockers;
                    blockers.AddRange(blockersArray);
                }

                if (readiness.next_steps != null)
                {
                    string[] stepsArray = readiness.next_steps;
                    nextSteps.AddRange(stepsArray);
                }

                return new ActivationReadinessResponse
                {
                    Success = true,
                    CloneId = readiness.clone_id,
                    DisplayName = readiness.display_name ?? "",
                    CurrentStatus = readiness.current_status ?? "",
                    IsActive = readiness.is_active ?? false,
                    HasActor = readiness.has_actor ?? false,
                    ActorId = readiness.actor_id,
                    CanActivate = readiness.can_activate ?? false,
                    ActivationBlockers = blockers,
                    NextSteps = nextSteps,
                    Message = readiness.can_activate == true
                        ? "Clone is ready for activation"
                        : "Clone cannot be activated yet"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error checking activation readiness for clone {CloneId}",
                    cloneId);

                return new ActivationReadinessResponse
                {
                    Success = false,
                    CloneId = cloneId,
                    Message = $"Error: {ex.Message}"
                };
            }
        }

        public async Task<BaseResponse> DeleteCloneAsync(Guid tenantId, Guid userId, Guid cloneId)
        {
            try
            {
                bool success = await _repo.DeleteCloneAsync(tenantId, userId, cloneId);

                if (!success)
                {
                    return new BaseResponse
                    {
                        Success = false,
                        Message = "Clone not found or you do not have permission to delete it"
                    };
                }

                return new BaseResponse
                {
                    Success = true,
                    Message = "Clone deleted successfully"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting clone {CloneId}", cloneId);
                return new BaseResponse
                {
                    Success = false,
                    Message = $"Failed to delete clone: {ex.Message}"
                };
            }
        }

        public async Task<CloneActorResponse> GetCloneActorAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            try
            {
                var actor = await _repo.GetCloneActorAsync(tenantId, userId, cloneId);

                if (actor == null)
                {
                    return new CloneActorResponse
                    {
                        Success = false,
                        CloneId = cloneId,
                        Message = "No actor found for this clone"
                    };
                }

                return new CloneActorResponse
                {
                    Success = true,
                    CloneId = cloneId,
                    ActorId = actor.actor_id,
                    DisplayName = actor.display_name ?? "",
                    Handle = actor.handle ?? "",
                    ActorType = actor.actor_type ?? "",
                    Status = actor.status ?? "",
                    AvatarUrl = actor.avatar_url ?? "",
                    AutonomyLevel = actor.autonomy_level ?? "supervised",
                    IsMemorial = actor.is_memorial ?? false,
                    OwnerActorId = actor.owner_actor_id,
                    LinkedAt = actor.linked_at,
                    Message = "Actor retrieved successfully"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting actor for clone {CloneId}", cloneId);
                return new CloneActorResponse
                {
                    Success = false,
                    CloneId = cloneId,
                    Message = $"Failed to retrieve actor: {ex.Message}"
                };
            }
        }

        public async Task<CloneReviewResponse> GetCloneReviewAsync(
    Guid tenantId, Guid userId, Guid cloneId)
        {
            try
            {
                var review = await _repo.GetCloneReviewAsync(tenantId, userId, cloneId);

                if (review == null)
                {
                    return new CloneReviewResponse
                    {
                        Success = false,
                        Message = "Clone not found or access denied"
                    };
                }

                // Parse blockers and warnings arrays
                var blockers = new List<string>();
                var warnings = new List<string>();

                if (review.activation_blockers != null)
                {
                    string[] blockersArray = review.activation_blockers;
                    blockers.AddRange(blockersArray);
                }

                if (review.warnings != null)
                {
                    string[] warningsArray = review.warnings;
                    warnings.AddRange(warningsArray);
                }

                return new CloneReviewResponse
                {
                    Success = true,
                    Message = review.can_activate
                        ? "Clone is ready for activation"
                        : "Clone cannot be activated - see blockers",

                    // Clone Info
                    CloneId = review.clone_id,
                    DisplayName = review.display_name ?? "",
                    CloneSlug = review.clone_slug ?? "",
                    Tagline = review.tagline ?? "",
                    Bio = review.bio ?? "",
                    AvatarUrl = review.avatar_url ?? "",
                    Visibility = review.visibility ?? "private",
                    Status = review.status ?? "draft",
                    WizardStep = review.wizard_step ?? 0,
                    CreatedAt = review.created_at,

                    // Actor Info
                    HasActor = review.has_actor ?? false,
                    ActorId = review.actor_id,
                    ActorHandle = review.actor_handle ?? "",
                    ActorStatus = review.actor_status ?? "",
                    AutonomyLevel = review.autonomy_level ?? "supervised",

                    // Experiences
                    TotalExperiences = review.total_experiences ?? 0,
                    PublishedExperiences = review.published_experiences ?? 0,
                    DraftExperiences = review.draft_experiences ?? 0,

                    // Capabilities
                    Capabilities = review.capabilities?.ToString() ?? "{}",

                    // Owner Info
                    OwnerUserId = review.owner_user_id,
                    OwnerEmail = review.owner_email ?? "",
                    OwnerDisplayName = review.owner_display_name ?? "",

                    // Readiness
                    CanActivate = review.can_activate ?? false,
                    ActivationBlockers = blockers,
                    Warnings = warnings
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting clone review for {CloneId}", cloneId);
                return new CloneReviewResponse
                {
                    Success = false,
                    Message = $"Failed to retrieve clone review: {ex.Message}"
                };
            }
        }
    }

   

}
#endregion DTOs and Responses

namespace KeiroGenesis.API.DTO.Clone
{

    // DTOs
    public class UpdateCloneRequest
    {
        [JsonPropertyName("displayName")]
        public string? DisplayName { get; set; }

        [JsonPropertyName("tagline")]
        public string? Tagline { get; set; }

        [JsonPropertyName("bio")]
        public string? Bio { get; set; }

        [JsonPropertyName("avatarUrl")]
        public string? AvatarUrl { get; set; }

        [JsonPropertyName("visibility")]
        public string? Visibility { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }
    }

    public class BaseResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; } = string.Empty;
    }

    public class CloneResponse : BaseResponse
    {
        [JsonPropertyName("clone")]
        public CloneDto? Clone { get; set; }
    }

    public class ClonesListResponse : BaseResponse
    {
        [JsonPropertyName("clones")]
        public List<CloneDto> Clones { get; set; } = new();
    }

    public class CloneDto
    {
        [JsonPropertyName("cloneId")]
        public Guid CloneId { get; set; }

        [JsonPropertyName("tenantId")]
        public Guid TenantId { get; set; }

        [JsonPropertyName("userId")]
        public Guid UserId { get; set; }

        [JsonPropertyName("cloneSlug")]
        public string CloneSlug { get; set; } = string.Empty;

        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; } = string.Empty;

        [JsonPropertyName("tagline")]
        public string Tagline { get; set; } = string.Empty;

        [JsonPropertyName("bio")]
        public string Bio { get; set; } = string.Empty;

        [JsonPropertyName("avatarUrl")]
        public string AvatarUrl { get; set; } = string.Empty;

        [JsonPropertyName("visibility")]
        public string Visibility { get; set; } = string.Empty;

        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        [JsonPropertyName("createdAt")]
        public DateTime CreatedAt { get; set; }

        [JsonPropertyName("updatedAt")]
        public DateTime? UpdatedAt { get; set; }
    }
    public class CloneStatusResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public Guid? CloneId { get; set; }
        public string? DisplayName { get; set; }
        public string? Status { get; set; }

        // ✅ Match DB function return columns
        public bool? IsActive { get; set; }
        public bool? IsPaused { get; set; }
        public int? TotalInteractions { get; set; }
        public int? TotalMessages { get; set; }
        public DateTime? LastActiveAt { get; set; }
        public DateTime? CreatedAt { get; set; }
        public string? HealthStatus { get; set; }
        public int? ResponseTimeMs { get; set; }
    }

    public class UpdateStatusRequest
    {
        public string Status { get; set; } = string.Empty;
    }

    // *** NEW DTO: Activation Readiness Response ***
    public sealed class ActivationReadinessResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("cloneId")]
        public Guid CloneId { get; init; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; init; } = string.Empty;

        [JsonPropertyName("currentStatus")]
        public string CurrentStatus { get; init; } = string.Empty;

        [JsonPropertyName("isActive")]
        public bool IsActive { get; init; }

        [JsonPropertyName("hasActor")]
        public bool HasActor { get; init; }

        [JsonPropertyName("actorId")]
        public Guid? ActorId { get; init; }

        [JsonPropertyName("canActivate")]
        public bool CanActivate { get; init; }

        [JsonPropertyName("activationBlockers")]
        public List<string> ActivationBlockers { get; init; } = new();

        [JsonPropertyName("nextSteps")]
        public List<string> NextSteps { get; init; } = new();

        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;
    }

    public sealed class CloneActorResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("cloneId")]
        public Guid CloneId { get; init; }

        [JsonPropertyName("actorId")]
        public Guid? ActorId { get; init; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; init; } = string.Empty;

        [JsonPropertyName("handle")]
        public string Handle { get; init; } = string.Empty;

        [JsonPropertyName("actorType")]
        public string ActorType { get; init; } = string.Empty;

        [JsonPropertyName("status")]
        public string Status { get; init; } = string.Empty;

        [JsonPropertyName("avatarUrl")]
        public string AvatarUrl { get; init; } = string.Empty;

        [JsonPropertyName("autonomyLevel")]
        public string AutonomyLevel { get; init; } = string.Empty;

        [JsonPropertyName("isMemorial")]
        public bool IsMemorial { get; init; }

        [JsonPropertyName("ownerActorId")]
        public Guid? OwnerActorId { get; init; }

        [JsonPropertyName("linkedAt")]
        public DateTime? LinkedAt { get; init; }

        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;
    }

    public sealed class CloneReviewResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;

        // Clone Information
        [JsonPropertyName("cloneId")]
        public Guid CloneId { get; init; }

        [JsonPropertyName("displayName")]
        public string DisplayName { get; init; } = string.Empty;

        [JsonPropertyName("cloneSlug")]
        public string CloneSlug { get; init; } = string.Empty;

        [JsonPropertyName("tagline")]
        public string Tagline { get; init; } = string.Empty;

        [JsonPropertyName("bio")]
        public string Bio { get; init; } = string.Empty;

        [JsonPropertyName("avatarUrl")]
        public string AvatarUrl { get; init; } = string.Empty;

        [JsonPropertyName("visibility")]
        public string Visibility { get; init; } = string.Empty;

        [JsonPropertyName("status")]
        public string Status { get; init; } = string.Empty;

        [JsonPropertyName("wizardStep")]
        public int WizardStep { get; init; }

        [JsonPropertyName("createdAt")]
        public DateTime? CreatedAt { get; init; }

        // Actor Information
        [JsonPropertyName("hasActor")]
        public bool HasActor { get; init; }

        [JsonPropertyName("actorId")]
        public Guid? ActorId { get; init; }

        [JsonPropertyName("actorHandle")]
        public string ActorHandle { get; init; } = string.Empty;

        [JsonPropertyName("actorStatus")]
        public string ActorStatus { get; init; } = string.Empty;

        [JsonPropertyName("autonomyLevel")]
        public string AutonomyLevel { get; init; } = string.Empty;

        // Experiences
        [JsonPropertyName("totalExperiences")]
        public int TotalExperiences { get; init; }

        [JsonPropertyName("publishedExperiences")]
        public int PublishedExperiences { get; init; }

        [JsonPropertyName("draftExperiences")]
        public int DraftExperiences { get; init; }

        // Capabilities
        [JsonPropertyName("capabilities")]
        public string Capabilities { get; init; } = "{}";

        // Owner Information
        [JsonPropertyName("ownerUserId")]
        public Guid? OwnerUserId { get; init; }

        [JsonPropertyName("ownerEmail")]
        public string OwnerEmail { get; init; } = string.Empty;

        [JsonPropertyName("ownerDisplayName")]
        public string OwnerDisplayName { get; init; } = string.Empty;

        // Activation Readiness
        [JsonPropertyName("canActivate")]
        public bool CanActivate { get; init; }

        [JsonPropertyName("activationBlockers")]
        public List<string> ActivationBlockers { get; init; } = new();

        [JsonPropertyName("warnings")]
        public List<string> Warnings { get; init; } = new();
    }
}


#region
#endregion

#region Controller
namespace KeiroGenesis.API.Controllers.V1
{

    [Route("api/v1/clone")]
    [Authorize]
    public class CloneController : ControllerBase
    {
        private readonly Services.CloneService _service;
        private readonly ILogger<CloneController> _logger;

        public CloneController(Services.CloneService service, ILogger<CloneController> logger)
        {
            _service = service;
            _logger = logger;
        }

        /// <summary>
        /// Get all my clones
        /// </summary>
        [HttpGet("my-clones")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetMyClones()
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();

            var result = await _service.GetUserClonesAsync(tenantId, userId);
            return Ok(result);
        }

        /// <summary>
        /// Get clone by ID
        /// </summary>
        [HttpGet("{cloneId}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetClone(Guid cloneId)
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();

            var result = await _service.GetCloneAsync(tenantId, userId, cloneId);

            if (!result.Success)
                return NotFound(result);

            return Ok(result);
        }

        /// <summary>
        /// Update clone
        /// </summary>
        [HttpPut("{cloneId}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> UpdateClone(Guid cloneId, [FromBody] UpdateCloneRequest request)
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();

            var result = await _service.UpdateCloneAsync(tenantId, userId, cloneId, request);

            if (!result.Success)
                return result.Message.Contains("not found") ? NotFound(result) : BadRequest(result);

            return Ok(result);
        }

        /// <summary>
        /// Delete clone
        /// </summary>
        [HttpDelete("{cloneId}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> DeleteClone(Guid cloneId)
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();

            var result = await _service.DeleteCloneAsync(tenantId, userId, cloneId);

            if (!result.Success)
                return NotFound(result);

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
            var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                     ?? User.FindFirst("sub")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var userId))
                throw new UnauthorizedAccessException("Invalid user claim");
            return userId;
        }

        /// <summary>
        /// Get clone status
        /// </summary>
        [HttpGet("{cloneId}/status")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetStatus(Guid cloneId)
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();

            _logger.LogInformation("Getting status for clone {CloneId}", cloneId);

            var result = await _service.GetCloneStatusAsync(tenantId, userId, cloneId);

            if (!result.Success)
                return NotFound(result);

            return Ok(result);
        }

        /// <summary>
        /// Update clone status (activation requires actor)
        /// </summary>
        /// <remarks>
        /// **IMPORTANT**: Setting status to 'active' requires an actor runtime to exist.
        /// 
        /// **Before activating:**
        /// 1. Check: GET /api/v1/clones/{cloneId}/activation-readiness
        /// 2. If hasActor = false: POST /api/v1/actors/ensure-runtime/{cloneId}
        /// 3. Then activate: PUT /api/v1/clones/{cloneId}/status
        /// 
        /// **This endpoint will fail if:**
        /// - Actor runtime doesn't exist (for status='active')
        /// - User doesn't own the clone
        /// - Clone not found
        /// </remarks>
        [HttpPut("{cloneId}/status")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> UpdateStatus(
            Guid cloneId,
            [FromBody] UpdateStatusRequest request)
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();

            _logger.LogInformation("Updating status for clone {CloneId} to {Status}",
                cloneId, request.Status);

            var result = await _service.UpdateCloneStatusAsync(
                tenantId, userId, cloneId, request.Status);

            if (!result.Success)
                return result.Message.Contains("not found") ? NotFound(result) : BadRequest(result);

            return Ok(result);
        }

        /// <summary>
        /// Check if clone is ready for activation
        /// </summary>
        /// <remarks>
        /// Returns detailed activation status including:
        /// - Whether actor exists
        /// - Whether clone can be activated
        /// - Blockers preventing activation
        /// - Next steps to enable activation
        /// 
        /// **Use this endpoint before showing "Activate" button in UI**
        /// </remarks>
        [HttpGet("{cloneId}/pre-activation-check")]
        [ProducesResponseType(typeof(ActivationReadinessResponse), 200)]
        public async Task<IActionResult> GetActivationCheck(Guid cloneId)
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();

            var result = await _service.GetActivationCheckAsync(
                tenantId, userId, cloneId);

            return Ok(result);
        }


        /// <summary>
        /// Get comprehensive pre-activation review for clone
        /// </summary>
        /// <remarks>
        /// Returns a complete review of the clone including:
        /// - Clone basic information
        /// - Actor assignment status
        /// - Experiences count (published vs draft)
        /// - Configured capabilities
        /// - Owner information
        /// - Activation readiness with specific blockers and warnings
        /// 
        /// **Use this endpoint before activation to catch any issues!**
        /// </remarks>
        [HttpGet("{cloneId}/final-activation-review")]
        [ProducesResponseType(typeof(CloneReviewResponse), 200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetCloneReview(Guid cloneId)
        {
            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();

            _logger.LogInformation("Getting pre-activation review for clone {CloneId}", cloneId);

            var result = await _service.GetCloneReviewAsync(tenantId, userId, cloneId);

            if (!result.Success)
                return NotFound(result);

            return Ok(result);
        }
    }

}
#endregion