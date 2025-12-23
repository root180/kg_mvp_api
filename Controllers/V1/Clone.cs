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
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
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

        // =========================================================
        // UPDATE CLONE STATUS (PROCEDURE)
        // =========================================================
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
            catch
            {
                return false;
            }
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
                var updated = await _repo.UpdateCloneStatusAsync(
                    tenantId, userId, cloneId, status);

                if (!updated)
                {
                    return new CloneStatusResponse
                    {
                        Success = false,
                        Message = "Clone not found or update failed"
                    };
                }

                return new CloneStatusResponse
                {
                    Success = true,
                    Message = "Status updated successfully",
                    CloneId = cloneId,
                    Status = status
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error updating clone status for {CloneId}", cloneId);

                return new CloneStatusResponse
                {
                    Success = false,
                    Message = "Failed to update status"
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

}


#region
#endregion

#region Controller
namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
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
        /// Update clone status
        /// </summary>
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
    }
}
#endregion