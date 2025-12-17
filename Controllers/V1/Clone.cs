// ==========================================================================
// CLONE MODULE — Clone Management (CORRECTED - Uses Functions)
// Single file: Repository + Service + Controller
// ==========================================================================

using Dapper;
using KeiroGenesis.API.Core.Database;
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
}
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
        public async Task<IActionResult> UpdateClone(Guid cloneId, [FromBody] Services.UpdateCloneRequest request)
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
    }
}
#endregion