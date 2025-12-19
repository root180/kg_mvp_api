// ==========================================================================
// EXPERIENCE WIZARD MODULE — Create Bounded Interaction Contexts
// Single file: DTOs + Repository + Service + Controller
// Pattern: Repository calls functions ONLY (no raw SQL)
// Authorization: Defense-in-depth (C# checks + DB validates)
// ==========================================================================

using System;
using System.Collections.Generic;
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
namespace KeiroGenesis.API.DTOs.ExperienceWizard
{
    /// <summary>
    /// Content rating for experiences (age-appropriateness)
    /// </summary>
    public enum ExperienceRating
    {
        G,      // General Audiences (All ages)
        PG,     // Parental Guidance
        PG13,   // Parents Strongly Cautioned (Under 13)
        MA      // Mature Audiences Only (18+)
    }

    public class ExperienceWizardResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? ErrorCode { get; set; }
        public Guid? ExperienceId { get; set; }
        public Guid? CloneId { get; set; }
        public object? Data { get; set; }
    }

    /// <summary>
    /// Step 1: Create Experience (Select Clone + Name)
    /// </summary>
    public class CreateExperienceRequest
    {
        [JsonPropertyName("cloneId")]
        public Guid CloneId { get; set; }

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string? Description { get; set; }
    }

    /// <summary>
    /// Step 2: Set Rating
    /// </summary>
    public class SetRatingRequest
    {
        [JsonPropertyName("rating")]
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ExperienceRating Rating { get; set; } = ExperienceRating.PG;
    }

    /// <summary>
    /// Step 3: Publish Experience
    /// </summary>
    public class PublishRequest
    {
        [JsonPropertyName("isPublic")]
        public bool IsPublic { get; set; } = true;
    }
}
#endregion

// ==========================================================================
#region Repository
// ==========================================================================
namespace KeiroGenesis.API.Repositories
{
    public class ExperienceWizardRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<ExperienceWizardRepository> _logger;

        public ExperienceWizardRepository(
            IDbConnectionFactory db,
            ILogger<ExperienceWizardRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        // ================================================================
        // AUTHORIZATION PATTERN: Defense-in-Depth
        // - C# layer checks ownership FIRST (fast, explicit)
        // - DB functions ALSO validate ownership (safety net)
        // - This prevents accidental bypass if service layer changes
        // ================================================================

        /// <summary>
        /// Verify clone ownership (C# authorization layer)
        /// </summary>
        public async Task<bool> CloneBelongsToUserAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            bool result = await conn.ExecuteScalarAsync<bool>(
                "SELECT clone.fn_clone_belongs_to_user(@tenant_id, @user_id, @clone_id)",
                new { tenant_id = tenantId, user_id = userId, clone_id = cloneId }
            );

            return result;
        }

        /// <summary>
        /// Verify experience ownership (C# authorization layer)
        /// </summary>
        public async Task<bool> ExperienceBelongsToUserAsync(
            Guid tenantId, Guid userId, Guid experienceId)
        {
            using var conn = _db.CreateConnection();

            bool result = await conn.ExecuteScalarAsync<bool>(
                "SELECT clone.fn_experience_belongs_to_user(@tenant_id, @user_id, @experience_id)",
                new { tenant_id = tenantId, user_id = userId, experience_id = experienceId }
            );

            return result;
        }

        /// <summary>
        /// Get user's active clones (for Experience creation)
        /// </summary>
        public async Task<IEnumerable<dynamic>> GetUserActiveClonesAsync(
            Guid tenantId, Guid userId)
        {
            using var conn = _db.CreateConnection();

            return await conn.QueryAsync(
                "SELECT * FROM clone.fn_get_user_active_clones(@tenant_id, @user_id)",
                new { tenant_id = tenantId, user_id = userId }
            );
        }

        /// <summary>
        /// Create experience draft
        /// DB function also validates clone ownership (defense-in-depth)
        /// </summary>
        public async Task<dynamic?> CreateExperienceDraftAsync(
            Guid tenantId, Guid userId, Guid cloneId, string name, string? description)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                @"SELECT * FROM clone.fn_create_experience_draft(
                    @tenant_id, @user_id, @clone_id, @name, @description
                )",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    clone_id = cloneId,
                    name,
                    description
                }
            );

            return result.FirstOrDefault();
        }

        /// <summary>
        /// Set experience rating
        /// DB function validates both ownership AND rating value
        /// </summary>
        public async Task<bool> SetExperienceRatingAsync(
            Guid tenantId, Guid userId, Guid experienceId, string rating)
        {
            using var conn = _db.CreateConnection();

            bool result = await conn.ExecuteScalarAsync<bool>(
                @"SELECT clone.fn_set_experience_rating(
                    @tenant_id, @user_id, @experience_id, @rating
                )",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    experience_id = experienceId,
                    rating
                }
            );

            return result;
        }

        /// <summary>
        /// Publish experience
        /// DB function validates ownership (defense-in-depth)
        /// </summary>
        public async Task<bool> PublishExperienceAsync(
            Guid tenantId, Guid userId, Guid experienceId, bool isPublic)
        {
            using var conn = _db.CreateConnection();

            bool result = await conn.ExecuteScalarAsync<bool>(
                @"SELECT clone.fn_publish_experience(
                    @tenant_id, @user_id, @experience_id, @is_public
                )",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    experience_id = experienceId,
                    is_public = isPublic
                }
            );

            return result;
        }

        /// <summary>
        /// Get experience details
        /// </summary>
        public async Task<dynamic?> GetExperienceAsync(
            Guid tenantId, Guid userId, Guid experienceId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                @"SELECT * FROM clone.fn_get_experience(
                    @tenant_id, @user_id, @experience_id
                )",
                new { tenant_id = tenantId, user_id = userId, experience_id = experienceId }
            );

            return result.FirstOrDefault();
        }

        /// <summary>
        /// Get all experiences for a clone
        /// </summary>
        public async Task<IEnumerable<dynamic>> GetCloneExperiencesAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            return await conn.QueryAsync(
                @"SELECT * FROM clone.fn_get_clone_experiences(
                    @tenant_id, @user_id, @clone_id
                )",
                new { tenant_id = tenantId, user_id = userId, clone_id = cloneId }
            );
        }

        /// <summary>
        /// Delete experience (soft delete)
        /// DB function validates ownership (defense-in-depth)
        /// </summary>
        public async Task<bool> DeleteExperienceAsync(
            Guid tenantId, Guid userId, Guid experienceId)
        {
            using var conn = _db.CreateConnection();

            bool result = await conn.ExecuteScalarAsync<bool>(
                @"SELECT clone.fn_delete_experience(
                    @tenant_id, @user_id, @experience_id
                )",
                new { tenant_id = tenantId, user_id = userId, experience_id = experienceId }
            );

            return result;
        }
    }
}
#endregion

// ==========================================================================
#region Service
// ==========================================================================
namespace KeiroGenesis.API.Services
{
    public class ExperienceWizardService
    {
        private readonly Repositories.ExperienceWizardRepository _repo;
        private readonly ILogger<ExperienceWizardService> _logger;

        public ExperienceWizardService(
            Repositories.ExperienceWizardRepository repo,
            ILogger<ExperienceWizardService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        /// <summary>
        /// Get user's available clones for Experience creation
        /// </summary>
        public async Task<DTOs.ExperienceWizard.ExperienceWizardResponse> GetAvailableClonesAsync(
            Guid tenantId, Guid userId)
        {
            try
            {
                var clones = await _repo.GetUserActiveClonesAsync(tenantId, userId);

                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = true,
                    Message = "Clones retrieved successfully",
                    Data = new { clones }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting available clones");
                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = false,
                    Message = "Failed to get clones"
                };
            }
        }

        /// <summary>
        /// Create experience draft (Step 1: Create Experience)
        /// Authorization: C# checks ownership first (defense-in-depth)
        /// </summary>
        public async Task<DTOs.ExperienceWizard.ExperienceWizardResponse> CreateExperienceDraftAsync(
            Guid tenantId, Guid userId, DTOs.ExperienceWizard.CreateExperienceRequest request)
        {
            try
            {
                // ============================================================
                // AUTHORIZATION: C# layer checks ownership FIRST
                // DB function will also validate (defense-in-depth)
                // ============================================================
                bool ownsClone = await _repo.CloneBelongsToUserAsync(
                    tenantId, userId, request.CloneId);

                if (!ownsClone)
                {
                    _logger.LogWarning(
                        "User {UserId} attempted to create experience for clone {CloneId} (unauthorized)",
                        userId, request.CloneId);

                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Clone not found or access denied",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                var experience = await _repo.CreateExperienceDraftAsync(
                    tenantId, userId, request.CloneId, request.Name, request.Description);

                if (experience == null)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Failed to create experience draft"
                    };
                }

                _logger.LogInformation(
                    "Experience draft created: {ExperienceId} for clone {CloneId}",
                    (Guid)experience.experience_id, (Guid)request.CloneId);

                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = true,
                    Message = "Experience draft created successfully",
                    ExperienceId = experience.experience_id,
                    CloneId = experience.clone_id,
                    Data = new
                    {
                        experience.experience_id,
                        experience.clone_id,
                        experience.name,
                        experience.description,
                        experience.rating,
                        experience.is_active,
                        experience.is_public
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating experience draft");
                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = false,
                    Message = "Failed to create experience: " + ex.Message
                };
            }
        }

        /// <summary>
        /// Set experience rating (Step 2: Configure Rating)
        /// Authorization: C# checks ownership first (defense-in-depth)
        /// </summary>
        public async Task<DTOs.ExperienceWizard.ExperienceWizardResponse> SetRatingAsync(
            Guid tenantId, Guid userId, Guid experienceId, DTOs.ExperienceWizard.SetRatingRequest request)
        {
            try
            {
                // ============================================================
                // AUTHORIZATION: C# layer checks ownership FIRST
                // ============================================================
                bool ownsExperience = await _repo.ExperienceBelongsToUserAsync(
                    tenantId, userId, experienceId);

                if (!ownsExperience)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Experience not found or access denied",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                // Convert enum to string for DB (DB will validate again)
                string ratingString = request.Rating switch
                {
                    DTOs.ExperienceWizard.ExperienceRating.G => "G",
                    DTOs.ExperienceWizard.ExperienceRating.PG => "PG",
                    DTOs.ExperienceWizard.ExperienceRating.PG13 => "PG-13",
                    DTOs.ExperienceWizard.ExperienceRating.MA => "MA",
                    _ => "PG" // Default fallback
                };

                bool updated = await _repo.SetExperienceRatingAsync(
                    tenantId, userId, experienceId, ratingString);

                if (!updated)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Failed to set rating"
                    };
                }

                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = true,
                    Message = "Rating set successfully",
                    ExperienceId = experienceId
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting rating for experience {ExperienceId}", experienceId);
                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = false,
                    Message = "Failed to set rating: " + ex.Message
                };
            }
        }

        /// <summary>
        /// Publish experience (Step 3: Publish)
        /// Authorization: C# checks ownership first (defense-in-depth)
        /// </summary>
        public async Task<DTOs.ExperienceWizard.ExperienceWizardResponse> PublishExperienceAsync(
            Guid tenantId, Guid userId, Guid experienceId, DTOs.ExperienceWizard.PublishRequest request)
        {
            try
            {
                // ============================================================
                // AUTHORIZATION: C# layer checks ownership FIRST
                // ============================================================
                bool ownsExperience = await _repo.ExperienceBelongsToUserAsync(
                    tenantId, userId, experienceId);

                if (!ownsExperience)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Experience not found or access denied",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                bool published = await _repo.PublishExperienceAsync(
                    tenantId, userId, experienceId, request.IsPublic);

                if (!published)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Failed to publish experience"
                    };
                }

                _logger.LogInformation("Experience {ExperienceId} published successfully", experienceId);

                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = true,
                    Message = "🎉 Experience published successfully!",
                    ExperienceId = experienceId
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error publishing experience {ExperienceId}", experienceId);
                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = false,
                    Message = "Failed to publish experience: " + ex.Message
                };
            }
        }

        /// <summary>
        /// Get experience details
        /// Authorization: C# checks ownership first
        /// </summary>
        public async Task<DTOs.ExperienceWizard.ExperienceWizardResponse> GetExperienceAsync(
            Guid tenantId, Guid userId, Guid experienceId)
        {
            try
            {
                bool ownsExperience = await _repo.ExperienceBelongsToUserAsync(
                    tenantId, userId, experienceId);

                if (!ownsExperience)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Experience not found or access denied",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                var experience = await _repo.GetExperienceAsync(tenantId, userId, experienceId);

                if (experience == null)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Experience not found"
                    };
                }

                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = true,
                    Message = "Experience retrieved successfully",
                    ExperienceId = experience.experience_id,
                    CloneId = experience.clone_id,
                    Data = experience
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting experience {ExperienceId}", experienceId);
                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = false,
                    Message = "Failed to get experience"
                };
            }
        }

        /// <summary>
        /// Get all experiences for a clone
        /// </summary>
        public async Task<DTOs.ExperienceWizard.ExperienceWizardResponse> GetCloneExperiencesAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            try
            {
                bool ownsClone = await _repo.CloneBelongsToUserAsync(tenantId, userId, cloneId);

                if (!ownsClone)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Clone not found or access denied",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                var experiences = await _repo.GetCloneExperiencesAsync(tenantId, userId, cloneId);

                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = true,
                    Message = "Experiences retrieved successfully",
                    CloneId = cloneId,
                    Data = new { experiences }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting experiences for clone {CloneId}", cloneId);
                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = false,
                    Message = "Failed to get experiences"
                };
            }
        }

        /// <summary>
        /// Delete experience
        /// Authorization: C# checks ownership first
        /// </summary>
        public async Task<DTOs.ExperienceWizard.ExperienceWizardResponse> DeleteExperienceAsync(
            Guid tenantId, Guid userId, Guid experienceId)
        {
            try
            {
                bool ownsExperience = await _repo.ExperienceBelongsToUserAsync(
                    tenantId, userId, experienceId);

                if (!ownsExperience)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Experience not found or access denied",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                bool deleted = await _repo.DeleteExperienceAsync(tenantId, userId, experienceId);

                if (!deleted)
                {
                    return new DTOs.ExperienceWizard.ExperienceWizardResponse
                    {
                        Success = false,
                        Message = "Failed to delete experience"
                    };
                }

                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = true,
                    Message = "Experience deleted successfully",
                    ExperienceId = experienceId
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting experience {ExperienceId}", experienceId);
                return new DTOs.ExperienceWizard.ExperienceWizardResponse
                {
                    Success = false,
                    Message = "Failed to delete experience"
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
    /// Experience Wizard - Create Bounded Interaction Contexts
    /// 
    /// Flow:
    /// 1. Get Available Clones → GET /clones
    /// 2. Create Experience → POST /
    /// 3. Set Rating → PUT /{experienceId}/rating
    /// 4. Publish → POST /{experienceId}/publish
    /// 
    /// Unit of Rating: Experience (not Clone)
    /// Authorization: Defense-in-depth (C# + DB)
    /// </summary>
    [Route("api/v1/experiencewizard")]
    [ApiController]
    [Authorize]
    public class ExperienceWizardController : ControllerBase
    {
        private readonly Services.ExperienceWizardService _service;
        private readonly ILogger<ExperienceWizardController> _logger;

        public ExperienceWizardController(
            Services.ExperienceWizardService service,
            ILogger<ExperienceWizardController> logger)
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
        /// Step 0: Get available clones (for Experience creation)
        /// </summary>
        [HttpGet("clones")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetAvailableClones()
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation("Getting available clones for user {UserId}", userId);

            var result = await _service.GetAvailableClonesAsync(tenantId, userId);
            return Ok(result);
        }

        /// <summary>
        /// Step 1: Create Experience (Select Clone + Name + Description)
        /// </summary>
        [HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> CreateExperience(
            [FromBody] DTOs.ExperienceWizard.CreateExperienceRequest request)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation(
                "Creating experience for clone {CloneId}",
                request.CloneId);

            var result = await _service.CreateExperienceDraftAsync(tenantId, userId, request);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Step 2: Set Rating (Configure age-appropriateness)
        /// </summary>
        [HttpPut("{experienceId}/rating")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> SetRating(
            Guid experienceId,
            [FromBody] DTOs.ExperienceWizard.SetRatingRequest request)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation(
                "Setting rating for experience {ExperienceId} to {Rating}",
                experienceId, request.Rating);

            var result = await _service.SetRatingAsync(tenantId, userId, experienceId, request);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Step 3: Publish Experience (Make discoverable)
        /// </summary>
        [HttpPost("{experienceId}/publish")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> PublishExperience(
            Guid experienceId,
            [FromBody] DTOs.ExperienceWizard.PublishRequest request)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation("Publishing experience {ExperienceId}", experienceId);

            var result = await _service.PublishExperienceAsync(tenantId, userId, experienceId, request);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Get experience details
        /// </summary>
        [HttpGet("{experienceId}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(403)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetExperience(Guid experienceId)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            var result = await _service.GetExperienceAsync(tenantId, userId, experienceId);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return NotFound(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Get all experiences for a clone
        /// </summary>
        [HttpGet("clone/{cloneId}/experiences")]
        [ProducesResponseType(200)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> GetCloneExperiences(Guid cloneId)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            var result = await _service.GetCloneExperiencesAsync(tenantId, userId, cloneId);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Delete experience
        /// </summary>
        [HttpDelete("{experienceId}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(403)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> DeleteExperience(Guid experienceId)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation("Deleting experience {ExperienceId}", experienceId);

            var result = await _service.DeleteExperienceAsync(tenantId, userId, experienceId);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return NotFound(result);
            }

            return Ok(result);
        }
    }
}
#endregion