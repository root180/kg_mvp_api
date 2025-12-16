// ==========================================================================
// CLONE WIZARD MODULE — 6-Step Clone Creation
// DEFENSE IN DEPTH VERSION - Ownership verified at BOTH layers
// Single file: Repository + Service + Controller
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
#region Repository
// ==========================================================================
namespace KeiroGenesis.API.Repositories
{
    public class CloneWizardRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<CloneWizardRepository> _logger;

        public CloneWizardRepository(IDbConnectionFactory db, ILogger<CloneWizardRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        // 🔐 OWNERSHIP VALIDATION (C# GUARD - First Layer)
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

        // Step 1: Create draft clone
        public async Task<dynamic?> CreateCloneDraftAsync(
            Guid tenantId, Guid userId, string displayName,
            string tagline, string bio, string visibility)
        {
            using var conn = _db.CreateConnection();

            IEnumerable<dynamic> result = await conn.QueryAsync(
                "SELECT * FROM clone.fn_create_clone_draft(@tenant_id, @user_id, @display_name, @tagline, @bio, @visibility)",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    display_name = displayName,
                    tagline = tagline,
                    bio = bio,
                    visibility = visibility
                }
            );

            return result.FirstOrDefault();
        }

        // Step 2: Update avatar (passes user_id - DB verifies again)
        public async Task<bool> UpdateCloneAvatarAsync(
            Guid tenantId, Guid userId, Guid cloneId, string avatarUrl)
        {
            using var conn = _db.CreateConnection();

            bool result = await conn.ExecuteScalarAsync<bool>(
                "SELECT clone.fn_update_clone_avatar(@tenant_id, @user_id, @clone_id, @avatar_url)",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    clone_id = cloneId,
                    avatar_url = avatarUrl
                }
            );

            return result;
        }

        // Step 3: Save personality (passes user_id - DB verifies again)
        public async Task<bool> SaveClonePersonalityAsync(
            Guid tenantId, Guid userId, Guid cloneId, string tone, string verbosity,
            string humor, string values, bool storytelling)
        {
            using var conn = _db.CreateConnection();

            bool result = await conn.ExecuteScalarAsync<bool>(
                @"SELECT clone.fn_save_clone_personality(
                    @tenant_id, @user_id, @clone_id, @tone, @verbosity, @humor, @values, @storytelling
                )",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    clone_id = cloneId,
                    tone = tone,
                    verbosity = verbosity,
                    humor = humor,
                    values = values,
                    storytelling = storytelling
                }
            );

            return result;
        }

        // Step 4: Add memory seeds (passes user_id - DB verifies again)
        public async Task<int> AddMemorySeedsAsync(
            Guid tenantId, Guid userId, Guid cloneId, string[] memories)
        {
            using var conn = _db.CreateConnection();

            int count = await conn.ExecuteScalarAsync<int>(
                "SELECT clone.fn_add_memory_seeds(@tenant_id, @user_id, @clone_id, @memories)",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    clone_id = cloneId,
                    memories = memories
                }
            );

            return count;
        }

        // Step 5: Upload knowledge documents (passes user_id - DB verifies again)
        public async Task<int> UploadKnowledgeDocumentsAsync(
            Guid tenantId, Guid userId, Guid cloneId, string documentsJson)
        {
            using var conn = _db.CreateConnection();

            int count = await conn.ExecuteScalarAsync<int>(
                "SELECT clone.fn_upload_knowledge_documents(@tenant_id, @user_id, @clone_id, @documents::jsonb)",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    clone_id = cloneId,
                    documents = documentsJson
                }
            );

            return count;
        }

        // Step 6: Activate clone (passes user_id - DB verifies again)
        public async Task<dynamic?> ActivateCloneAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            IEnumerable<dynamic> result = await conn.QueryAsync(
                "SELECT * FROM clone.fn_activate_clone(@tenant_id, @user_id, @clone_id)",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    clone_id = cloneId
                }
            );

            return result.FirstOrDefault();
        }

        // Helper: Get wizard status (passes user_id - DB verifies again)
        public async Task<dynamic?> GetWizardStatusAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();

            IEnumerable<dynamic> result = await conn.QueryAsync(
                "SELECT * FROM clone.fn_get_clone_wizard_status(@tenant_id, @user_id, @clone_id)",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    clone_id = cloneId
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
    public class CloneWizardService
    {
        private readonly Repositories.CloneWizardRepository _repo;
        private readonly ILogger<CloneWizardService> _logger;

        public CloneWizardService(
            Repositories.CloneWizardRepository repo,
            ILogger<CloneWizardService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        // Step 1: Create draft clone (no ownership check needed - creating new)
        public async Task<WizardResponse> CreateCloneDraftAsync(
            Guid tenantId, Guid userId, Step1Request request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.DisplayName))
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = "Display name is required",
                        ErrorCode = "VALIDATION_ERROR"
                    };
                }

                dynamic? result = await _repo.CreateCloneDraftAsync(
                    tenantId, userId,
                    request.DisplayName,
                    request.Tagline ?? "",
                    request.Bio ?? "",
                    request.Visibility ?? "private"
                );

                if (result == null)
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = "Failed to create clone",
                        ErrorCode = "CREATION_FAILED"
                    };
                }

                if (result.status == "error")
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = result.error_message,
                        ErrorCode = "BUSINESS_RULE_VIOLATION"
                    };
                }

                // FIXED: Extract values before logging
                Guid cloneId = result.clone_id;
                string cloneSlug = result.clone_slug;

                _logger.LogInformation("Clone draft created: {CloneId} for user {UserId}",
                    cloneId,
                    userId);

                return new WizardResponse
                {
                    Success = true,
                    Message = "Clone draft created successfully",
                    Data = new
                    {
                        cloneId = cloneId,
                        cloneSlug = cloneSlug,
                        status = "draft"
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating clone draft for user {UserId}", userId);
                return new WizardResponse
                {
                    Success = false,
                    Message = $"Failed to create clone: {ex.Message}",
                    ErrorCode = "INTERNAL_ERROR"
                };
            }
        }

        // Step 2: Update avatar
        public async Task<WizardResponse> UpdateAvatarAsync(
            Guid tenantId, Guid userId, Guid cloneId, Step2Request request)
        {
            try
            {
                // 🔐 LAYER 1: C# ownership guard
                bool ownsClone = await _repo.CloneBelongsToUserAsync(tenantId, userId, cloneId);
                if (!ownsClone)
                {
                    _logger.LogWarning("User {UserId} attempted to update avatar for clone {CloneId} (unauthorized)",
                        userId, cloneId);

                    return new WizardResponse
                    {
                        Success = false,
                        Message = "You do not own this clone",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                // 🔐 LAYER 2: DB function verifies AGAIN (defense in depth)
                bool success = await _repo.UpdateCloneAvatarAsync(
                    tenantId, userId, cloneId, request.AvatarUrl);

                if (!success)
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = "Failed to update avatar (DB rejected)",
                        ErrorCode = "UPDATE_FAILED"
                    };
                }

                _logger.LogInformation("Avatar updated for clone {CloneId}", cloneId);

                return new WizardResponse
                {
                    Success = true,
                    Message = "Avatar updated"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating avatar for clone {CloneId}", cloneId);
                return new WizardResponse
                {
                    Success = false,
                    Message = $"Failed to update avatar: {ex.Message}",
                    ErrorCode = "INTERNAL_ERROR"
                };
            }
        }

        // Step 3: Save personality
        public async Task<WizardResponse> SavePersonalityAsync(
            Guid tenantId, Guid userId, Guid cloneId, Step3Request request)
        {
            try
            {
                // 🔐 LAYER 1: C# ownership guard
                bool ownsClone = await _repo.CloneBelongsToUserAsync(tenantId, userId, cloneId);
                if (!ownsClone)
                {
                    _logger.LogWarning("User {UserId} attempted to update personality for clone {CloneId} (unauthorized)",
                        userId, cloneId);

                    return new WizardResponse
                    {
                        Success = false,
                        Message = "You do not own this clone",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                // 🔐 LAYER 2: DB function verifies AGAIN
                bool success = await _repo.SaveClonePersonalityAsync(
                    tenantId, userId, cloneId,
                    request.Tone ?? "balanced",
                    request.Verbosity ?? "moderate",
                    request.Humor ?? "subtle",
                    string.Join(",", request.Values ?? Array.Empty<string>()),
                    request.Storytelling
                );

                if (!success)
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = "Failed to save personality (DB rejected)",
                        ErrorCode = "UPDATE_FAILED"
                    };
                }

                _logger.LogInformation("Personality saved for clone {CloneId}", cloneId);

                return new WizardResponse
                {
                    Success = true,
                    Message = "Personality saved"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving personality for clone {CloneId}", cloneId);
                return new WizardResponse
                {
                    Success = false,
                    Message = $"Failed to save personality: {ex.Message}",
                    ErrorCode = "INTERNAL_ERROR"
                };
            }
        }

        // Step 4: Add memories
        public async Task<WizardResponse> AddMemoriesAsync(
            Guid tenantId, Guid userId, Guid cloneId, Step4Request request)
        {
            try
            {
                // 🔐 LAYER 1: C# ownership guard
                bool ownsClone = await _repo.CloneBelongsToUserAsync(tenantId, userId, cloneId);
                if (!ownsClone)
                {
                    _logger.LogWarning("User {UserId} attempted to add memories for clone {CloneId} (unauthorized)",
                        userId, cloneId);

                    return new WizardResponse
                    {
                        Success = false,
                        Message = "You do not own this clone",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                if (request.Memories == null || request.Memories.Length == 0)
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = "At least one memory is required",
                        ErrorCode = "VALIDATION_ERROR"
                    };
                }

                // 🔐 LAYER 2: DB function verifies AGAIN
                int count = await _repo.AddMemorySeedsAsync(
                    tenantId, userId, cloneId, request.Memories);

                _logger.LogInformation("Added {Count} memories for clone {CloneId}", count, cloneId);

                return new WizardResponse
                {
                    Success = true,
                    Message = $"Added {count} memories",
                    Data = new { count }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding memories for clone {CloneId}", cloneId);
                return new WizardResponse
                {
                    Success = false,
                    Message = $"Failed to add memories: {ex.Message}",
                    ErrorCode = "INTERNAL_ERROR"
                };
            }
        }

        // Step 5: Upload knowledge documents
        public async Task<WizardResponse> UploadKnowledgeAsync(
            Guid tenantId, Guid userId, Guid cloneId, Step5Request request)
        {
            try
            {
                // 🔐 LAYER 1: C# ownership guard
                bool ownsClone = await _repo.CloneBelongsToUserAsync(tenantId, userId, cloneId);
                if (!ownsClone)
                {
                    _logger.LogWarning("User {UserId} attempted to upload knowledge for clone {CloneId} (unauthorized)",
                        userId, cloneId);

                    return new WizardResponse
                    {
                        Success = false,
                        Message = "You do not own this clone",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                if (request.Documents == null || request.Documents.Length == 0)
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = "At least one document is required",
                        ErrorCode = "VALIDATION_ERROR"
                    };
                }

                // Serialize documents to JSON
                string documentsJson = System.Text.Json.JsonSerializer.Serialize(request.Documents);

                // 🔐 LAYER 2: DB function verifies AGAIN
                int count = await _repo.UploadKnowledgeDocumentsAsync(
                    tenantId, userId, cloneId, documentsJson);

                _logger.LogInformation("Uploaded {Count} documents for clone {CloneId}", count, cloneId);

                return new WizardResponse
                {
                    Success = true,
                    Message = $"Uploaded {count} documents",
                    Data = new { count }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading knowledge for clone {CloneId}", cloneId);
                return new WizardResponse
                {
                    Success = false,
                    Message = $"Failed to upload knowledge: {ex.Message}",
                    ErrorCode = "INTERNAL_ERROR"
                };
            }
        }

        // Step 6: Activate clone
        public async Task<WizardResponse> ActivateCloneAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            try
            {
                // 🔐 LAYER 1: C# ownership guard
                bool ownsClone = await _repo.CloneBelongsToUserAsync(tenantId, userId, cloneId);
                if (!ownsClone)
                {
                    _logger.LogWarning("User {UserId} attempted to activate clone {CloneId} (unauthorized)",
                        userId, cloneId);

                    return new WizardResponse
                    {
                        Success = false,
                        Message = "You do not own this clone",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                // 🔐 LAYER 2: DB function verifies AGAIN
                dynamic? result = await _repo.ActivateCloneAsync(tenantId, userId, cloneId);

                if (result == null)
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = "Failed to activate clone",
                        ErrorCode = "ACTIVATION_FAILED"
                    };
                }

                if (result.status == "error")
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = result.error_message,
                        ErrorCode = "BUSINESS_RULE_VIOLATION"
                    };
                }

                _logger.LogInformation("Clone {CloneId} activated", cloneId);

                return new WizardResponse
                {
                    Success = true,
                    Message = "Clone activated successfully!",
                    Data = new
                    {
                        cloneId = result.clone_id,
                        status = result.status
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error activating clone {CloneId}", cloneId);
                return new WizardResponse
                {
                    Success = false,
                    Message = $"Failed to activate clone: {ex.Message}",
                    ErrorCode = "INTERNAL_ERROR"
                };
            }
        }

        // Helper: Get wizard status
        public async Task<WizardResponse> GetWizardStatusAsync(
            Guid tenantId, Guid userId, Guid cloneId)
        {
            try
            {
                // 🔐 LAYER 1: C# ownership guard
                bool ownsClone = await _repo.CloneBelongsToUserAsync(tenantId, userId, cloneId);
                if (!ownsClone)
                {
                    _logger.LogWarning("User {UserId} attempted to get status for clone {CloneId} (unauthorized)",
                        userId, cloneId);

                    return new WizardResponse
                    {
                        Success = false,
                        Message = "You do not own this clone",
                        ErrorCode = "UNAUTHORIZED"
                    };
                }

                // 🔐 LAYER 2: DB function verifies AGAIN
                dynamic? status = await _repo.GetWizardStatusAsync(tenantId, userId, cloneId);

                if (status == null)
                {
                    return new WizardResponse
                    {
                        Success = false,
                        Message = "Clone not found",
                        ErrorCode = "NOT_FOUND"
                    };
                }

                return new WizardResponse
                {
                    Success = true,
                    Message = "Status retrieved",
                    Data = new
                    {
                        cloneId = status.clone_id,
                        displayName = status.display_name,
                        status = status.status,
                        progress = new
                        {
                            step1_identity = true,
                            step2_avatar = status.has_avatar,
                            step3_personality = status.has_personality,
                            step4_memories = status.memory_count > 0,
                            step5_knowledge = status.document_count > 0,
                            canActivate = status.can_activate
                        },
                        counts = new
                        {
                            memories = status.memory_count,
                            documents = status.document_count
                        }
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting wizard status for clone {CloneId}", cloneId);
                return new WizardResponse
                {
                    Success = false,
                    Message = $"Failed to get status: {ex.Message}",
                    ErrorCode = "INTERNAL_ERROR"
                };
            }
        }

     
       
    }

    // Request/Response Models
    public class Step1Request
    {
        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; } = string.Empty;

        [JsonPropertyName("tagline")]
        public string? Tagline { get; set; }

        [JsonPropertyName("bio")]
        public string? Bio { get; set; }

        [JsonPropertyName("visibility")]
        public string? Visibility { get; set; }
    }

    public class Step2Request
    {
        [JsonPropertyName("avatarUrl")]
        public string AvatarUrl { get; set; } = string.Empty;
    }

    public class Step3Request
    {
        [JsonPropertyName("tone")]
        public string Tone { get; set; } = string.Empty;

        [JsonPropertyName("verbosity")]
        public string? Verbosity { get; set; }

        [JsonPropertyName("humor")]
        public string? Humor { get; set; }

        [JsonPropertyName("values")]
        public string[]? Values { get; set; }

        [JsonPropertyName("storytelling")]
        public bool Storytelling { get; set; }
    }

    public class Step4Request
    {
        [JsonPropertyName("memories")]
        public string[] Memories { get; set; } = Array.Empty<string>();
    }

    public class Step5Request
    {
        [JsonPropertyName("documents")]
        public DocumentInfo[] Documents { get; set; } = Array.Empty<DocumentInfo>();
    }

    public class DocumentInfo
    {
        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;

        [JsonPropertyName("filename")]
        public string Filename { get; set; } = string.Empty;

        [JsonPropertyName("fileSize")]
        public long FileSize { get; set; }

        [JsonPropertyName("mimeType")]
        public string MimeType { get; set; } = string.Empty;
    }

    public class WizardResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; } = string.Empty;

        [JsonPropertyName("errorCode")]
        public string? ErrorCode { get; set; }

        [JsonPropertyName("data")]
        public object? Data { get; set; }
    }
}
#endregion

// ==========================================================================
#region Controller
// ==========================================================================
namespace KeiroGenesis.API.Controllers.V1
{
    [Route("api/v1/clonewizard")]
    [Authorize]
    public class CloneWizardController : ControllerBase
    {
        private readonly Services.CloneWizardService _service;
        private readonly ILogger<CloneWizardController> _logger;

        public CloneWizardController(
            Services.CloneWizardService service,
            ILogger<CloneWizardController> logger)
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
        /// Create draft clone (Step 1)
        /// </summary>
        [HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> Create([FromBody] Services.Step1Request request)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation("Creating clone for user {UserId}", userId);

            Services.WizardResponse result = await _service.CreateCloneDraftAsync(tenantId, userId, request);

            if (!result.Success)
                return BadRequest(result);

            return Ok(result);
        }

        /// <summary>
        /// Update avatar (Step 2)
        /// </summary>
        [HttpPut("{cloneId}/avatar")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> UpdateAvatar(Guid cloneId, [FromBody] Services.Step2Request request)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation("Updating avatar for clone {CloneId}", cloneId);

            Services.WizardResponse result = await _service.UpdateAvatarAsync(tenantId, userId, cloneId, request);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Configure personality (Step 3)
        /// </summary>
        [HttpPut("{cloneId}/personality")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> SavePersonality(Guid cloneId, [FromBody] Services.Step3Request request)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation("Saving personality for clone {CloneId}", cloneId);

            Services.WizardResponse result = await _service.SavePersonalityAsync(tenantId, userId, cloneId, request);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Add memory seeds (Step 4)
        /// </summary>
        [HttpPost("{cloneId}/memories")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> AddMemories(Guid cloneId, [FromBody] Services.Step4Request request)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation("Adding memories for clone {CloneId}", cloneId);

            Services.WizardResponse result = await _service.AddMemoriesAsync(tenantId, userId, cloneId, request);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Upload knowledge documents (Step 5 - metadata only)
        /// </summary>
        [HttpPost("{cloneId}/knowledge")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> UploadKnowledge(Guid cloneId, [FromBody] Services.Step5Request request)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation("Uploading knowledge for clone {CloneId}", cloneId);

            Services.WizardResponse result = await _service.UploadKnowledgeAsync(tenantId, userId, cloneId, request);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Activate clone (Step 6)
        /// </summary>
        [HttpPost("{cloneId}/activate")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> Activate(Guid cloneId)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            _logger.LogInformation("Activating clone {CloneId}", cloneId);

            Services.WizardResponse result = await _service.ActivateCloneAsync(tenantId, userId, cloneId);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Get wizard status (resume wizard)
        /// </summary>
        [HttpGet("{cloneId}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(403)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetStatus(Guid cloneId)
        {
            Guid tenantId = GetTenantId();
            Guid userId = GetCurrentUserId();

            Services.WizardResponse result = await _service.GetWizardStatusAsync(tenantId, userId, cloneId);

            if (!result.Success)
            {
                if (result.ErrorCode == "UNAUTHORIZED")
                    return StatusCode(403, result);
                return NotFound(result);
            }

            return Ok(result);
        }

        //Helper: Get tenant ID from claims


    }
}
#endregion