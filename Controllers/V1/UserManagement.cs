// ==========================================================================
// USER MANAGEMENT MODULE - Deletion + Role Management
// COMPLETE FIXED VERSION with DapperHelper and enhanced logging
// Single file: Repository + Service + Controller
// ==========================================================================

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Core.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

// ==========================================================================
#region Repository
// ==========================================================================
namespace KeiroGenesis.API.Repositories
{
    public class UserManagementRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<UserManagementRepository> _logger;

        public UserManagementRepository(IDbConnectionFactory db, ILogger<UserManagementRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        // Delete user by ID
        public async Task<dynamic?> DeleteUserByIdAsync(Guid userId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM core.fn_delete_user_by_id(@user_id)",
                new { user_id = userId }
            );
        }

        // Delete user by email
        public async Task<dynamic?> DeleteUserByEmailAsync(string email)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM core.fn_delete_user_by_email(@email)",
                new { email }
            );
        }

        // Delete user by username
        public async Task<dynamic?> DeleteUserByUsernameAsync(string username)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM core.fn_delete_user_by_username(@username)",
                new { username }
            );
        }

        // Batch delete by email pattern
        public async Task<dynamic?> DeleteUsersByEmailPatternAsync(string emailPattern)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM core.fn_delete_users_by_email_pattern(@email_pattern)",
                new { email_pattern = emailPattern }
            );
        }

        // Delete all test users
        public async Task<dynamic?> DeleteAllTestUsersAsync()
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM core.fn_delete_all_test_users()"
            );
        }

        // Promote user to admin
        public async Task<dynamic?> PromoteUserToAdminAsync(Guid ownerUserId, Guid ownerTenantId, string targetUserEmail)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM security.fn_promote_user_to_admin(@owner_user_id, @owner_tenant_id, @target_user_email)",
                new { owner_user_id = ownerUserId, owner_tenant_id = ownerTenantId, target_user_email = targetUserEmail }
            );
        }

        // Demote admin to member
        public async Task<dynamic?> DemoteAdminToMemberAsync(Guid ownerUserId, Guid ownerTenantId, string targetUserEmail)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM security.fn_demote_admin_to_member(@owner_user_id, @owner_tenant_id, @target_user_email)",
                new { owner_user_id = ownerUserId, owner_tenant_id = ownerTenantId, target_user_email = targetUserEmail }
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
    public class UserManagementService
    {
        private readonly Repositories.UserManagementRepository _repo;
        private readonly ILogger<UserManagementService> _logger;

        public UserManagementService(
            Repositories.UserManagementRepository repo,
            ILogger<UserManagementService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<DeleteUserResponse> DeleteUserByIdAsync(Guid userId)
        {
            try
            {
                int result = await _repo.DeleteUserByIdAsync(userId);

                if (result == null)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                var success = DapperHelper.GetValue<bool>(result, "deleted");
                var message = DapperHelper.GetValue<string>(result, "message");

                _logger.LogInformation("User deleted by ID: {UserId} - Success: {Success}", userId, success);

                return new DeleteUserResponse
                {
                    Success = success,
                    Message = message
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user by ID: {UserId}", userId);
                return new DeleteUserResponse
                {
                    Success = false,
                    Message = $"Deletion failed: {ex.Message}"
                };
            }
        }

        public async Task<DeleteUserResponse> DeleteUserByEmailAsync(string email)
        {
            try
            {
                var result = await _repo.DeleteUserByEmailAsync(email);

                if (result == null)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                bool success = DapperHelper.GetValue<bool>(result, "deleted");
                string message = DapperHelper.GetValue<string>(result, "message");

                _logger.LogInformation("User deleted by email: {Email} - Success: {Success}", email, success);

                return new DeleteUserResponse
                {
                    Success = success,
                    Message = message
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user by email: {Email}", email);
                return new DeleteUserResponse
                {
                    Success = false,
                    Message = $"Deletion failed: {ex.Message}"
                };
            }
        }

        public async Task<DeleteUserResponse> DeleteUserByUsernameAsync(string username)
        {
            try
            {
                var result = await _repo.DeleteUserByUsernameAsync(username);

                if (result == null)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                bool success = DapperHelper.GetValue<bool>(result, "deleted");
                string message = DapperHelper.GetValue<string>(result, "message");

                _logger.LogInformation("User deleted by username: {Username} - Success: {Success}", username, success);

                return new DeleteUserResponse
                {
                    Success = success,
                    Message = message
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user by username: {Username}", username);
                return new DeleteUserResponse
                {
                    Success = false,
                    Message = $"Deletion failed: {ex.Message}"
                };
            }
        }

        public async Task<BatchDeleteResponse> DeleteUsersByEmailPatternAsync(string emailPattern)
        {
            try
            {
                int result = await _repo.DeleteUsersByEmailPatternAsync(emailPattern);

                if (result == null)
                {
                    return new BatchDeleteResponse
                    {
                        Success = false,
                        Message = "No users found",
                        DeletedCount = 0
                    };
                }

                var deletedCount = DapperHelper.GetValue<int>(result, "deleted_count");
                var message = DapperHelper.GetValue<string>(result, "message");

                _logger.LogInformation("Batch delete by pattern: {Pattern}, Count: {Count}",
                    emailPattern, deletedCount);

                return new BatchDeleteResponse
                {
                    Success = deletedCount > 0,
                    Message = message,
                    DeletedCount = deletedCount
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error batch deleting users by pattern: {Pattern}", emailPattern);
                return new BatchDeleteResponse
                {
                    Success = false,
                    Message = $"Batch deletion failed: {ex.Message}",
                    DeletedCount = 0
                };
            }
        }

        public async Task<BatchDeleteResponse> DeleteAllTestUsersAsync()
        {
            try
            {
                var result = await _repo.DeleteAllTestUsersAsync();

                if (result == null)
                {
                    return new BatchDeleteResponse
                    {
                        Success = false,
                        Message = "No test users found",
                        DeletedCount = 0
                    };
                }

                int deletedCount = DapperHelper.GetValue<int>(result, "deleted_count");
                var message = DapperHelper.GetValue<string>(result, "message");

                _logger.LogWarning("ALL TEST USERS DELETED - Count: {Count}", deletedCount);

                return new BatchDeleteResponse
                {
                    Success = true,
                    Message = message,
                    DeletedCount = deletedCount
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting all test users");
                return new BatchDeleteResponse
                {
                    Success = false,
                    Message = $"Batch deletion failed: {ex.Message}",
                    DeletedCount = 0
                };
            }
        }

        public async Task<RoleChangeResponse> PromoteUserToAdminAsync(Guid ownerUserId, Guid ownerTenantId, string targetUserEmail)
        {
            try
            {
                _logger.LogInformation("🔵 PROMOTE - Owner: {OwnerId}, Tenant: {TenantId}, Target: {Email}",
                    ownerUserId, ownerTenantId, targetUserEmail);

                var result = await _repo.PromoteUserToAdminAsync(ownerUserId, ownerTenantId, targetUserEmail);

                if (result == null)
                {
                    _logger.LogError("❌ PROMOTE - Database returned null");
                    return new RoleChangeResponse { Success = false, Message = "Operation failed - database returned null" };
                }

                bool success = DapperHelper.GetValue<bool>(result, "success");
                string message = DapperHelper.GetValue<string>(result, "message");

                if (success)
                {
                    _logger.LogInformation("✅ PROMOTION SUCCESS - {Email} promoted to admin by owner {OwnerId}",
                        targetUserEmail, ownerUserId);
                }
                else
                {
                    _logger.LogWarning("❌ PROMOTION FAILED - {Email}: {Message}", targetUserEmail, message);
                }

                return new RoleChangeResponse
                {
                    Success = success,
                    Message = message
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ PROMOTE ERROR - Owner: {OwnerId}, Target: {Email}, Error: {Message}",
                    ownerUserId, targetUserEmail, ex.Message);
                return new RoleChangeResponse
                {
                    Success = false,
                    Message = $"Promotion failed: {ex.Message}"
                };
            }
        }

        public async Task<RoleChangeResponse> DemoteAdminToMemberAsync(Guid ownerUserId, Guid ownerTenantId, string targetUserEmail)
        {
            try
            {
                _logger.LogInformation("🔵 DEMOTE - Owner: {OwnerId}, Tenant: {TenantId}, Target: {Email}",
                    ownerUserId, ownerTenantId, targetUserEmail);

                var result = await _repo.DemoteAdminToMemberAsync(ownerUserId, ownerTenantId, targetUserEmail);

                if (result == null)
                {
                    _logger.LogError("❌ DEMOTE - Database returned null");
                    return new RoleChangeResponse { Success = false, Message = "Operation failed - database returned null" };
                }

               bool success = DapperHelper.GetValue<bool>(result, "success");
               string message = DapperHelper.GetValue<string>(result, "message");

                if (success)
                {
                    _logger.LogInformation("✅ DEMOTION SUCCESS - {Email} demoted to member by owner {OwnerId}",
                        targetUserEmail, ownerUserId);
                }
                else
                {
                    _logger.LogWarning("❌ DEMOTION FAILED - {Email}: {Message}", targetUserEmail, message);
                }

                return new RoleChangeResponse
                {
                    Success = success,
                    Message = message
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ DEMOTE ERROR - Owner: {OwnerId}, Target: {Email}, Error: {Message}",
                    ownerUserId, targetUserEmail, ex.Message);
                return new RoleChangeResponse
                {
                    Success = false,
                    Message = $"Demotion failed: {ex.Message}"
                };
            }
        }
    }

    // Response Models
    public class DeleteUserResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class BatchDeleteResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public int DeletedCount { get; set; }
    }

    public class RoleChangeResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public Guid? UserId { get; set; }
        public string? NewRole { get; set; }
    }
}
#endregion

// ==========================================================================
#region Controller
// ==========================================================================
namespace KeiroGenesis.API.Controllers.V1
{
    /// <summary>
    /// User management endpoints for deletion, cleanup, and role management
    /// WARNING: These are destructive operations - use with caution!
    /// </summary>
    [ApiController]
    [Route("api/v1/usermanagement")]
    [Authorize]
    public class UserManagementController : ControllerBase
    {
        private readonly Services.UserManagementService _service;
        private readonly ILogger<UserManagementController> _logger;
        private readonly IHostEnvironment _environment;

        public UserManagementController(
            Services.UserManagementService service,
            ILogger<UserManagementController> logger,
            IHostEnvironment environment)
        {
            _service = service;
            _logger = logger;
            _environment = environment;
        }

        // Get tenant ID from JWT claims
        private Guid GetTenantId()
        {
            var claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var tenantId))
            {
                _logger.LogError("❌ tenant_id claim missing or invalid");
                throw new UnauthorizedAccessException("Invalid tenant claim");
            }
            return tenantId;
        }

        // Get current user ID from JWT claims
        private Guid GetCurrentUserId()
        {
            var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var userId))
            {
                _logger.LogError("❌ user_id claim missing or invalid");
                throw new UnauthorizedAccessException("Invalid user claim");
            }
            return userId;
        }

        /// <summary>
        /// Delete user by ID
        /// </summary>
        [HttpDelete("user/{userId}")]
        [Authorize(Roles = "owner,admin")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> DeleteUserById(Guid userId)
        {
            var result = await _service.DeleteUserByIdAsync(userId);

            if (!result.Success)
            {
                return result.Message.Contains("not found")
                    ? NotFound(result)
                    : BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Delete user by email address
        /// </summary>
        [HttpDelete("delete-by-email")]
        [Authorize(Roles = "owner,admin")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> DeleteUserByEmail([FromQuery] string email)
        {
            var result = await _service.DeleteUserByEmailAsync(email);

            if (!result.Success)
            {
                return result.Message.Contains("not found")
                    ? NotFound(result)
                    : BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Delete user by username
        /// </summary>
        [HttpDelete("user/username/{username}")]
        [Authorize(Roles = "owner,admin")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> DeleteUserByUsername(string username)
        {
            var result = await _service.DeleteUserByUsernameAsync(username);

            if (!result.Success)
            {
                return result.Message.Contains("not found")
                    ? NotFound(result)
                    : BadRequest(result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Batch delete users by email pattern (SQL LIKE pattern)
        /// ⚠️ DEVELOPMENT ONLY - Disabled in production
        /// </summary>
        [HttpDelete("batch-delete")]
        [Authorize(Roles = "owner,admin")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> DeleteUsersByEmailPattern([FromQuery] string pattern)
        {
            if (!_environment.IsDevelopment())
            {
                _logger.LogWarning("Batch delete blocked in {Environment}", _environment.EnvironmentName);
                return StatusCode(403, new { success = false, message = "This endpoint is disabled outside development" });
            }

            _logger.LogWarning("Batch delete requested with pattern: {Pattern}", pattern);

            var result = await _service.DeleteUsersByEmailPatternAsync(pattern);
            return result.Success ? Ok(result) : BadRequest(result);
        }

        /// <summary>
        /// Delete ALL test users (emails/usernames containing 'test' or 'example')
        /// ⚠️ DEVELOPMENT ONLY
        /// </summary>
        [HttpDelete("users/batch/test-users")]
        [Authorize(Roles = "owner")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> DeleteAllTestUsers()
        {
            if (!_environment.IsDevelopment())
            {
                _logger.LogWarning("Delete all test users blocked in {Environment}", _environment.EnvironmentName);
                return StatusCode(403, new { success = false, message = "This endpoint is disabled outside development" });
            }

            _logger.LogWarning("DELETE ALL TEST USERS requested");

            var result = await _service.DeleteAllTestUsersAsync();
            return Ok(result);
        }

        /// <summary>
        /// Promote a member to admin (Owner only)
        /// </summary>
        [HttpPost("promote-to-admin")]
        [Authorize(Roles = "owner")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> PromoteToAdmin([FromBody] RoleChangeRequest request)
        {
            try
            {
                var ownerUserId = GetCurrentUserId();
                var ownerTenantId = GetTenantId();

                _logger.LogInformation("🔵 CONTROLLER - Promote request: Owner={OwnerId}, Target={Email}",
                    ownerUserId, request.TargetUserEmail);

                // Log JWT roles for debugging
                var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
                _logger.LogInformation("🔵 Owner JWT roles: [{Roles}]", string.Join(", ", roles));

                var result = await _service.PromoteUserToAdminAsync(ownerUserId, ownerTenantId, request.TargetUserEmail);

                if (result.Success)
                {
                    _logger.LogInformation("✅ CONTROLLER - Promotion successful");
                    return Ok(result);
                }
                else
                {
                    _logger.LogWarning("⚠️ CONTROLLER - Promotion failed: {Message}", result.Message);
                    return BadRequest(result);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ CONTROLLER ERROR - Promote endpoint exception");
                return BadRequest(new { success = false, message = $"Promotion failed: {ex.Message}" });
            }
        }

        /// <summary>
        /// Demote an admin to member (Owner only)
        /// </summary>
        [HttpPost("demote-to-member")]
        [Authorize(Roles = "owner")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> DemoteToMember([FromBody] RoleChangeRequest request)
        {
            try
            {
                var ownerUserId = GetCurrentUserId();
                var ownerTenantId = GetTenantId();

                _logger.LogInformation("🔵 CONTROLLER - Demote request: Owner={OwnerId}, Target={Email}",
                    ownerUserId, request.TargetUserEmail);

                // Log JWT roles for debugging
                var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
                _logger.LogInformation("🔵 Owner JWT roles: [{Roles}]", string.Join(", ", roles));

                var result = await _service.DemoteAdminToMemberAsync(ownerUserId, ownerTenantId, request.TargetUserEmail);

                if (result.Success)
                {
                    _logger.LogInformation("✅ CONTROLLER - Demotion successful");
                    return Ok(result);
                }
                else
                {
                    _logger.LogWarning("⚠️ CONTROLLER - Demotion failed: {Message}", result.Message);
                    return BadRequest(result);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ CONTROLLER ERROR - Demote endpoint exception");
                return BadRequest(new { success = false, message = $"Demotion failed: {ex.Message}" });
            }
        }
    }

    // Request model for role changes
    public class RoleChangeRequest
    {
        public string TargetUserEmail { get; set; } = string.Empty;
    }
}
#endregion