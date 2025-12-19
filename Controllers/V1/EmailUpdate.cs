// ==========================================================================
// EMAIL UPDATE MODULE — User Email Address Management
// Single file: Repository + Service + Controller
// NO DTOs, NO Interfaces - Simple request/response classes
// Secure email changes with verification workflow
// ==========================================================================

using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

// ==========================================================================
// DTOs - Email Update Request/Response Models
// ==========================================================================

#region DTOs

namespace KeiroGenesis.API.DTOs
{
    // ============================================================
    // 1. REQUEST EMAIL CHANGE
    // ============================================================

    public sealed class RequestEmailChangeRequest
    {
        public string NewEmail { get; init; } = string.Empty;
        public string CurrentPassword { get; init; } = string.Empty;
    }

    public sealed class RequestEmailChangeResponse
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public string? NewEmail { get; init; }
        public DateTime? ExpiresAt { get; init; }
    }

    // ============================================================
    // 2. VERIFY EMAIL CHANGE
    // ============================================================

    public sealed class VerifyEmailChangeRequest
    {
        public string VerificationCode { get; init; } = string.Empty;
    }

    public sealed class VerifyEmailChangeResponse
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public string? OldEmail { get; init; }
        public string? NewEmail { get; init; }
    }

    // ============================================================
    // 3. GET PENDING EMAIL CHANGE
    // ============================================================

    public sealed class PendingEmailChangeResponse
    {
        public bool HasPendingChange { get; init; }
        public string? NewEmail { get; init; }
        public DateTime? RequestedAt { get; init; }
        public DateTime? ExpiresAt { get; init; }
        public bool IsExpired { get; init; }
    }

    // ============================================================
    // 4. CANCEL EMAIL CHANGE
    // ============================================================

    public sealed class CancelEmailChangeResponse
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
    }
}

#endregion

// ==========================================================================
// REPOSITORY - Database Access Layer
// ==========================================================================

#region Repository

namespace KeiroGenesis.API.Repositories
{
    public class EmailUpdateRepository
    {
        private readonly IDbConnectionFactory _db;

        public EmailUpdateRepository(IDbConnectionFactory db)
        {
            _db = db;
        }

        // ============================================================
        // 1. REQUEST EMAIL CHANGE
        // ============================================================

        public async Task<dynamic?> RequestEmailChangeAsync(
            Guid tenantId,
            Guid userId,
            string newEmail,
            string passwordHash,
            string verificationCode,
            string verificationCodeHash,
            string? ipAddress = null,
            string? userAgent = null)
        {
            using var conn = _db.CreateConnection();

            return await conn.QueryFirstOrDefaultAsync(
                @"SELECT * FROM auth.fn_request_email_change(
                    @tenant_id, 
                    @user_id, 
                    @new_email, 
                    @password_hash, 
                    @verification_code, 
                    @verification_code_hash, 
                    @ip_address, 
                    @user_agent
                )",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    new_email = newEmail,
                    password_hash = passwordHash,
                    verification_code = verificationCode,
                    verification_code_hash = verificationCodeHash,
                    ip_address = ipAddress,
                    user_agent = userAgent
                });
        }

        // ============================================================
        // 2. VERIFY EMAIL CHANGE
        // ============================================================

        public async Task<dynamic?> VerifyEmailChangeAsync(
            Guid tenantId,
            Guid userId,
            string verificationCodeHash)
        {
            using var conn = _db.CreateConnection();

            return await conn.QueryFirstOrDefaultAsync(
                @"SELECT * FROM auth.fn_verify_email_change(
                    @tenant_id,
                    @user_id,
                    @verification_code_hash
                )",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    verification_code_hash = verificationCodeHash
                });
        }

        // ============================================================
        // 3. GET PENDING EMAIL CHANGE
        // ============================================================

        public async Task<dynamic?> GetPendingEmailChangeAsync(
            Guid tenantId,
            Guid userId)
        {
            using var conn = _db.CreateConnection();

            return await conn.QueryFirstOrDefaultAsync(
                @"SELECT * FROM auth.fn_get_pending_email_change(
                    @tenant_id,
                    @user_id
                )",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId
                });
        }

        // ============================================================
        // 4. CANCEL EMAIL CHANGE REQUEST
        // ============================================================

        public async Task<dynamic?> CancelEmailChangeAsync(
            Guid tenantId,
            Guid userId)
        {
            using var conn = _db.CreateConnection();

            return await conn.QueryFirstOrDefaultAsync(
                @"SELECT * FROM auth.fn_cancel_email_change(
                    @tenant_id,
                    @user_id
                )",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId
                });
        }

        // ============================================================
        // 5. GET USER BY ID (For password verification)
        // ============================================================

        public async Task<dynamic?> GetUserByIdAsync(Guid userId, Guid tenantId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                @"SELECT 
                    user_id,
                    username,
                    email,
                    password_hash,
                    is_active,
                    is_email_verified
                FROM auth.fn_get_user_by_id(@user_id, @tenant_id)",
                new { user_id = userId, tenant_id = tenantId });

            return result.FirstOrDefault();
        }
    }
}

#endregion

// ==========================================================================
// SERVICE - Business Logic Layer
// ==========================================================================

#region Service

namespace KeiroGenesis.API.Services
{
    public class EmailUpdateService
    {
        private readonly Repositories.EmailUpdateRepository _repo;
        private readonly IConfiguration _config;
        private readonly ILogger<EmailUpdateService> _logger;
        private readonly IEmailProvider _email;

        public EmailUpdateService(
            Repositories.EmailUpdateRepository repo,
            IConfiguration config,
            ILogger<EmailUpdateService> logger,
            IEmailProvider email)
        {
            _repo = repo;
            _config = config;
            _logger = logger;
            _email = email;
        }

        // ============================================================
        // HELPER: Generate 6-digit verification code
        // ============================================================

        private string GenerateVerificationCode()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            var code = BitConverter.ToUInt32(bytes, 0) % 1000000;
            return code.ToString("D6"); // 6 digits with leading zeros
        }

        // ============================================================
        // HELPER: Hash verification code
        // ============================================================

        private string HashVerificationCode(string code)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(code);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        // ============================================================
        // HELPER: Verify password
        // ============================================================

        private bool VerifyPassword(string password, string passwordHash)
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }

        // ============================================================
        // 1. REQUEST EMAIL CHANGE
        // ============================================================

        public async Task<RequestEmailChangeResponse> RequestEmailChangeAsync(
            Guid tenantId,
            Guid userId,
            string newEmail,
            string currentPassword,
            string? ipAddress = null,
            string? userAgent = null)
        {
            try
            {
                // 1. Get user and verify password
                var user = await _repo.GetUserByIdAsync(userId, tenantId);

                if (user == null)
                {
                    return new RequestEmailChangeResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                if (!user.is_active)
                {
                    return new RequestEmailChangeResponse
                    {
                        Success = false,
                        Message = "User account is not active"
                    };
                }

                // Verify password
                if (!VerifyPassword(currentPassword, user.password_hash))
                {
                    _logger.LogWarning(
                        "Failed email change attempt for user {UserId} - incorrect password",
                        userId);

                    return new RequestEmailChangeResponse
                    {
                        Success = false,
                        Message = "Current password is incorrect"
                    };
                }

                // 2. Generate verification code
                var verificationCode = GenerateVerificationCode();
                var verificationCodeHash = HashVerificationCode(verificationCode);

                // 3. Create email change request
                var result = await _repo.RequestEmailChangeAsync(
                    tenantId,
                    userId,
                    newEmail.Trim().ToLower(),
                    user.password_hash, // Pass for stored procedure validation
                    verificationCode,
                    verificationCodeHash,
                    ipAddress,
                    userAgent);

                if (result == null || !result.success)
                {
                    return new RequestEmailChangeResponse
                    {
                        Success = false,
                        Message = result?.message ?? "Failed to create email change request"
                    };
                }

                // 4. Send verification email
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _email.SendEmailVerificationAsync(
                            newEmail,
                            user.username ?? "User",
                            verificationCode);

                        _logger.LogInformation(
                            "Email change verification sent to {NewEmail} for user {UserId}",
                            newEmail,
                            userId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(
                            ex,
                            "Failed to send email change verification to {NewEmail}",
                            newEmail);
                    }
                });

                // 5. Send notification to old email
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _email.SendEmailChangeNotificationAsync(
                            user.email,
                            user.username ?? "User",
                            newEmail);

                        _logger.LogInformation(
                            "Email change notification sent to old email {OldEmail} for user {UserId}",
                            (string)user.email,
                            userId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(
                            ex,
                            "Failed to send email change notification to {OldEmail}",
                            (string)user.email);
                    }
                });

                return new RequestEmailChangeResponse
                {
                    Success = true,
                    Message = $"Verification code sent to {newEmail}. Please check your email and enter the code within 24 hours.",
                    NewEmail = newEmail,
                    ExpiresAt = DateTime.UtcNow.AddHours(24)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Error in RequestEmailChangeAsync for user {UserId}",
                    userId);

                return new RequestEmailChangeResponse
                {
                    Success = false,
                    Message = "An error occurred while processing your request"
                };
            }
        }

        // ============================================================
        // 2. VERIFY EMAIL CHANGE
        // ============================================================

        public async Task<VerifyEmailChangeResponse> VerifyEmailChangeAsync(
            Guid tenantId,
            Guid userId,
            string verificationCode)
        {
            try
            {
                var verificationCodeHash = HashVerificationCode(verificationCode);

                var result = await _repo.VerifyEmailChangeAsync(
                    tenantId,
                    userId,
                    verificationCodeHash);

                if (result == null || !result.success)
                {
                    return new VerifyEmailChangeResponse
                    {
                        Success = false,
                        Message = result?.message ?? "Invalid or expired verification code"
                    };
                }

                _logger.LogInformation(
                    "Email successfully changed from {OldEmail} to {NewEmail} for user {UserId}",
                    (string)result.old_email,
                    (string)result.new_email,
                    userId);

                return new VerifyEmailChangeResponse
                {
                    Success = true,
                    Message = "Email address updated successfully",
                    OldEmail = result.old_email,
                    NewEmail = result.new_email
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Error in VerifyEmailChangeAsync for user {UserId}",
                    userId);

                return new VerifyEmailChangeResponse
                {
                    Success = false,
                    Message = "An error occurred while verifying your email change"
                };
            }
        }

        // ============================================================
        // 3. GET PENDING EMAIL CHANGE
        // ============================================================

        public async Task<PendingEmailChangeResponse> GetPendingEmailChangeAsync(
            Guid tenantId,
            Guid userId)
        {
            try
            {
                var result = await _repo.GetPendingEmailChangeAsync(tenantId, userId);

                if (result == null)
                {
                    return new PendingEmailChangeResponse
                    {
                        HasPendingChange = false
                    };
                }

                return new PendingEmailChangeResponse
                {
                    HasPendingChange = true,
                    NewEmail = result.new_email,
                    RequestedAt = result.requested_at,
                    ExpiresAt = result.expires_at,
                    IsExpired = result.is_expired
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Error in GetPendingEmailChangeAsync for user {UserId}",
                    userId);

                return new PendingEmailChangeResponse
                {
                    HasPendingChange = false
                };
            }
        }

        // ============================================================
        // 4. CANCEL EMAIL CHANGE REQUEST
        // ============================================================

        public async Task<CancelEmailChangeResponse> CancelEmailChangeAsync(
            Guid tenantId,
            Guid userId)
        {
            try
            {
                var result = await _repo.CancelEmailChangeAsync(tenantId, userId);

                if (result == null || !result.success)
                {
                    return new CancelEmailChangeResponse
                    {
                        Success = false,
                        Message = result?.message ?? "No pending email change request found"
                    };
                }

                _logger.LogInformation(
                    "Email change request cancelled for user {UserId}",
                    userId);

                return new CancelEmailChangeResponse
                {
                    Success = true,
                    Message = "Email change request cancelled successfully"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Error in CancelEmailChangeAsync for user {UserId}",
                    userId);

                return new CancelEmailChangeResponse
                {
                    Success = false,
                    Message = "An error occurred while cancelling your request"
                };
            }
        }
    }
}

#endregion

// ==========================================================================
// CONTROLLER - API Endpoints
// ==========================================================================

#region Controller

namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
    [Route("api/v1/user/email")]
    [Produces("application/json")]
    public class EmailUpdateController : ControllerBase
    {
        private readonly Services.EmailUpdateService _service;
        private readonly ILogger<EmailUpdateController> _logger;

        public EmailUpdateController(
            Services.EmailUpdateService service,
            ILogger<EmailUpdateController> logger)
        {
            _service = service;
            _logger = logger;
        }

        // ============================================================
        // HELPER: Extract tenant ID from JWT
        // ============================================================

        private Guid GetTenantId()
        {
            var tenantIdClaim = User.FindFirst("tenant_id")?.Value;
            if (string.IsNullOrEmpty(tenantIdClaim) || !Guid.TryParse(tenantIdClaim, out var tenantId))
            {
                throw new UnauthorizedAccessException("Tenant ID not found in token");
            }
            return tenantId;
        }

        // ============================================================
        // HELPER: Extract user ID from JWT
        // ============================================================

        private Guid GetUserId()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                           ?? User.FindFirst("sub")?.Value;

            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                throw new UnauthorizedAccessException("User ID not found in token");
            }
            return userId;
        }

        // ============================================================
        // HELPER: Get client IP address
        // ============================================================

        private string? GetClientIpAddress()
        {
            return HttpContext.Connection.RemoteIpAddress?.ToString();
        }

        // ============================================================
        // HELPER: Get user agent
        // ============================================================

        private string? GetUserAgent()
        {
            return HttpContext.Request.Headers["User-Agent"].ToString();
        }

        // ============================================================
        // POST: /api/v1/user/email/change-request
        // Request email change (requires current password)
        // ============================================================

        [HttpPost("change-request")]
        [Authorize]
        public async Task<ActionResult<DTOs.RequestEmailChangeResponse>> RequestEmailChange(
            [FromBody] DTOs.RequestEmailChangeRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.NewEmail))
                {
                    return BadRequest(new DTOs.RequestEmailChangeResponse
                    {
                        Success = false,
                        Message = "New email is required"
                    });
                }

                if (string.IsNullOrWhiteSpace(request.CurrentPassword))
                {
                    return BadRequest(new DTOs.RequestEmailChangeResponse
                    {
                        Success = false,
                        Message = "Current password is required"
                    });
                }

                var tenantId = GetTenantId();
                var userId = GetUserId();
                var ipAddress = GetClientIpAddress();
                var userAgent = GetUserAgent();

                var result = await _service.RequestEmailChangeAsync(
                    tenantId,
                    userId,
                    request.NewEmail,
                    request.CurrentPassword,
                    ipAddress,
                    userAgent);

                if (!result.Success)
                {
                    return BadRequest(result);
                }

                return Ok(result);
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized email change request");
                return Unauthorized(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in RequestEmailChange endpoint");
                return StatusCode(500, new { message = "An error occurred" });
            }
        }

        // ============================================================
        // POST: /api/v1/user/email/verify-change
        // Verify email change with code
        // ============================================================

        [HttpPost("verify-change")]
        [Authorize]
        public async Task<ActionResult<DTOs.VerifyEmailChangeResponse>> VerifyEmailChange(
            [FromBody] DTOs.VerifyEmailChangeRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.VerificationCode))
                {
                    return BadRequest(new DTOs.VerifyEmailChangeResponse
                    {
                        Success = false,
                        Message = "Verification code is required"
                    });
                }

                var tenantId = GetTenantId();
                var userId = GetUserId();

                var result = await _service.VerifyEmailChangeAsync(
                    tenantId,
                    userId,
                    request.VerificationCode);

                if (!result.Success)
                {
                    return BadRequest(result);
                }

                return Ok(result);
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized email verification");
                return Unauthorized(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in VerifyEmailChange endpoint");
                return StatusCode(500, new { message = "An error occurred" });
            }
        }

        // ============================================================
        // GET: /api/v1/user/email/pending-change
        // Get pending email change request
        // ============================================================

        [HttpGet("pending-change")]
        [Authorize]
        public async Task<ActionResult<DTOs.PendingEmailChangeResponse>> GetPendingChange()
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();

                var result = await _service.GetPendingEmailChangeAsync(tenantId, userId);

                return Ok(result);
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized access to pending change");
                return Unauthorized(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in GetPendingChange endpoint");
                return StatusCode(500, new { message = "An error occurred" });
            }
        }

        // ============================================================
        // DELETE: /api/v1/user/email/cancel-change
        // Cancel pending email change request
        // ============================================================

        [HttpDelete("cancel-change")]
        [Authorize]
        public async Task<ActionResult<DTOs.CancelEmailChangeResponse>> CancelEmailChange()
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();

                var result = await _service.CancelEmailChangeAsync(tenantId, userId);

                if (!result.Success)
                {
                    return BadRequest(result);
                }

                return Ok(result);
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized cancel request");
                return Unauthorized(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in CancelEmailChange endpoint");
                return StatusCode(500, new { message = "An error occurred" });
            }
        }
    }
}

#endregion