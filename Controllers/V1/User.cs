// ==========================================================================
// USER MODULE — User Profile Management
// Single file: Repository + Service + Controller
// ==========================================================================

using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

#region Repository
namespace KeiroGenesis.API.Repositories
{
    public class UserRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<UserRepository> _logger;

        public UserRepository(IDbConnectionFactory db, ILogger<UserRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<dynamic?> GetUserProfileAsync(Guid tenantId, Guid userId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                "SELECT * FROM auth.fn_get_user_profile(@tenant_id, @user_id)",
                new { tenant_id = tenantId, user_id = userId }
            );

            return result.FirstOrDefault();
        }
        public async Task<dynamic?> GetUserAsync(Guid userId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM core.users WHERE user_id = @user_id",
                new { user_id = userId }
            );
        }
    }
}
#endregion

#region Service
namespace KeiroGenesis.API.Services
{
    public class UserService
    {
        private readonly UserRepository _repo;
        private readonly ILogger<UserService> _logger;



        public UserService(Repositories.UserRepository repo, ILogger<UserService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<UserProfileResponse> GetUserProfileAsync(Guid tenantId, Guid userId)
        {
            try
            {
                var profile = await _repo.GetUserProfileAsync(tenantId, userId);

                if (profile == null)
                {
                    return new UserProfileResponse
                    {
                        Success = false,
                        Message = "User profile not found"
                    };
                }

                return new UserProfileResponse
                {
                    Success = true,
                    UserId = profile.user_id,
                    TenantId = profile.tenant_id,
                    Username = profile.username,
                    Email = profile.email,
                    FirstName = profile.first_name,
                    LastName = profile.last_name,
                    DateOfBirth = profile.date_of_birth,
                    Gender = profile.gender,
                    MobileNumber = profile.mobile_number,
                    ContentEligibilityLevel = profile.content_eligibility_level,
                    Age = profile.age,
                    IsActive = profile.is_active,
                    IsEmailVerified = profile.is_email_verified,
                    AvatarUrl = profile.avatar_url,
                    Bio = profile.bio,
                    CreatedAt = profile.created_at,
                    LastLoginAt = profile.last_login_at,
                    TotalClones = profile.total_clones ?? 0,
                    SubscriptionTier = profile.subscription_tier,
                    TenantName = profile.tenant_name
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user profile for user {UserId}", userId);
                return new UserProfileResponse
                {
                    Success = false,
                    Message = $"Failed to retrieve user profile: {ex.Message}"
                };
            }
     }
        public Task<dynamic?> GetUserAsync(Guid userId) => _repo.GetUserAsync(userId);
    }
}
#endregion

#region Controller
namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
    [Route("api/v1/[controller]")]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly UserService _service;

        public UserController(UserService service)
        {
            _service = service;
        }

        [HttpGet("get-user")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetUser()
        {
            var userId = GetCurrentUserId();
            var user = await _service.GetUserAsync(userId);
            return user != null ? Ok(user) : NotFound();
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
}
#endregion

#region DTO
// DTOs
public class UserProfileResponse
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    [JsonPropertyName("userId")]
    public Guid UserId { get; set; }

    [JsonPropertyName("tenantId")]
    public Guid TenantId { get; set; }

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    [JsonPropertyName("firstName")]
    public string? FirstName { get; set; }

    [JsonPropertyName("lastName")]
    public string? LastName { get; set; }

    [JsonPropertyName("dateOfBirth")]
    public DateTime? DateOfBirth { get; set; }

    [JsonPropertyName("gender")]
    public string? Gender { get; set; }

    [JsonPropertyName("mobileNumber")]
    public string? MobileNumber { get; set; }

    [JsonPropertyName("contentEligibilityLevel")]
    public string? ContentEligibilityLevel { get; set; }

    [JsonPropertyName("age")]
    public int? Age { get; set; }

    [JsonPropertyName("isActive")]
    public bool IsActive { get; set; }

    [JsonPropertyName("isEmailVerified")]
    public bool IsEmailVerified { get; set; }

    [JsonPropertyName("avatarUrl")]
    public string? AvatarUrl { get; set; }

    [JsonPropertyName("bio")]
    public string? Bio { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTime CreatedAt { get; set; }

    [JsonPropertyName("lastLoginAt")]
    public DateTime? LastLoginAt { get; set; }

    [JsonPropertyName("totalClones")]
    public int TotalClones { get; set; }

    [JsonPropertyName("subscriptionTier")]
    public string SubscriptionTier { get; set; } = string.Empty;

    [JsonPropertyName("tenantName")]
    public string TenantName { get; set; } = string.Empty;
}


#endregion