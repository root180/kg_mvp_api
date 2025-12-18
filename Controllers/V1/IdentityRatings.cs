// ============================================================================
// IDENTITY RATINGS MODULE (MVP)
// Purpose:
//   - Convert Identity Signals → Content Rating Decisions
//   - NO identity verification logic
//   - NO authorization decisions
//   - Stored procedures ONLY
//
// Ratings (MVP):
//   - G
//   - PG
//
// Identity provides SIGNALS.
// Rating module provides DECISIONS.
// Authorization/Billing consume DECISIONS.
// ============================================================================

using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Npgsql;
using System;
using System.Data;
using System.Security.Claims;
using System.Threading.Tasks;

#region Repository
namespace KeiroGenesis.Identity
{
    public class IdentityRatingRepository
    {
        private readonly string _connectionString;

        public IdentityRatingRepository(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("KeiroGenesisDb")
                ?? throw new ArgumentNullException("Database connection string not found");
        }

        private IDbConnection CreateConnection() => new NpgsqlConnection(_connectionString);

        // Ensure rating profile exists
        public async Task<dynamic?> InitializeRatingProfileAsync(Guid tenantId, Guid userId)
        {
            using var conn = CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "auth.create_user_rating_profile",
                new { p_tenant_id = tenantId, p_user_id = userId },
                commandType: CommandType.StoredProcedure
            );
        }

        // Evaluate effective rating from identity signals
        public async Task<dynamic?> EvaluateEffectiveRatingAsync(Guid tenantId, Guid userId)
        {
            using var conn = CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "auth.evaluate_user_effective_rating",
                new { p_tenant_id = tenantId, p_user_id = userId },
                commandType: CommandType.StoredProcedure
            );
        }

        // Get current rating profile
        public async Task<dynamic?> GetRatingProfileAsync(Guid tenantId, Guid userId)
        {
            using var conn = CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "auth.get_user_rating_profile",
                new { p_tenant_id = tenantId, p_user_id = userId },
                commandType: CommandType.StoredProcedure
            );
        }

        // Update preferred rating (user choice, constrained by effective rating)
        public async Task<dynamic?> UpdatePreferredRatingAsync(
            Guid tenantId,
            Guid userId,
            string preferredRating)
        {
            using var conn = CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "auth.update_user_preferred_rating",
                new
                {
                    p_tenant_id = tenantId,
                    p_user_id = userId,
                    p_preferred_rating = preferredRating
                },
                commandType: CommandType.StoredProcedure
            );
        }
    }
}
#endregion

#region Service
namespace KeiroGenesis.Identity
{
    public class IdentityRatingService
    {
        private readonly IdentityRatingRepository _repo;
        private readonly ILogger<IdentityRatingService> _logger;

        public IdentityRatingService(
            IdentityRatingRepository repo,
            ILogger<IdentityRatingService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<RatingStatusResponse> GetRatingStatusAsync(Guid tenantId, Guid userId)
        {
            await _repo.InitializeRatingProfileAsync(tenantId, userId);

            var profile = await _repo.GetRatingProfileAsync(tenantId, userId);
            if (profile == null)
            {
                return new RatingStatusResponse
                {
                    AllowedRating = "G",
                    PreferredRating = "G",
                    Message = "Rating profile not found; default applied"
                };
            }

            return new RatingStatusResponse
            {
                AllowedRating = profile.effective_rating,
                PreferredRating = profile.preferred_rating,
                LastEvaluatedAt = profile.last_evaluated_at,
                Reason = profile.reason
            };
        }

        public async Task<RatingDecisionResponse> EvaluateRatingAsync(Guid tenantId, Guid userId)
        {
            var result = await _repo.EvaluateEffectiveRatingAsync(tenantId, userId);
            if (result == null)
            {
                return new RatingDecisionResponse
                {
                    Success = false,
                    Message = "Failed to evaluate rating"
                };
            }

            _logger.LogInformation(
                "Rating evaluated for user {UserId}: {Rating}",
                userId, (Guid)result.effective_rating);

            return new RatingDecisionResponse
            {
                Success = true,
                AllowedRating = result.effective_rating,
                Reason = result.reason
            };
        }

        public async Task<RatingDecisionResponse> UpdatePreferredRatingAsync(
            Guid tenantId,
            Guid userId,
            string preferredRating)
        {
            var result = await _repo.UpdatePreferredRatingAsync(
                tenantId, userId, preferredRating);

            if (result == null || !(bool)result.success)
            {
                return new RatingDecisionResponse
                {
                    Success = false,
                    Message = "Preferred rating not allowed"
                };
            }

            return new RatingDecisionResponse
            {
                Success = true,
                AllowedRating = result.effective_rating,
                PreferredRating = result.preferred_rating,
                Reason = result.reason
            };
        }
    }

    // Responses
    public class RatingStatusResponse
    {
        public string AllowedRating { get; set; } = "G";
        public string PreferredRating { get; set; } = "G";
        public DateTime? LastEvaluatedAt { get; set; }
        public string? Reason { get; set; }
        public string? Message { get; set; }
    }

    public class RatingDecisionResponse
    {
        public bool Success { get; set; }
        public string? AllowedRating { get; set; }
        public string? PreferredRating { get; set; }
        public string? Reason { get; set; }
        public string? Message { get; set; }
    }
}
#endregion

#region Controller
namespace KeiroGenesis.Identity
{
    [ApiController]
    [Route("api/v1/identity/ratings")]
    [Authorize]
    public class IdentityRatingController : ControllerBase
    {
        private readonly IdentityRatingService _service;

        public IdentityRatingController(IdentityRatingService service)
        {
            _service = service;
        }

        private Guid GetTenantId() =>
            Guid.Parse(User.FindFirst("tenant_id")?.Value
                ?? throw new UnauthorizedAccessException("Tenant ID missing"));

        private Guid GetUserId() =>
            Guid.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                ?? throw new UnauthorizedAccessException("User ID missing"));

        /// <summary>
        /// Get current rating status (effective + preferred)
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<RatingStatusResponse>> GetStatus()
        {
            return Ok(await _service.GetRatingStatusAsync(GetTenantId(), GetUserId()));
        }

        /// <summary>
        /// Re-evaluate rating from identity signals
        /// </summary>
        [HttpPost("evaluate")]
        public async Task<ActionResult<RatingDecisionResponse>> Evaluate()
        {
            return Ok(await _service.EvaluateRatingAsync(GetTenantId(), GetUserId()));
        }

        /// <summary>
        /// Update preferred rating (constrained by identity)
        /// </summary>
        [HttpPost("preference")]
        public async Task<ActionResult<RatingDecisionResponse>> UpdatePreference(
            [FromBody] UpdateRatingPreferenceRequest request)
        {
            return Ok(await _service.UpdatePreferredRatingAsync(
                GetTenantId(), GetUserId(), request.PreferredRating));
        }
    }

    public class UpdateRatingPreferenceRequest
    {
        public string PreferredRating { get; set; } = "G";
    }
}
#endregion
