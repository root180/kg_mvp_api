// ============================================================================
// IDENTITY RATINGS MODULE (MVP)
// Purpose:
//   - Convert Identity Signals → Content Rating Decisions
//   - NO identity verification logic
//   - NO authorization decisions
//   - Stored procedures ONLY
//
// Ratings (MVP):
//   - G  (General - under 13 or no DOB)
//   - PG (Parental Guidance - ages 13-17)
//   - MA (Mature - ages 18+)
//
// Identity provides SIGNALS.
// Rating module provides DECISIONS.
// Authorization/Billing consume DECISIONS.
// ============================================================================

using Dapper;
using KeiroGenesis.API.Core.Database;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Data;
using System.Security.Claims;
using System.Threading.Tasks;

#region Repository
namespace KeiroGenesis.API.Ratings
{
    public class ContentRatingsRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<ContentRatingsRepository> _logger;

        public ContentRatingsRepository(
            IDbConnectionFactory db,
            ILogger<ContentRatingsRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        /// <summary>
        /// CREATE rating profile (call once during registration)
        /// Calculates rating from date_of_birth and stores it
        /// Returns: "G", "PG", or "MA"
        /// </summary>
        public async Task<string?> InitializeRatingProfileAsync(
      Guid tenantId,
      Guid userId,
      DateTime? dateOfBirth)
        {
            using var conn = _db.CreateConnection();
            return await conn.ExecuteScalarAsync<string>(
                "SELECT auth.create_user_rating_profile(@p_tenant_id, @p_user_id, @p_date_of_birth::date)",
                new
                {
                    p_tenant_id = tenantId,
                    p_user_id = userId,
                    p_date_of_birth = dateOfBirth
                }
            );
        }

        /// <summary>
        /// GET existing rating profile
        /// </summary>
        public async Task<dynamic?> GetRatingProfileAsync(Guid tenantId, Guid userId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM auth.get_user_rating_profile(@p_tenant_id, @p_user_id)",
                new { p_tenant_id = tenantId, p_user_id = userId }
            );
        }

        /// <summary>
        /// Re-evaluate rating from current age (e.g., after birthday)
        /// </summary>
        public async Task<dynamic?> EvaluateEffectiveRatingAsync(Guid tenantId, Guid userId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "auth.evaluate_user_effective_rating",
                new { p_tenant_id = tenantId, p_user_id = userId },
                commandType: CommandType.StoredProcedure
            );
        }
    }
}
#endregion

#region Service
namespace KeiroGenesis.API.Ratings
{
    public class ContentRatingsService
    {
        private readonly ContentRatingsRepository _repo;
        private readonly ILogger<ContentRatingsService> _logger;

        public ContentRatingsService(
            ContentRatingsRepository repo,
            ILogger<ContentRatingsService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        /// <summary>
        /// CREATE rating profile during registration
        /// Returns the calculated rating ("G", "PG", or "MA")
        /// </summary>
        public async Task<string> InitializeRatingProfileAsync(
            Guid tenantId,
            Guid userId,
            DateTime? dateOfBirth)
        {
            var rating = await _repo.InitializeRatingProfileAsync(tenantId, userId, dateOfBirth);

            _logger.LogInformation(
                "Rating profile created for user {UserId}: {Rating}",
                userId, rating ?? "G");

            return rating ?? "G";
        }

        /// <summary>
        /// GET existing rating profile (for token generation, API calls)
        /// </summary>
        public async Task<RatingStatusResponse> GetRatingStatusAsync(Guid tenantId, Guid userId)
        {
            var profile = await _repo.GetRatingProfileAsync(tenantId, userId);

            if (profile == null)
            {
                _logger.LogWarning(
                    "Rating profile not found for user {UserId}, defaulting to G",
                    userId);

                return new RatingStatusResponse
                {
                    AllowedRating = "G",
                    Message = "Rating profile not found; default applied"
                };
            }

            return new RatingStatusResponse
            {
                AllowedRating = profile.effective_rating,
                LastEvaluatedAt = profile.last_evaluated_at,
                Reason = profile.reason
            };
        }

        /// <summary>
        /// Re-evaluate rating (e.g., user had a birthday)
        /// </summary>
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
                "Rating re-evaluated for user {UserId}: {Rating}",
                userId, (string)result.effective_rating);

            return new RatingDecisionResponse
            {
                Success = true,
                AllowedRating = result.effective_rating,
                Reason = result.reason
            };
        }
    }

    // Response DTOs
    public class RatingStatusResponse
    {
        public string AllowedRating { get; set; } = "G";
        public DateTime? LastEvaluatedAt { get; set; }
        public string? Reason { get; set; }
        public string? Message { get; set; }
    }

    public class RatingDecisionResponse
    {
        public bool Success { get; set; }
        public string? AllowedRating { get; set; }
        public string? Reason { get; set; }
        public string? Message { get; set; }
    }
}
#endregion

#region Controller
namespace KeiroGenesis.API.Ratings
{
    [ApiController]
    [Route("api/v1/content/ratings")]
    [Authorize]
    public class ContentRatingsController : ControllerBase
    {
        private readonly ContentRatingsService _service;

        public ContentRatingsController(ContentRatingsService service)
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
        /// Get current rating status
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<RatingStatusResponse>> GetStatus()
        {
            return Ok(await _service.GetRatingStatusAsync(GetTenantId(), GetUserId()));
        }

        /// <summary>
        /// Re-evaluate rating from identity signals (e.g., after birthday)
        /// </summary>
        [HttpPost("evaluate")]
        public async Task<ActionResult<RatingDecisionResponse>> Evaluate()
        {
            return Ok(await _service.EvaluateRatingAsync(GetTenantId(), GetUserId()));
        }
    }
}
#endregion