// ============================================================================
// BILLING SUBSCRIPTION SYSTEM - Complete Implementation
// ============================================================================
// Contract Compliant: Uses billing.subscription_plans as canonical source
// Follows Repository → Service → Controller pattern
// Includes subscription plan in JWT token generation

using Dapper;
using KeiroGenesis.API.Models;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Npgsql;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;


#region Models and DTOs
namespace KeiroGenesis.API.Models
{
    #region Models & DTOs
    // ============================================================================
    // MODELS & DTOs
    // ============================================================================

    public class SubscriptionStatus
    {
        public Guid SubscriptionId { get; set; }
        public Guid TenantId { get; set; }
        public Guid SubscriptionPlanId { get; set; }
        public string PlanName { get; set; } = string.Empty;
        public int PlanRank { get; set; }
        public string Status { get; set; } = string.Empty;
        public DateTime ActivatedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
    }

    public class UserSubscriptionStatus
    {
        public Guid UserId { get; set; }
        public Guid TenantId { get; set; }
        public string PlanName { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public DateTime? ActivatedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool IsActive { get; set; }
    }

    public class SubscriptionUpgradeResult
    {
        public Guid SubscriptionId { get; set; }
        public string? OldPlan { get; set; }
        public string NewPlan { get; set; } = string.Empty;
        public DateTime UpgradedAt { get; set; }
    }

    public class SubscriptionCancellationResult
    {
        public Guid SubscriptionId { get; set; }
        public DateTime CancelledAt { get; set; }
        public DateTime? EffectiveUntil { get; set; }
    }
    #endregion

}
#endregion
#region Repository Layer
// ============================================================================
// REPOSITORY LAYER
// ============================================================================
namespace KeiroGenesis.API.Repositories
{
   

    public class BillingRepository
    {
        private readonly IConfiguration _config;
        private readonly ILogger<BillingRepository> _logger;

        public BillingRepository(IConfiguration config, ILogger<BillingRepository> logger)
        {
            _config = config;
            _logger = logger;
        }

        private IDbConnection CreateConnection()
        {
            var connectionString = _config.GetConnectionString("PostgreSQL")
                ?? throw new InvalidOperationException("PostgreSQL connection string not configured");
            return new NpgsqlConnection(connectionString);
        }

        public async Task<SubscriptionStatus?> GetSubscriptionStatusAsync(Guid tenantId)
        {
            try
            {
                using var conn = CreateConnection();
                var result = await conn.QueryFirstOrDefaultAsync<SubscriptionStatus>(
                    "SELECT * FROM billing.fn_get_subscription_status(@p_tenant_id)",
                    new { p_tenant_id = tenantId }
                );
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting subscription status for tenant {TenantId}", tenantId);
                throw;
            }
        }

        public async Task<UserSubscriptionStatus?> GetUserSubscriptionAsync(Guid tenantId, Guid userId)
        {
            try
            {
                using var conn = CreateConnection();
                var result = await conn.QueryFirstOrDefaultAsync<UserSubscriptionStatus>(
                    @"SELECT 
                        s.user_id as UserId,
                        s.tenant_id as TenantId,
                        sp.subscription_name as PlanName,
                        s.status as Status,
                        s.activated_at as ActivatedAt,
                        s.expires_at as ExpiresAt,
                        (s.status = 'active') as IsActive
                      FROM billing.subscriptions s
                      JOIN billing.subscription_plans sp ON s.subscription_plan_id = sp.subscription_plan_id
                      WHERE s.tenant_id = @tenant_id 
                        AND s.user_id = @user_id
                      ORDER BY s.created_at DESC
                      LIMIT 1",
                    new { tenant_id = tenantId, user_id = userId }
                );
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user subscription for tenant {TenantId}, user {UserId}", tenantId, userId);
                throw;
            }
        }

        public async Task<SubscriptionUpgradeResult> UpgradeSubscriptionAsync(
            Guid tenantId,
            Guid userId,
            string newPlan)
        {
            try
            {
                using var conn = CreateConnection();
                var result = await conn.QuerySingleAsync<SubscriptionUpgradeResult>(
                    @"SELECT * FROM billing.fn_upgrade_subscription(
                        @p_tenant_id, 
                        @p_user_id, 
                        @p_new_plan
                    )",
                    new
                    {
                        p_tenant_id = tenantId,
                        p_user_id = userId,
                        p_new_plan = newPlan
                    }
                );
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error upgrading subscription for tenant {TenantId}", tenantId);
                throw;
            }
        }

        public async Task<SubscriptionUpgradeResult> DowngradeSubscriptionAsync(
            Guid tenantId,
            Guid userId,
            string newPlan)
        {
            try
            {
                using var conn = CreateConnection();
                var result = await conn.QuerySingleAsync<SubscriptionUpgradeResult>(
                    @"SELECT * FROM billing.fn_downgrade_subscription(
                        @p_tenant_id, 
                        @p_user_id, 
                        @p_new_plan
                    )",
                    new
                    {
                        p_tenant_id = tenantId,
                        p_user_id = userId,
                        p_new_plan = newPlan
                    }
                );
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error downgrading subscription for tenant {TenantId}", tenantId);
                throw;
            }
        }

        public async Task<SubscriptionCancellationResult> CancelSubscriptionAsync(
            Guid tenantId,
            Guid userId,
            string? cancellationReason = null)
        {
            try
            {
                using var conn = CreateConnection();
                var result = await conn.QuerySingleAsync<SubscriptionCancellationResult>(
                    @"SELECT * FROM billing.fn_cancel_subscription(
                        @p_tenant_id, 
                        @p_user_id, 
                        @p_cancellation_reason
                    )",
                    new
                    {
                        p_tenant_id = tenantId,
                        p_user_id = userId,
                        p_cancellation_reason = cancellationReason
                    }
                );
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cancelling subscription for tenant {TenantId}", tenantId);
                throw;
            }
        }
    }
    
}
#endregion
#region Service Layer
// ============================================================================
// SERVICE LAYER
// ============================================================================

namespace KeiroGenesis.API.Services
{ 
    public class BillingService
    {
        private readonly BillingRepository _repo;
        private readonly ILogger<BillingService> _logger;

        public BillingService(BillingRepository repo, ILogger<BillingService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        /// <summary>
        /// Get subscription plan name for JWT token generation
        /// Returns canonical plan name from subscription_plans
        /// </summary>
        public async Task<string> GetSubscriptionPlanAsync(Guid tenantId)
        {
            var status = await _repo.GetSubscriptionStatusAsync(tenantId);

            if (status == null || status.Status != "active")
            {
                _logger.LogWarning("No active subscription found for tenant {TenantId}, defaulting to free", tenantId);
                return "free";
            }

            return status.PlanName;
        }

        /// <summary>
        /// Get full subscription status for tenant
        /// </summary>
        public async Task<SubscriptionStatus?> GetSubscriptionStatusAsync(Guid tenantId)
        {
            return await _repo.GetSubscriptionStatusAsync(tenantId);
        }

        /// <summary>
        /// Get subscription status for a specific user
        /// </summary>
        public async Task<UserSubscriptionStatus?> GetUserSubscriptionAsync(Guid tenantId, Guid userId)
        {
            return await _repo.GetUserSubscriptionAsync(tenantId, userId);
        }

        /// <summary>
        /// Upgrade subscription to a higher plan
        /// </summary>
        public async Task<SubscriptionUpgradeResult> UpgradeAsync(
            Guid tenantId,
            Guid userId,
            string newPlan)
        {
            var result = await _repo.UpgradeSubscriptionAsync(tenantId, userId, newPlan);

            _logger.LogInformation(
                "Subscription upgraded: Tenant {TenantId} from {OldPlan} to {NewPlan}",
                tenantId, result.OldPlan ?? "none", result.NewPlan
            );

            return result;
        }

        /// <summary>
        /// Downgrade subscription to a lower plan
        /// </summary>
        public async Task<SubscriptionUpgradeResult> DowngradeAsync(
            Guid tenantId,
            Guid userId,
            string newPlan)
        {
            var result = await _repo.DowngradeSubscriptionAsync(tenantId, userId, newPlan);

            _logger.LogInformation(
                "Subscription downgraded: Tenant {TenantId} from {OldPlan} to {NewPlan}",
                tenantId, result.OldPlan, result.NewPlan
            );

            return result;
        }

        /// <summary>
        /// Cancel subscription
        /// </summary>
        public async Task<SubscriptionCancellationResult> CancelAsync(
            Guid tenantId,
            Guid userId,
            string? reason = null)
        {
            var result = await _repo.CancelSubscriptionAsync(tenantId, userId, reason);

            _logger.LogInformation(
                "Subscription cancelled: Tenant {TenantId}, effective until {EffectiveUntil}",
                tenantId, result.EffectiveUntil
            );

            return result;
        }
    }
  

}

#endregion

#region Controller
// ============================================================================
// CONTROLLER LAYER
// ============================================================================

namespace KeiroGenesis.API.Controllers.V1
{


    [Route("api/v1/billing")]
    [ApiController]
    [Produces("application/json")]
    public class BillingController : ControllerBase
    {
        private readonly BillingService _service;
        private readonly ILogger<BillingController> _logger;

        public BillingController(BillingService service, ILogger<BillingController> logger)
        {
            _service = service;
            _logger = logger;
        }

        private Guid GetTenantId()
            => Guid.Parse(User.FindFirst("tenant_id")?.Value
                ?? throw new UnauthorizedAccessException("Tenant ID not found"));

        private Guid GetUserId()
            => Guid.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                ?? User.FindFirst("sub")?.Value
                ?? throw new UnauthorizedAccessException("User ID not found"));

        /// <summary>
        /// Get current subscription status for tenant
        /// </summary>
        [HttpGet("subscription")]
        [Authorize]
        public async Task<ActionResult<SubscriptionStatus>> GetSubscription()
        {
            try
            {
                var tenantId = GetTenantId();
                var result = await _service.GetSubscriptionStatusAsync(tenantId);

                if (result == null)
                {
                    return NotFound(new { message = "No subscription found" });
                }

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting subscription");
                return StatusCode(500, new { message = "Failed to retrieve subscription" });
            }
        }

        /// <summary>
        /// Get subscription for a specific user
        /// </summary>
        [HttpGet("subscription/user/{userId}")]
        [Authorize]
        public async Task<ActionResult<UserSubscriptionStatus>> GetUserSubscription(Guid userId)
        {
            try
            {
                var tenantId = GetTenantId();
                var result = await _service.GetUserSubscriptionAsync(tenantId, userId);

                if (result == null)
                {
                    return NotFound(new { message = "No subscription found for user" });
                }

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user subscription");
                return StatusCode(500, new { message = "Failed to retrieve user subscription" });
            }
        }

        /// <summary>
        /// Upgrade subscription to a higher plan
        /// </summary>
        [HttpPost("subscription/upgrade")]
        [Authorize]
        public async Task<ActionResult<SubscriptionUpgradeResult>> Upgrade([FromBody] UpgradeRequest request)
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();
                var result = await _service.UpgradeAsync(tenantId, userId, request.NewPlan);

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error upgrading subscription");
                return StatusCode(500, new { message = $"Failed to upgrade subscription: {ex.Message}" });
            }
        }

        /// <summary>
        /// Downgrade subscription to a lower plan
        /// </summary>
        [HttpPost("subscription/downgrade")]
        [Authorize]
        public async Task<ActionResult<SubscriptionUpgradeResult>> Downgrade([FromBody] DowngradeRequest request)
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();
                var result = await _service.DowngradeAsync(tenantId, userId, request.NewPlan);

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error downgrading subscription");
                return StatusCode(500, new { message = $"Failed to downgrade subscription: {ex.Message}" });
            }
        }

        /// <summary>
        /// Cancel subscription
        /// </summary>
        [HttpPost("subscription/cancel")]
        [Authorize]
        public async Task<ActionResult<SubscriptionCancellationResult>> Cancel([FromBody] CancelRequest request)
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();
                var result = await _service.CancelAsync(tenantId, userId, request.Reason);

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cancelling subscription");
                return StatusCode(500, new { message = $"Failed to cancel subscription: {ex.Message}" });
            }
        }


        // Request DTOs
        public class UpgradeRequest
        {
            public string NewPlan { get; set; } = string.Empty;
        }

        public class DowngradeRequest
        {
            public string NewPlan { get; set; } = string.Empty;
        }

        public class CancelRequest
        {
            public string? Reason { get; set; }
        }

    }
}
#endregion

// End of File