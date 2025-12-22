// ==========================================================================
// BILLING MODULE
// Subscription upgrades with identity-gated enforcement
// Single-file pattern (Repository + Service + Controller)
// ==========================================================================

using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Npgsql;
using System;
using System.Collections.Generic;
using System.Data;
using System.Security.Claims;
using System.Threading.Tasks;

#region Repository

namespace KeiroGenesis.API.Repositories
{
    public sealed class BillingRepository
    {
        private readonly IDbConnectionFactory _db;

        public BillingRepository(IDbConnectionFactory db)
        {
            _db = db;
        }

        /// <summary>
        /// Determines whether identity verification is required for a target tier.
        /// Pure policy call – no user context.
        /// </summary>
        public async Task<bool> RequiresIdentityVerificationAsync(string targetTier)
        {
            using var conn = _db.CreateConnection();
            return await conn.ExecuteScalarAsync<bool>(
                "SELECT billing.fn_requires_identity_verification(@tier)",
                new { tier = targetTier }
            );
        }

        /// <summary>
        /// Activates the subscription after all gates have passed.
        /// Throws if the tier is invalid.
        /// </summary>
        public async Task<bool> ActivateSubscriptionAsync(
            Guid tenantId,
            Guid userId,
            string targetTier)
        {
            using var conn = _db.CreateConnection();
            return await conn.ExecuteScalarAsync<bool>(
                "SELECT billing.fn_activate_subscription(@tenant_id, @user_id, @tier)",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    tier = targetTier
                }
            );
        }
    }
}

#endregion

#region Service

namespace KeiroGenesis.API.Services
{
    using global::KeiroGenesis.API.Repositories;
   

    public sealed class BillingService
    {
        private readonly BillingRepository _repo;
        private readonly IdentitySignalsService _identity;
        private readonly ILogger<BillingService> _logger;

        public BillingService(
            BillingRepository repo,
            IdentitySignalsService identity,
            ILogger<BillingService> logger)
        {
            _repo = repo;
            _identity = identity;
            _logger = logger;
        }

        /// <summary>
        /// Attempts a subscription upgrade.
        /// Identity is enforced ONLY if required by the target plan.
        /// </summary>
        public async Task<UpgradeResponse> AttemptUpgradeAsync(
            Guid tenantId,
            Guid userId,
            string targetTier)
        {
            // Normalize once
            targetTier = targetTier.Trim().ToLowerInvariant();

            // 1. Policy gate: does this tier require identity verification?
            var requiresIdentity =
                await _repo.RequiresIdentityVerificationAsync(targetTier);

            if (requiresIdentity)
            {
                var identity = await _identity.GetStatusAsync(tenantId, userId);

                if (identity.VerificationLevel < IdentityVerificationLevel.HumanVerified)
                {
                    _logger.LogInformation(
                        "Upgrade blocked: identity verification required. User={UserId}, Tier={Tier}",
                        userId, targetTier);

                    return UpgradeResponse.Blocked(
                        "Identity verification required to upgrade",
                        IdentityVerificationLevel.HumanVerified,
                        new[] { "verify_age", "verify_human" }
                    );
                }
            }

            // 2. Activate subscription (payment assumed complete upstream)
            try
            {
                await _repo.ActivateSubscriptionAsync(
                    tenantId,
                    userId,
                    targetTier);
            }
            catch (PostgresException ex)
            {
                _logger.LogWarning(ex,
                    "Subscription activation failed. Tenant={TenantId}, Tier={Tier}",
                    tenantId, targetTier);

                return UpgradeResponse.Failed(ex.MessageText);
            }

            _logger.LogInformation(
                "Subscription upgraded successfully. Tenant={TenantId}, Tier={Tier}",
                tenantId, targetTier);

            return UpgradeResponse.Successful(targetTier);
        }
    }
}

#endregion

#region Request / Response Models

namespace KeiroGenesis.API.Services
{
    public sealed class UpgradeRequest
    {
        public string TargetTier { get; set; } = string.Empty;

    }

    public sealed class UpgradeResponse
    {
        public bool Success { get; set; }
        public bool isBlocked { get; set; }
        public string Message { get; set; } = string.Empty;

        public string? ActivatedTier { get; set; }

        // Identity gate
        public string? RequiredVerificationLevel { get; set; }
        public List<string>? RequiredSteps { get; set; }

        // Token handling
        public bool RequiresTokenRefresh { get; set; }

        public static UpgradeResponse Blocked(
            string message,
            IdentityVerificationLevel level,
            IEnumerable<string> steps)
        {
            return new UpgradeResponse
            {
                Success = false,
                isBlocked = true,
                Message = message,
                RequiredVerificationLevel = level.ToString(),
                RequiredSteps = new List<string>(steps),
                RequiresTokenRefresh = false
            };
        }

        public static UpgradeResponse Failed(string message)
        {
            return new UpgradeResponse
            {
                Success = false,
                isBlocked = false,
                Message = message,
                RequiresTokenRefresh = false
            };
        }

        public static UpgradeResponse Successful(string tier)
        {
            return new UpgradeResponse
            {
                Success = true,
                isBlocked = false,
                Message = "Subscription upgraded successfully",
                ActivatedTier = tier,
                RequiresTokenRefresh = true
            };
        }
    }
}

#endregion

#region Controller

namespace KeiroGenesis.API.Controllers.V1
{
    using KeiroGenesis.API.Services;

    
    [Route("api/v1/billing")]
    [Authorize]
    public sealed class BillingController : ControllerBase
    {
        private readonly BillingService _service;

        public BillingController(BillingService service)
        {
            _service = service;
        }

        private Guid GetUserId()
            => Guid.Parse(
                User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? User.FindFirstValue("sub")
                ?? throw new UnauthorizedAccessException("User ID missing"));

        private Guid GetTenantId()
            => Guid.Parse(
                User.FindFirstValue("tenant_id")
                ?? throw new UnauthorizedAccessException("Tenant ID missing"));

        /// <summary>
        /// Attempts to upgrade the current tenant subscription.
        /// </summary>
        [HttpPost("upgrade")]
        public async Task<IActionResult> Upgrade([FromBody] UpgradeRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.TargetTier))
            {
                return BadRequest(new { message = "TargetTier is required" });
            }

            var result = await _service.AttemptUpgradeAsync(
                GetTenantId(),
                GetUserId(),
                request.TargetTier);

            if (result.Success)
                return Ok(result);

            if (result.isBlocked)
                return Conflict(result);

            return BadRequest(result);
        }
    }
}

#endregion
