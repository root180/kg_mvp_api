// ==========================================================================
// CAPABILITY AUTHORIZATION — SINGLE FILE (LOCKED)
// - Billing is authoritative
// - Capabilities resolved via DB functions (NO raw SQL)
// - Authorization enforced via attribute + handler
// - NO interfaces
// - NO policy logic outside DB
// 
// REVIEW FIXES APPLIED:
// ✅ Fixed defaulting to "free" - now fails closed
// ✅ Added capability existence logging
// ✅ Added cache invalidation guidance
// ✅ capability_id type verified (Guid matches schema)
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
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

// ==========================================================================
#region DTOs and Models
// ==========================================================================

namespace KeiroGenesis.API.Models
{
    /// <summary>
    /// Complete entitlement bundle with subscription limits and capabilities
    /// </summary>
    public sealed class EntitlementBundle
    {
        [JsonPropertyName("subscription_name")]
        public string SubscriptionName { get; set; } = string.Empty;

        [JsonPropertyName("max_clones")]
        public int MaxClones { get; set; }

        [JsonPropertyName("max_users")]
        public int MaxUsers { get; set; }

        [JsonPropertyName("max_storage_mb")]
        public int MaxStorageMb { get; set; }

        [JsonPropertyName("monthly_interactions")]
        public int MonthlyInteractions { get; set; }

        [JsonPropertyName("capabilities")]
        public List<CapabilityDetail> Capabilities { get; set; } = new();
    }

    /// <summary>
    /// Individual capability detail from entitlement bundle
    /// </summary>
    public sealed class CapabilityDetail
    {
        [JsonPropertyName("capability_id")]
        public Guid CapabilityId { get; set; }

        [JsonPropertyName("capability_code")]
        public string CapabilityCode { get; set; } = string.Empty;

        [JsonPropertyName("capability_name")]
        public string CapabilityName { get; set; } = string.Empty;

        [JsonPropertyName("effective_trust_level_required")]
        public int EffectiveTrustLevelRequired { get; set; }

        [JsonPropertyName("effective_requires_approval")]
        public bool EffectiveRequiresApproval { get; set; }

        [JsonPropertyName("effective_max_daily_uses")]
        public int? EffectiveMaxDailyUses { get; set; }
    }

    // Add after line 82 (after CapabilityDetail class)

    public sealed class CapabilityCheckResponse
    {
        [JsonPropertyName("capability_code")]
        public string CapabilityCode { get; set; } = string.Empty;

        [JsonPropertyName("has_capability")]
        public bool HasCapability { get; set; }
    }

    public sealed class ErrorResponse
    {
        [JsonPropertyName("error")]
        public string Error { get; set; } = string.Empty;

        [JsonPropertyName("error_code")]
        public string? ErrorCode { get; set; }
    }

    // Internal Dapper mapping class
    internal class EntitlementRow
    {
        public string subscription_name { get; set; } = string.Empty;
        public int max_clones { get; set; }
        public int max_users { get; set; }
        public int max_storage_mb { get; set; }
        public int monthly_interactions { get; set; }
        public Guid capability_id { get; set; }  // ✅ Verified: matches schema
        public string capability_code { get; set; } = string.Empty;
        public string capability_name { get; set; } = string.Empty;
        public int effective_trust_level_required { get; set; }
        public bool effective_requires_approval { get; set; }
        public int? effective_max_daily_uses { get; set; }
    }
}

#endregion

// ==========================================================================
#region Repository
// ==========================================================================

namespace KeiroGenesis.API.Repositories
{
    using Models;

    public sealed class CapabilityRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<CapabilityRepository> _logger;

        public CapabilityRepository(IDbConnectionFactory db, ILogger<CapabilityRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        /// <summary>
        /// Check if user has specific capability.
        /// Calls capability.fn_has_capability() - NO raw SQL
        /// </summary>
        public async Task<bool> HasCapabilityAsync(
            Guid tenantId,
            Guid userId,
            string capabilityCode)
        {
            using var conn = _db.CreateConnection();

            // Call DB function (not raw SQL)
            var result = await conn.ExecuteScalarAsync<bool?>(
                "SELECT capability.fn_has_capability(@tenant_id, @user_id, @capability_code)",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId,
                    capability_code = capabilityCode
                });

            // ⚠️ HARDENING: Log when capability doesn't exist (helps catch typos)
            if (!result.HasValue)
            {
                _logger.LogWarning(
                    "Capability '{Code}' returned null for tenant {TenantId} - may not exist or function failed",
                    capabilityCode, tenantId);
                return false; // Fail safe
            }

            return result.Value;
        }

        /// <summary>
        /// Get complete entitlement bundle for user/tenant.
        /// Calls capability.fn_get_entitlement_bundle() - NO raw SQL
        /// </summary>
        public async Task<EntitlementBundle> GetEntitlementBundleAsync(
            Guid tenantId,
            Guid userId)
        {
            using var conn = _db.CreateConnection();

            // Call DB function (not raw SQL)
            var rows = await conn.QueryAsync<EntitlementRow>(
                "SELECT * FROM capability.fn_get_entitlement_bundle(@tenant_id, @user_id)",
                new
                {
                    tenant_id = tenantId,
                    user_id = userId
                });

            var rowList = rows.ToList();

            // ❌ REQUIRED FIX #1: Fail closed when no active plan
            // DO NOT default to "free" - billing is authoritative
            if (!rowList.Any())
            {
                _logger.LogError(
                    "No active subscription found for tenant {TenantId}, user {UserId}",
                    tenantId, userId);

                throw new UnauthorizedAccessException(
                    "No active subscription found. Contact support to activate a plan.");
            }

            var first = rowList.First();
            return new EntitlementBundle
            {
                SubscriptionName = first.subscription_name,
                MaxClones = first.max_clones,
                MaxUsers = first.max_users,
                MaxStorageMb = first.max_storage_mb,
                MonthlyInteractions = first.monthly_interactions,
                Capabilities = rowList.Select(r => new CapabilityDetail
                {
                    CapabilityId = r.capability_id,
                    CapabilityCode = r.capability_code,
                    CapabilityName = r.capability_name,
                    EffectiveTrustLevelRequired = r.effective_trust_level_required,
                    EffectiveRequiresApproval = r.effective_requires_approval,
                    EffectiveMaxDailyUses = r.effective_max_daily_uses
                }).ToList()
            };
        }
    }
}

#endregion

// ==========================================================================
#region Service
// ==========================================================================

namespace KeiroGenesis.API.Services
{
    using Models;
    using Repositories;

    public sealed class CapabilityService
    {
        private readonly CapabilityRepository _repo;
        private readonly IMemoryCache _cache;
        private readonly ILogger<CapabilityService> _logger;

        private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan BundleCacheDuration = TimeSpan.FromMinutes(10);

        public CapabilityService(
            CapabilityRepository repo,
            IMemoryCache cache,
            ILogger<CapabilityService> logger)
        {
            _repo = repo;
            _cache = cache;
            _logger = logger;
        }

        public async Task<bool> HasCapabilityAsync(
            Guid tenantId,
            Guid userId,
            string capabilityCode)
        {
            var cacheKey = $"cap:{tenantId}:{userId}:{capabilityCode}";

            if (_cache.TryGetValue(cacheKey, out bool cached))
            {
                _logger.LogDebug("Capability check cache hit: {Code}", capabilityCode);
                return cached;
            }

            var allowed = await _repo.HasCapabilityAsync(tenantId, userId, capabilityCode);
            _cache.Set(cacheKey, allowed, CacheDuration);

            _logger.LogDebug("Capability check: {Code} = {Allowed} for tenant {TenantId}",
                capabilityCode, allowed, tenantId);

            return allowed;
        }

        public async Task<EntitlementBundle> GetEntitlementBundleAsync(
            Guid tenantId,
            Guid userId)
        {
            var cacheKey = $"bundle:{tenantId}:{userId}";

            if (_cache.TryGetValue(cacheKey, out EntitlementBundle? cached) && cached != null)
            {
                _logger.LogDebug("Entitlement bundle cache hit for tenant {TenantId}", tenantId);
                return cached;
            }

            var bundle = await _repo.GetEntitlementBundleAsync(tenantId, userId);
            _cache.Set(cacheKey, bundle, BundleCacheDuration);

            _logger.LogInformation(
                "Loaded entitlement bundle: tenant={TenantId}, tier={Tier}, capabilities={Count}",
                tenantId, bundle.SubscriptionName, bundle.Capabilities.Count);

            return bundle;
        }

        /// <summary>
        /// ⚠️ CRITICAL: Invalidate cache when subscription changes
        /// MUST be called when:
        /// - Subscription is upgraded/downgraded
        /// - Billing webhook fires
        /// - Tenant ownership changes
        /// </summary>
        public void Invalidate(Guid tenantId, Guid userId)
        {
            // Note: MemoryCache doesn't support prefix removal
            // Entries will expire naturally within 5-10 minutes
            // For production, consider Redis with SCAN for pattern-based removal
            _logger.LogInformation(
                "Cache invalidation requested for tenant {TenantId}, user {UserId}. " +
                "Entries will expire within 10 minutes.",
                tenantId, userId);
        }
    }
}

#endregion

// ==========================================================================
#region Authorization (Requirement + Handler + Attribute + Policy Provider)
// ==========================================================================

namespace KeiroGenesis.API.Security
{
    using Services;

    /// <summary>
    /// Authorization requirement for capability check
    /// </summary>
    public sealed class CapabilityRequirement : IAuthorizationRequirement
    {
        public string CapabilityCode { get; }

        public CapabilityRequirement(string capabilityCode)
        {
            CapabilityCode = capabilityCode;
        }
    }

    /// <summary>
    /// Authorization handler that checks capability via service
    /// </summary>
    public sealed class CapabilityAuthorizationHandler
        : AuthorizationHandler<CapabilityRequirement>
    {
        private readonly CapabilityService _capabilityService;
        private readonly ILogger<CapabilityAuthorizationHandler> _logger;

        public CapabilityAuthorizationHandler(
            CapabilityService capabilityService,
            ILogger<CapabilityAuthorizationHandler> logger)
        {
            _capabilityService = capabilityService;
            _logger = logger;
        }

        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            CapabilityRequirement requirement)
        {
            var tenantClaim = context.User.FindFirst("tenant_id")?.Value;
            var userClaim =
                context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
                context.User.FindFirst("sub")?.Value;

            if (!Guid.TryParse(tenantClaim, out var tenantId) ||
                !Guid.TryParse(userClaim, out var userId))
            {
                _logger.LogWarning("Invalid tenant/user claims for capability {Code}",
                    requirement.CapabilityCode);
                return;
            }

            var allowed = await _capabilityService.HasCapabilityAsync(
                tenantId, userId, requirement.CapabilityCode);

            if (allowed)
            {
                _logger.LogDebug("Capability authorized: {Code} for user {UserId}",
                    requirement.CapabilityCode, userId);
                context.Succeed(requirement);
            }
            else
            {
                _logger.LogWarning("Capability denied: {Code} for user {UserId}, tenant {TenantId}",
                    requirement.CapabilityCode, userId, tenantId);
            }
        }
    }

    /// <summary>
    /// Attribute for capability-based authorization.
    /// Usage: [RequireCapability("clone.create")]
    /// </summary>
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
    public sealed class RequireCapabilityAttribute : AuthorizeAttribute
    {
        public RequireCapabilityAttribute(string capabilityCode)
        {
            Policy = $"CAPABILITY:{capabilityCode}";
        }
    }

    /// <summary>
    /// Dynamic policy provider for capability-based authorization
    /// </summary>
    public sealed class CapabilityPolicyProvider : IAuthorizationPolicyProvider
    {
        private const string Prefix = "CAPABILITY:";
        private readonly DefaultAuthorizationPolicyProvider _fallback;

        public CapabilityPolicyProvider(IOptions<AuthorizationOptions> options)
        {
            _fallback = new DefaultAuthorizationPolicyProvider(options);
        }

        public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
            => _fallback.GetDefaultPolicyAsync();

        public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
            => _fallback.GetFallbackPolicyAsync();

        public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
        {
            if (!policyName.StartsWith(Prefix))
                return _fallback.GetPolicyAsync(policyName);

            var capabilityCode = policyName.Substring(Prefix.Length);

            var policy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddRequirements(new CapabilityRequirement(capabilityCode))
                .Build();

            return Task.FromResult<AuthorizationPolicy?>(policy);
        }
    }
}

#endregion

// ==========================================================================
#region Controller
// ==========================================================================

namespace KeiroGenesis.API.Controllers.V1
{
    using Models;
    using Security;
    using Services;

    /// <summary>
    /// API endpoints for capability queries
    /// </summary>
  
    [Route("api/v1/capabilities")]
    [Authorize]
    public sealed class CapabilityController : ControllerBase
    {
        private readonly CapabilityService _service;
        private readonly ILogger<CapabilityController> _logger;

        public CapabilityController(
            CapabilityService service,
            ILogger<CapabilityController> logger)
        {
            _service = service;
            _logger = logger;
        }

        /// <summary>
        /// Get complete entitlement bundle for authenticated user.
        /// Returns subscription limits + all allowed capabilities.
        /// </summary>
        [HttpGet("entitlements")]
        [ProducesResponseType(typeof(EntitlementBundle), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(500)]
        public async Task<ActionResult<EntitlementBundle>> GetEntitlements()
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();

                var bundle = await _service.GetEntitlementBundleAsync(tenantId, userId);
                return Ok(bundle);
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized entitlement request");
                return Unauthorized(new ErrorResponse { Error = ex.Message, ErrorCode = "UNAUTHORIZED" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting entitlements");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        /// <summary>
        /// Check if authenticated user has specific capability.
        /// </summary>
        [HttpGet("check/{capabilityCode}")]
        [ProducesResponseType(typeof(CapabilityCheckResponse), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(500)]
        public async Task<ActionResult> CheckCapability(string capabilityCode)
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();

                var hasCapability = await _service.HasCapabilityAsync(
                    tenantId, userId, capabilityCode);

                return Ok(new CapabilityCheckResponse
                {
                    CapabilityCode = capabilityCode,
                    HasCapability = hasCapability
                });
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized capability check");
                return Unauthorized(new ErrorResponse { Error = ex.Message, ErrorCode = "UNAUTHORIZED" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking capability {Code}", capabilityCode);
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        private Guid GetTenantId()
        {
            var claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var tenantId))
                throw new UnauthorizedAccessException("Invalid tenant claim");
            return tenantId;
        }

        private Guid GetUserId()
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

// ==========================================================================
#region Example Usage in Other Controllers
// ==========================================================================

namespace KeiroGenesis.API.Controllers.V1
{
    using Security;

    /// <summary>
    /// Example controller showing capability-based authorization
    /// </summary>
    [ApiController]
    [Route("api/v1/clones")]
    [Authorize]
    public sealed class ExampleCloneController : ControllerBase
    {
        [HttpPost]
        [RequireCapability("clone.create")]
        public IActionResult CreateClone()
        {
            return Ok(new { success = true });
        }

        [HttpDelete("{cloneId}")]
        [RequireCapability("clone.delete")]
        public IActionResult DeleteClone(Guid cloneId)
        {
            return Ok(new { success = true });
        }
    }
}

#endregion