// ============================================================================
// KeiroGenesis.Identity - Identity Verification Module (MVP)
// ----------------------------------------------------------------------------
// Organized with proper namespace separation:
// - KeiroGenesis.Identity (Shared models, enums, interfaces)
// - KeiroGenesis.API.Repositories (Repository layer)
// - KeiroGenesis.API.Services (Service layer)
// - KeiroGenesis.API.Controllers.V1 (Controller layer)
// ============================================================================

using Dapper;
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
using System.Text.Json;
using System.Threading.Tasks;

// ============================================================================
// SHARED NAMESPACE: Models, Enums, Interfaces, Core Logic
// ============================================================================

namespace KeiroGenesis.Identity
{
    // =========================================================================
    // IDENTITY SIGNAL CORE (NO DECISIONS)
    // =========================================================================

    public static class IdentitySignalCore
    {
        public static IdentitySignalSnapshot Normalize(IdentitySignalSnapshot snapshot)
        {
            snapshot.VerificationLevel = snapshot.VerificationLevel < IdentityVerificationLevel.Unverified
                ? IdentityVerificationLevel.Unverified
                : snapshot.VerificationLevel;

            snapshot.AgeCategory ??= AgeVerificationResult.Unknown;

            snapshot.AgeVerified = snapshot.VerificationLevel >= IdentityVerificationLevel.AgeAssured
                ? true
                : snapshot.AgeVerified;

            snapshot.HumanVerified = snapshot.VerificationLevel >= IdentityVerificationLevel.HumanVerified
                ? true
                : snapshot.HumanVerified;

            snapshot.GovernmentIDVerified = snapshot.VerificationLevel >= IdentityVerificationLevel.GovernmentVerified
                ? true
                : snapshot.GovernmentIDVerified;

            if (snapshot.ExpiresAt.HasValue && snapshot.ExpiresAt.Value <= DateTime.UtcNow)
            {
                snapshot.RequiresReverification = true;
                snapshot.ReverificationReason ??= "Verification expired";
            }

            return snapshot;
        }

        public static IdentitySignalEvent CreateInitializationEvent(Guid tenantId, Guid userId)
            => new IdentitySignalEvent
            {
                TenantId = tenantId,
                UserId = userId,
                EventType = IdentitySignalEventType.ProfileInitialized,
                OccurredAtUtc = DateTime.UtcNow,
                PayloadJson = JsonSerializer.Serialize(new { initialized = true })
            };
    }

    // =========================================================================
    // CORE MODELS
    // =========================================================================

    public sealed class IdentitySignalSnapshot
    {
        public Guid TenantId { get; set; }
        public Guid UserId { get; set; }
        public IdentityVerificationLevel VerificationLevel { get; set; } = IdentityVerificationLevel.Unverified;
        public bool AgeVerified { get; set; }
        public AgeVerificationResult? AgeCategory { get; set; } = AgeVerificationResult.Unknown;
        public bool HumanVerified { get; set; }
        public bool GovernmentIDVerified { get; set; }
        public DateTime? VerifiedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool RequiresReverification { get; set; }
        public string? ReverificationReason { get; set; }
    }

    public sealed class IdentitySignalEvent
    {
        public Guid TenantId { get; set; }
        public Guid UserId { get; set; }
        public IdentitySignalEventType EventType { get; set; }
        public DateTime OccurredAtUtc { get; set; }
        public string PayloadJson { get; set; } = "{}";
    }

    // =========================================================================
    // DATABASE MODELS
    // =========================================================================

    public sealed class IdentityProfile
    {
        public Guid IdentityProfileId { get; set; }
        public Guid TenantId { get; set; }
        public Guid UserId { get; set; }
        public IdentityVerificationLevel VerificationLevel { get; set; }
        public bool AgeVerified { get; set; }
        public AgeVerificationResult AgeCategory { get; set; }
        public DateTime? VerifiedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool RequiresReverification { get; set; }
        public string? ReverificationReason { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }

    public sealed class ConsentRecord
    {
        public Guid ConsentRecordId { get; set; }
        public Guid TenantId { get; set; }
        public Guid IdentityProfileId { get; set; }
        public Guid UserId { get; set; }
        public ConsentType ConsentType { get; set; }
        public bool Granted { get; set; }
        public string PolicyVersion { get; set; } = string.Empty;
        public string ConsentText { get; set; } = string.Empty;
        public DateTime ConsentedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool Revoked { get; set; }
        public DateTime? RevokedAt { get; set; }
    }

    public sealed class VerificationAttempt
    {
        public Guid VerificationAttemptId { get; set; }
        public Guid TenantId { get; set; }
        public Guid IdentityProfileId { get; set; }
        public Guid UserId { get; set; }
        public VerificationMethod Method { get; set; }
        public VerificationStatus Status { get; set; }
        public VerificationProvider? Provider { get; set; }
        public decimal? ConfidenceScore { get; set; }
        public bool FraudAlertTriggered { get; set; }
        public DateTime InitiatedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public string? FailureReason { get; set; }
    }

    // =========================================================================
    // API CONTRACTS (DTOs)
    // =========================================================================

    public sealed class IdentityStatusResponse
    {
        public Guid UserId { get; set; }
        public bool ProfileExists { get; set; }
        public IdentityVerificationLevel VerificationLevel { get; set; }
        public bool AgeVerified { get; set; }
        public AgeVerificationResult AgeCategory { get; set; }
        public bool HumanVerified { get; set; }
        public bool GovernmentIDVerified { get; set; }
        public DateTime? VerifiedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool RequiresReverification { get; set; }
        public string? ReverificationReason { get; set; }
    }

    public sealed class ConsentRequest
    {
        public ConsentType ConsentType { get; set; }
        public bool Granted { get; set; }
        public string PolicyVersion { get; set; } = string.Empty;
        public string? ConsentText { get; set; }
    }

    public sealed class ConsentResponse
    {
        public Guid Id { get; set; }
        public ConsentType ConsentType { get; set; }
        public bool Granted { get; set; }
        public string PolicyVersion { get; set; } = string.Empty;
        public DateTime ConsentedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool Revoked { get; set; }
        public DateTime? RevokedAt { get; set; }
    }

    public sealed class VerificationAttemptResponse
    {
        public Guid Id { get; set; }
        public VerificationMethod Method { get; set; }
        public VerificationStatus Status { get; set; }
        public VerificationProvider? Provider { get; set; }
        public decimal? ConfidenceScore { get; set; }
        public bool FraudAlertTriggered { get; set; }
        public DateTime InitiatedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public string? FailureReason { get; set; }
    }

    // =========================================================================
    // AUTHORIZATION BOUNDARY (Interface only - implementation elsewhere)
    // =========================================================================

    public interface IAuthorizationDecisionService
    {
        Task<AuthorizationDecision> DecideAsync(AuthorizationDecisionRequest request);
    }

    public sealed class AuthorizationDecisionRequest
    {
        public Guid TenantId { get; set; }
        public Guid UserId { get; set; }
        public string Action { get; set; } = string.Empty;
        public Dictionary<string, string>? Context { get; set; }
        public IdentitySignalSnapshot IdentitySignals { get; set; } = new IdentitySignalSnapshot();
    }

    public sealed class AuthorizationDecision
    {
        public bool Allowed { get; set; }
        public string Reason { get; set; } = string.Empty;
        public List<string>? RequiredSteps { get; set; }
    }

    // =========================================================================
    // ENUMS
    // =========================================================================

    public enum IdentitySignalEventType
    {
        ProfileInitialized = 1,
        ConsentRecorded = 2,
        VerificationAttemptCreated = 3,
        VerificationAttemptUpdated = 4,
        VerificationLevelUpdated = 5
    }

    public enum IdentityVerificationLevel
    {
        Unverified = 0,
        AgeAssured = 1,
        HumanVerified = 2,
        GovernmentVerified = 3
    }

    public enum VerificationMethod
    {
        None = 0,
        AIAgeEstimation = 1,
        ZeroKnowledgeAgeProof = 2,
        LivenessSelfie = 3,
        GovernmentID = 4,
        DigitalWalletID = 5,
        ThirdPartyKYC = 6
    }

    public enum VerificationStatus
    {
        Pending = 0,
        InProgress = 1,
        Verified = 2,
        Failed = 3,
        Expired = 4,
        ManuallyApproved = 5,
        ManuallyRejected = 6
    }

    public enum AgeVerificationResult
    {
        Unknown = 0,
        Minor = 1,
        Adult = 2,
        Inconclusive = 3
    }

    public enum ConsentType
    {
        AgeVerification = 1,
        BiometricProcessing = 2,
        GovernmentIDVerification = 3,
        ThirdPartySharing = 4,
        LongTermRetention = 5
    }

    public enum VerificationProvider
    {
        Internal = 0,
        Jumio = 1,
        IDMERIT = 2,
        Onfido = 3,
        Yoti = 4,
        StripeIdentity = 5,
        Custom = 99
    }

    public enum IdentityGatedFeature
    {
        PublicCloneVisibility = 1,
        VisitorChat = 2,
        FamilyInvitations = 3,
        Monetization = 4,
        IoTControl = 5,
        PosthumousAccess = 6,
        CloneMarketplace = 7,
        RevenuePayouts = 8
    }

    // =========================================================================
    // DORMANT V2/V3 TYPES
    // =========================================================================

#if KEIRO_FUTURE
    public sealed class AgeVerificationRequest
    {
        public bool ConsentGiven { get; set; }
        public string PolicyVersion { get; set; } = string.Empty;
        public VerificationMethod Method { get; set; } = VerificationMethod.AIAgeEstimation;
    }

    public sealed class HumanVerificationRequest
    {
        public bool ConsentGiven { get; set; }
        public string PolicyVersion { get; set; } = string.Empty;
    }

    public sealed class GovernmentIDVerificationRequest
    {
        public bool ConsentGiven { get; set; }
        public string PolicyVersion { get; set; } = string.Empty;
    }

    public sealed class VerificationWebhookPayload
    {
        public string? ProviderTransactionId { get; set; }
        public VerificationStatus Status { get; set; }
        public decimal? ConfidenceScore { get; set; }
        public bool FraudDetected { get; set; }
        public DateTime? CompletedAt { get; set; }
        public string? FailureReason { get; set; }
        public object? VerificationData { get; set; }
    }

    public sealed class FeatureAccessRequest
    {
        public IdentityGatedFeature Feature { get; set; }
    }

    public sealed class FeatureAccessResponse
    {
        public IdentityGatedFeature Feature { get; set; }
        public bool Allowed { get; set; }
        public IdentityVerificationLevel RequiredLevel { get; set; }
        public IdentityVerificationLevel CurrentLevel { get; set; }
        public string Message { get; set; } = string.Empty;
        public List<string>? NextSteps { get; set; }
    }

    public sealed class VerificationStatsResponse
    {
        public int TotalAttempts { get; set; }
        public int VerifiedCount { get; set; }
        public int FailedCount { get; set; }
        public int FraudFlaggedCount { get; set; }
    }
#endif
}

// ============================================================================
// REPOSITORY NAMESPACE
// ============================================================================

namespace KeiroGenesis.API.Repositories
{
    using KeiroGenesis.Identity;

    public class IdentitySignalsRepository
    {
        private readonly NpgsqlDataSource _dataSource;

        public IdentitySignalsRepository(NpgsqlDataSource dataSource)
        {
            _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
        }

        private NpgsqlConnection CreateConnection()
            => _dataSource.CreateConnection();

        // ============================================================
        // IDENTITY SNAPSHOT
        // ============================================================

        public async Task<IdentitySignalSnapshot?> GetIdentitySnapshotAsync(Guid tenantId, Guid userId)
        {
            using var conn = CreateConnection();

            var profile = await conn.QueryFirstOrDefaultAsync<IdentityProfile>(
                "SELECT * FROM auth.fn_get_identity_profile_by_user(@tenant_id, @user_id)",
                new { tenant_id = tenantId, user_id = userId }
            );

            if (profile == null)
                return null;

            return new IdentitySignalSnapshot
            {
                TenantId = profile.TenantId,
                UserId = profile.UserId,
                VerificationLevel = profile.VerificationLevel,
                AgeVerified = profile.AgeVerified,
                AgeCategory = profile.AgeCategory,
                HumanVerified = false,
                GovernmentIDVerified = false,
                VerifiedAt = profile.VerifiedAt,
                ExpiresAt = profile.ExpiresAt,
                RequiresReverification = profile.RequiresReverification,
                ReverificationReason = profile.ReverificationReason
            };
        }

        public async Task<bool> IdentityProfileExistsAsync(Guid tenantId, Guid userId)
        {
            using var conn = CreateConnection();

            var profile = await conn.QueryFirstOrDefaultAsync<IdentityProfile>(
                "SELECT * FROM auth.fn_get_identity_profile_by_user(@tenant_id, @user_id)",
                new { tenant_id = tenantId, user_id = userId }
            );

            return profile != null;
        }

        // ============================================================
        // IDENTITY PROFILE
        // ============================================================

        public async Task<Guid> CreateIdentityProfileAsync(Guid tenantId, Guid userId)
        {
            using var conn = CreateConnection();

            return await conn.ExecuteScalarAsync<Guid>(
                "SELECT auth.fn_create_identity_profile(@tenant_id, @user_id)",
                new { tenant_id = tenantId, user_id = userId }
            );
        }

        // ============================================================
        // CONSENT RECORDS
        // ============================================================

        public async Task<Guid> CreateConsentRecordAsync(
            Guid tenantId,
            Guid userId,
            ConsentRequest request)
        {
            using var conn = CreateConnection();

            var profile = await conn.QueryFirstOrDefaultAsync<IdentityProfile>(
                "SELECT * FROM auth.fn_get_identity_profile_by_user(@tenant_id, @user_id)",
                new { tenant_id = tenantId, user_id = userId }
            );

            if (profile == null)
                throw new InvalidOperationException("Identity profile not found");

            return await conn.ExecuteScalarAsync<Guid>(
                @"SELECT auth.fn_create_consent_record(
                    @tenant_id, @identity_profile_id, @user_id,
                    @consent_type::auth.consent_type,
                    @granted, @policy_version,
                    @consent_text, NULL, NULL, NULL
                )",
                new
                {
                    tenant_id = tenantId,
                    identity_profile_id = profile.IdentityProfileId,
                    user_id = userId,
                    consent_type = request.ConsentType.ToString(),
                    granted = request.Granted,
                    policy_version = request.PolicyVersion,
                    consent_text = request.ConsentText ?? $"User consent for {request.ConsentType}"
                }
            );
        }

        public async Task<List<ConsentRecord>> GetConsentRecordsAsync(Guid tenantId, Guid userId)
        {
            using var conn = CreateConnection();

            var result = await conn.QueryAsync<ConsentRecord>(
                "SELECT * FROM auth.fn_get_consent_records_by_user(@tenant_id, @user_id)",
                new { tenant_id = tenantId, user_id = userId }
            );

            return result.ToList();
        }

        // ============================================================
        // VERIFICATION ATTEMPTS
        // ============================================================

        public async Task<List<VerificationAttempt>> GetVerificationAttemptsAsync(
            Guid tenantId,
            Guid userId,
            int limit)
        {
            using var conn = CreateConnection();

            var result = await conn.QueryAsync<VerificationAttempt>(
                "SELECT * FROM auth.fn_get_verification_attempts_by_user(@tenant_id, @user_id, @limit)",
                new { tenant_id = tenantId, user_id = userId, limit }
            );

            return result.ToList();
        }
    }
}

// ============================================================================
// SERVICE NAMESPACE
// ============================================================================

namespace KeiroGenesis.API.Services
{
    using KeiroGenesis.API.Repositories;
    using KeiroGenesis.Identity;

    public class IdentitySignalsService
    {
        private readonly IdentitySignalsRepository _repo;
        private readonly ILogger<IdentitySignalsService> _logger;

        public IdentitySignalsService(
            IdentitySignalsRepository repo,
            ILogger<IdentitySignalsService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<IdentityStatusResponse> GetStatusAsync(Guid tenantId, Guid userId)
        {
            var snapshot = await _repo.GetIdentitySnapshotAsync(tenantId, userId);

            if (snapshot == null)
            {
                var empty = new IdentitySignalSnapshot
                {
                    TenantId = tenantId,
                    UserId = userId,
                    VerificationLevel = IdentityVerificationLevel.Unverified,
                    AgeVerified = false,
                    AgeCategory = AgeVerificationResult.Unknown,
                    HumanVerified = false,
                    GovernmentIDVerified = false
                };
                empty = IdentitySignalCore.Normalize(empty);
                return MapToStatusResponse(empty, profileExists: false);
            }

            snapshot = IdentitySignalCore.Normalize(snapshot);
            return MapToStatusResponse(snapshot, profileExists: true);
        }

        public async Task<IdentityStatusResponse> InitializeAsync(Guid tenantId, Guid userId)
        {
            var exists = await _repo.IdentityProfileExistsAsync(tenantId, userId);
            if (!exists)
            {
                await _repo.CreateIdentityProfileAsync(tenantId, userId);
                var evt = IdentitySignalCore.CreateInitializationEvent(tenantId, userId);
                _logger.LogInformation("Identity profile initialized: {Event}", JsonSerializer.Serialize(evt));
            }
            else
            {
                _logger.LogInformation("Identity profile already exists for user {UserId} in tenant {TenantId}", userId, tenantId);
            }

            return await GetStatusAsync(tenantId, userId);
        }

        public async Task<ConsentResponse> RecordConsentAsync(Guid tenantId, Guid userId, ConsentRequest request)
        {
            var exists = await _repo.IdentityProfileExistsAsync(tenantId, userId);
            if (!exists)
            {
                await _repo.CreateIdentityProfileAsync(tenantId, userId);
                var evt = IdentitySignalCore.CreateInitializationEvent(tenantId, userId);
                _logger.LogInformation("Identity profile auto-created during consent: {Event}", JsonSerializer.Serialize(evt));
            }

            var consentId = await _repo.CreateConsentRecordAsync(tenantId, userId, request);

            var consentEvent = new IdentitySignalEvent
            {
                TenantId = tenantId,
                UserId = userId,
                EventType = IdentitySignalEventType.ConsentRecorded,
                OccurredAtUtc = DateTime.UtcNow,
                PayloadJson = JsonSerializer.Serialize(new
                {
                    consentType = request.ConsentType.ToString(),
                    granted = request.Granted,
                    policyVersion = request.PolicyVersion
                })
            };
            _logger.LogInformation("Consent recorded: {Event}", JsonSerializer.Serialize(consentEvent));

            return new ConsentResponse
            {
                Id = consentId,
                ConsentType = request.ConsentType,
                Granted = request.Granted,
                PolicyVersion = request.PolicyVersion,
                ConsentedAt = DateTime.UtcNow,
                Revoked = false
            };
        }

        public async Task<List<ConsentResponse>> GetConsentsAsync(Guid tenantId, Guid userId)
        {
            var consents = await _repo.GetConsentRecordsAsync(tenantId, userId);
            return consents.Select(c => new ConsentResponse
            {
                Id = c.ConsentRecordId,
                ConsentType = c.ConsentType,
                Granted = c.Granted,
                PolicyVersion = c.PolicyVersion,
                ConsentedAt = c.ConsentedAt,
                ExpiresAt = c.ExpiresAt,
                Revoked = c.Revoked,
                RevokedAt = c.RevokedAt
            }).ToList();
        }

        public async Task<List<VerificationAttemptResponse>> GetHistoryAsync(Guid tenantId, Guid userId, int limit)
        {
            var attempts = await _repo.GetVerificationAttemptsAsync(tenantId, userId, limit);
            return attempts.Select(a => new VerificationAttemptResponse
            {
                Id = a.VerificationAttemptId,
                Method = a.Method,
                Status = a.Status,
                Provider = a.Provider,
                ConfidenceScore = a.ConfidenceScore,
                FraudAlertTriggered = a.FraudAlertTriggered,
                InitiatedAt = a.InitiatedAt,
                CompletedAt = a.CompletedAt,
                FailureReason = a.FailureReason
            }).ToList();
        }

        private static IdentityStatusResponse MapToStatusResponse(IdentitySignalSnapshot s, bool profileExists)
            => new IdentityStatusResponse
            {
                UserId = s.UserId,
                ProfileExists = profileExists,
                VerificationLevel = s.VerificationLevel,
                AgeVerified = s.AgeVerified,
                AgeCategory = s.AgeCategory ?? AgeVerificationResult.Unknown,
                HumanVerified = s.HumanVerified,
                GovernmentIDVerified = s.GovernmentIDVerified,
                VerifiedAt = s.VerifiedAt,
                ExpiresAt = s.ExpiresAt,
                RequiresReverification = s.RequiresReverification,
                ReverificationReason = s.ReverificationReason
            };
    }
}

// ============================================================================
// CONTROLLER NAMESPACE
// ============================================================================

namespace KeiroGenesis.API.Controllers.V1
{
    using KeiroGenesis.API.Services;
    using KeiroGenesis.Identity;

    [ApiController]
    [Route("api/v1/auth/identity")]
    [Produces("application/json")]
    public class IdentitySignalsController : ControllerBase
    {
        private readonly IdentitySignalsService _service;
        private readonly ILogger<IdentitySignalsController> _logger;

        public IdentitySignalsController(
            IdentitySignalsService service,
            ILogger<IdentitySignalsController> logger)
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
        /// Get current identity verification status
        /// </summary>
        [HttpGet("status")]
        [Authorize]
        public async Task<ActionResult<IdentityStatusResponse>> GetStatus()
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();
                var result = await _service.GetStatusAsync(tenantId, userId);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting identity status");
                return StatusCode(500, new { message = "Failed to retrieve identity status" });
            }
        }

        /// <summary>
        /// Initialize identity profile for current user
        /// </summary>
        [HttpPost("initialize")]
        [Authorize]
        public async Task<ActionResult<IdentityStatusResponse>> Initialize()
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();
                var result = await _service.InitializeAsync(tenantId, userId);
                return CreatedAtAction(nameof(GetStatus), result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing identity profile");
                return StatusCode(500, new { message = "Failed to initialize identity profile" });
            }
        }

        /// <summary>
        /// Record user consent
        /// </summary>
        [HttpPost("consent")]
        [Authorize]
        public async Task<ActionResult<ConsentResponse>> RecordConsent([FromBody] ConsentRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.PolicyVersion))
                    return BadRequest(new { message = "PolicyVersion is required" });

                var tenantId = GetTenantId();
                var userId = GetUserId();
                var result = await _service.RecordConsentAsync(tenantId, userId, request);
                return CreatedAtAction(nameof(GetConsents), result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error recording consent");
                return StatusCode(500, new { message = "Failed to record consent" });
            }
        }

        /// <summary>
        /// Get consent history
        /// </summary>
        [HttpGet("consent")]
        [Authorize]
        public async Task<ActionResult<List<ConsentResponse>>> GetConsents()
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();
                var result = await _service.GetConsentsAsync(tenantId, userId);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving consent records");
                return StatusCode(500, new { message = "Failed to retrieve consent records" });
            }
        }

        /// <summary>
        /// Get verification attempt history
        /// </summary>
        [HttpGet("history")]
        [Authorize]
        public async Task<ActionResult<List<VerificationAttemptResponse>>> GetHistory([FromQuery] int limit = 10)
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();
                var result = await _service.GetHistoryAsync(tenantId, userId, limit);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving identity history");
                return StatusCode(500, new { message = "Failed to retrieve identity history" });
            }
        }
    }
}