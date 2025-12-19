// ============================================================================
// MOCK VERIFICATION ENDPOINTS FOR MVP (Auto-Verify Mode)
// ----------------------------------------------------------------------------
// Add these endpoints to IdentitySignalsController for MVP testing.
// Everyone gets auto-verified, but the flow is complete and testable.
// Remove/disable these when integrating real verification providers.
// ============================================================================

namespace KeiroGenesis.API.Controllers.V1
{
    using KeiroGenesis.API.Services;
    using KeiroGenesis.Identity;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;

    // Add these methods to your existing IdentitySignalsController class

    public partial class IdentitySignalsController
    {
        /// <summary>
        /// [MVP MOCK] Start age verification (auto-verifies to Adult in MVP)
        /// POST /api/v1/auth/identity/verify/age
        /// </summary>
        [HttpPost("verify/age")]
        [Authorize]
        public async Task<ActionResult<MockVerificationResult>> StartAgeVerification([FromBody] AgeVerificationRequest request)
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();

                _logger.LogInformation("MVP Mock: Auto-verifying age for user {UserId}", userId);

                // Create verification attempt record
                await _service.RecordVerificationAttemptAsync(
                    tenantId, 
                    userId,
                    VerificationMethod.AgeVerification,
                    VerificationStatus.Success,
                    VerificationProvider.MVPMock,
                    confidenceScore: 1.0m
                );

                // Update identity profile to AgeAssured
                await _service.UpdateVerificationLevelAsync(
                    tenantId, 
                    userId, 
                    IdentityVerificationLevel.AgeAssured,
                    AgeVerificationResult.Adult
                );

                return Ok(new MockVerificationResult
                {
                    Success = true,
                    Message = "[MVP MOCK] Age verification completed automatically",
                    VerificationLevel = IdentityVerificationLevel.AgeAssured,
                    AgeCategory = AgeVerificationResult.Adult,
                    IsMockData = true,
                    NextSteps = new List<string> 
                    { 
                        "Age verified as Adult",
                        "You can now proceed to human verification",
                        "NOTE: This is mock data for MVP testing"
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in mock age verification");
                return StatusCode(500, new { message = "Failed to complete age verification" });
            }
        }

        /// <summary>
        /// [MVP MOCK] Start human verification (auto-verifies in MVP)
        /// POST /api/v1/auth/identity/verify/human
        /// </summary>
        [HttpPost("verify/human")]
        [Authorize]
        public async Task<ActionResult<MockVerificationResult>> StartHumanVerification()
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();

                _logger.LogInformation("MVP Mock: Auto-verifying human for user {UserId}", userId);

                // Create verification attempt record
                await _service.RecordVerificationAttemptAsync(
                    tenantId,
                    userId,
                    VerificationMethod.HumanVerification,
                    VerificationStatus.Success,
                    VerificationProvider.MVPMock,
                    confidenceScore: 1.0m
                );

                // Update identity profile to HumanVerified
                await _service.UpdateVerificationLevelAsync(
                    tenantId,
                    userId,
                    IdentityVerificationLevel.HumanVerified,
                    null // Age category stays same
                );

                return Ok(new MockVerificationResult
                {
                    Success = true,
                    Message = "[MVP MOCK] Human verification completed automatically",
                    VerificationLevel = IdentityVerificationLevel.HumanVerified,
                    IsMockData = true,
                    NextSteps = new List<string>
                    {
                        "Human verification passed",
                        "You can now proceed to government ID verification",
                        "NOTE: This is mock data for MVP testing"
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in mock human verification");
                return StatusCode(500, new { message = "Failed to complete human verification" });
            }
        }

        /// <summary>
        /// [MVP MOCK] Start government ID verification (auto-verifies in MVP)
        /// POST /api/v1/auth/identity/verify/government-id
        /// </summary>
        [HttpPost("verify/government-id")]
        [Authorize]
        public async Task<ActionResult<MockVerificationResult>> StartGovernmentIDVerification([FromBody] GovernmentIDRequest request)
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();

                _logger.LogInformation("MVP Mock: Auto-verifying government ID for user {UserId}", userId);

                // Validate that they've completed human verification first
                var status = await _service.GetStatusAsync(tenantId, userId);
                if (status.VerificationLevel < IdentityVerificationLevel.HumanVerified)
                {
                    return BadRequest(new 
                    { 
                        message = "Must complete human verification before government ID verification",
                        currentLevel = status.VerificationLevel.ToString()
                    });
                }

                // Create verification attempt record
                await _service.RecordVerificationAttemptAsync(
                    tenantId,
                    userId,
                    VerificationMethod.GovernmentID,
                    VerificationStatus.Success,
                    VerificationProvider.MVPMock,
                    confidenceScore: 1.0m
                );

                // Update identity profile to GovernmentVerified
                await _service.UpdateVerificationLevelAsync(
                    tenantId,
                    userId,
                    IdentityVerificationLevel.GovernmentVerified,
                    AgeVerificationResult.Adult // Ensure adult status
                );

                return Ok(new MockVerificationResult
                {
                    Success = true,
                    Message = "[MVP MOCK] Government ID verification completed automatically",
                    VerificationLevel = IdentityVerificationLevel.GovernmentVerified,
                    AgeCategory = AgeVerificationResult.Adult,
                    IsMockData = true,
                    MockIDInfo = new 
                    {
                        IdType = request.IdType,
                        Country = request.Country ?? "US",
                        DocumentNumber = "MOCK-" + Guid.NewGuid().ToString("N").Substring(0, 8).ToUpper(),
                        ExpirationDate = DateTime.UtcNow.AddYears(5).ToString("yyyy-MM-dd")
                    },
                    NextSteps = new List<string>
                    {
                        "Government ID verification completed",
                        "Full identity verification achieved",
                        "You now have access to all age-restricted features",
                        "NOTE: This is mock data for MVP testing"
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in mock government ID verification");
                return StatusCode(500, new { message = "Failed to complete government ID verification" });
            }
        }

        /// <summary>
        /// [MVP MOCK] Complete full verification in one step (for testing)
        /// POST /api/v1/auth/identity/verify/complete
        /// </summary>
        [HttpPost("verify/complete")]
        [Authorize]
        public async Task<ActionResult<MockVerificationResult>> CompleteFullVerification()
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();

                _logger.LogInformation("MVP Mock: Auto-completing full verification for user {UserId}", userId);

                // Record all verification attempts
                await _service.RecordVerificationAttemptAsync(
                    tenantId, userId, VerificationMethod.AgeVerification,
                    VerificationStatus.Success, VerificationProvider.MVPMock, 1.0m);

                await _service.RecordVerificationAttemptAsync(
                    tenantId, userId, VerificationMethod.HumanVerification,
                    VerificationStatus.Success, VerificationProvider.MVPMock, 1.0m);

                await _service.RecordVerificationAttemptAsync(
                    tenantId, userId, VerificationMethod.GovernmentID,
                    VerificationStatus.Success, VerificationProvider.MVPMock, 1.0m);

                // Update to highest verification level
                await _service.UpdateVerificationLevelAsync(
                    tenantId,
                    userId,
                    IdentityVerificationLevel.GovernmentVerified,
                    AgeVerificationResult.Adult
                );

                // Get updated status
                var status = await _service.GetStatusAsync(tenantId, userId);

                return Ok(new MockVerificationResult
                {
                    Success = true,
                    Message = "[MVP MOCK] Complete identity verification done instantly",
                    VerificationLevel = status.VerificationLevel,
                    AgeCategory = status.AgeCategory,
                    AgeVerified = status.AgeVerified,
                    HumanVerified = status.HumanVerified,
                    GovernmentIDVerified = status.GovernmentIDVerified,
                    IsMockData = true,
                    NextSteps = new List<string>
                    {
                        "✅ Age verified: Adult",
                        "✅ Human verified: Passed",
                        "✅ Government ID verified: Passed",
                        "🎉 Full verification complete!",
                        "NOTE: This is mock data for MVP testing"
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in mock complete verification");
                return StatusCode(500, new { message = "Failed to complete verification" });
            }
        }

        /// <summary>
        /// [MVP MOCK] Reset verification status (for testing)
        /// DELETE /api/v1/auth/identity/verify/reset
        /// </summary>
        [HttpDelete("verify/reset")]
        [Authorize]
        public async Task<ActionResult> ResetVerification()
        {
            try
            {
                var tenantId = GetTenantId();
                var userId = GetUserId();

                _logger.LogInformation("MVP Mock: Resetting verification for user {UserId}", userId);

                // Reset to unverified
                await _service.UpdateVerificationLevelAsync(
                    tenantId,
                    userId,
                    IdentityVerificationLevel.Unverified,
                    AgeVerificationResult.Unknown
                );

                return Ok(new 
                { 
                    success = true,
                    message = "[MVP MOCK] Verification reset to Unverified",
                    note = "You can now re-test the verification flow"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting verification");
                return StatusCode(500, new { message = "Failed to reset verification" });
            }
        }
    }

    // ========================================================================
    // DTOs for Mock Verification
    // ========================================================================

    public sealed class AgeVerificationRequest
    {
        public DateTime? DateOfBirth { get; set; }
        public string? Country { get; set; }
    }

    public sealed class GovernmentIDRequest
    {
        public string IdType { get; set; } = "DriversLicense"; // DriversLicense, Passport, NationalID
        public string? Country { get; set; }
        public string? DocumentNumber { get; set; } // Not actually validated in MVP
    }

    public sealed class MockVerificationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public IdentityVerificationLevel VerificationLevel { get; set; }
        public AgeVerificationResult? AgeCategory { get; set; }
        public bool AgeVerified { get; set; }
        public bool HumanVerified { get; set; }
        public bool GovernmentIDVerified { get; set; }
        public bool IsMockData { get; set; }
        public object? MockIDInfo { get; set; }
        public List<string> NextSteps { get; set; } = new();
    }
}

// ============================================================================
// SERVICE LAYER - Add these methods to IdentitySignalsService
// ============================================================================

namespace KeiroGenesis.API.Services
{
  
    using global::KeiroGenesis.Identity;

    public partial class IdentitySignalsService
    {
        /// <summary>
        /// Record a verification attempt
        /// </summary>
        public async Task RecordVerificationAttemptAsync(
            Guid tenantId,
            Guid userId,
            VerificationMethod method,
            VerificationStatus status,
            VerificationProvider? provider,
            decimal? confidenceScore)
        {
            await _repo.CreateVerificationAttemptAsync(
                tenantId,
                userId,
                method,
                status,
                provider,
                confidenceScore
            );
        }

        /// <summary>
        /// Update verification level and age category
        /// </summary>
        public async Task UpdateVerificationLevelAsync(
            Guid tenantId,
            Guid userId,
            IdentityVerificationLevel level,
            AgeVerificationResult? ageCategory)
        {
            await _repo.UpdateVerificationLevelAsync(tenantId, userId, level, ageCategory);
        }
    }
}

// ============================================================================
// REPOSITORY LAYER - Add these methods to IdentitySignalsRepository
// ============================================================================

namespace KeiroGenesis.API.Repositories
{
    using KeiroGenesis.Identity;
    using Dapper;

    public partial class IdentitySignalsRepository
    {
        /// <summary>
        /// Create a verification attempt record
        /// </summary>
        public async Task CreateVerificationAttemptAsync(
            Guid tenantId,
            Guid userId,
            VerificationMethod method,
            VerificationStatus status,
            VerificationProvider? provider,
            decimal? confidenceScore)
        {
            using var conn = CreateConnection();

            // Get identity profile ID
            var profileId = await conn.ExecuteScalarAsync<Guid?>(
                @"SELECT identity_profile_id 
                  FROM identity.identity_profiles 
                  WHERE tenant_id = @TenantId AND user_id = @UserId",
                new { TenantId = tenantId, UserId = userId });

            if (!profileId.HasValue)
            {
                throw new InvalidOperationException("Identity profile not found");
            }

            await conn.ExecuteAsync(
                @"INSERT INTO identity.verification_attempts (
                    tenant_id, identity_profile_id, user_id, method, status,
                    provider, confidence_score, fraud_alert_triggered,
                    initiated_at, completed_at
                  ) VALUES (
                    @TenantId, @ProfileId, @UserId, @Method, @Status,
                    @Provider, @ConfidenceScore, false,
                    @Now, @Now
                  )",
                new
                {
                    TenantId = tenantId,
                    ProfileId = profileId.Value,
                    UserId = userId,
                    Method = method.ToString(),
                    Status = status.ToString(),
                    Provider = provider?.ToString(),
                    ConfidenceScore = confidenceScore,
                    Now = DateTime.UtcNow
                });
        }

        /// <summary>
        /// Update verification level and age category
        /// </summary>
        public async Task UpdateVerificationLevelAsync(
            Guid tenantId,
            Guid userId,
            IdentityVerificationLevel level,
            AgeVerificationResult? ageCategory)
        {
            using var conn = CreateConnection();

            var now = DateTime.UtcNow;
            var expiresAt = level >= IdentityVerificationLevel.GovernmentVerified
                ? now.AddYears(1) // Government ID expires after 1 year
                : (DateTime?)null;

            await conn.ExecuteAsync(
                @"UPDATE identity.identity_profiles
                  SET verification_level = @Level,
                      age_verified = @AgeVerified,
                      age_category = @AgeCategory,
                      verified_at = @VerifiedAt,
                      expires_at = @ExpiresAt,
                      requires_reverification = false,
                      reverification_reason = NULL,
                      updated_at = @UpdatedAt
                  WHERE tenant_id = @TenantId AND user_id = @UserId",
                new
                {
                    TenantId = tenantId,
                    UserId = userId,
                    Level = level.ToString(),
                    AgeVerified = level >= IdentityVerificationLevel.AgeAssured,
                    AgeCategory = ageCategory?.ToString() ?? AgeVerificationResult.Unknown.ToString(),
                    VerifiedAt = now,
                    ExpiresAt = expiresAt,
                    UpdatedAt = now
                });
        }
    }
}

// ============================================================================
// ENUMS - Add to KeiroGenesis.Identity namespace if not present
// ============================================================================

namespace KeiroGenesis.Identity
{
   
}
