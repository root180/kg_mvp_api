using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using HotChocolate;
using HotChocolate.Authorization;
using HotChocolate.Types;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace KeiroGenesis.API.GraphQL.Dashboard
{
    #region MODELS – All Result Set Mappings

    // ============================================================
    // 1) USER PROFILE (Basic)
    // ============================================================
    public class DashboardUserProfileGql
    {
        public Guid UserId { get; set; }
        public Guid TenantId { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? DisplayName { get; set; }
        public string? AvatarUrl { get; set; }
        public string? CoverImageUrl { get; set; }
        public string? Timezone { get; set; }
        public string? Language { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public bool IsActive { get; set; }
        public bool? IsLocked { get; set; }
    }

    // ============================================================
    // 2) USER PREFERENCES
    // ============================================================
    public class DashboardUserPreferencesGql
    {
        public Guid PreferenceId { get; set; }
        public Guid UserId { get; set; }
        public Guid? DefaultTenantId { get; set; }
        public Guid? LastSelectedTenantId { get; set; }
        public bool AutoSwitchTenant { get; set; }
        public string? Theme { get; set; }
        public string? Language { get; set; }
        public string? Timezone { get; set; }
        public string? DateFormat { get; set; }
        public string? TimeFormat { get; set; }
        public string? DefaultDashboardView { get; set; }
        public string? DashboardLayout { get; set; }
        public int? ItemsPerPage { get; set; }
        public int? SessionTimeoutMinutes { get; set; }
        public bool Require2FA { get; set; }
        public bool TrustedDevicesEnabled { get; set; }
        public Guid EffectiveTenantId { get; set; }
    }

    // ============================================================
    // 3) TENANT + SUBSCRIPTION SNAPSHOT
    // ============================================================
    public class DashboardTenantSnapshotGql
    {
        public Guid TenantId { get; set; }
        public string TenantName { get; set; } = string.Empty;
        public string? Domain { get; set; }
        public bool IsActive { get; set; }
        public Guid? TenantTypeId { get; set; }
        public int? MaxClones { get; set; }
        public int? MaxUsers { get; set; }
        public int? StorageLimitMb { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }

        // Subscription fields
        public string? SubscriptionStatus { get; set; }
        public string? BillingStatus { get; set; }
        public string? BillingCycle { get; set; }
        public DateTime? CurrentPeriodStart { get; set; }
        public DateTime? CurrentPeriodEnd { get; set; }
        public DateTime? NextBillingDate { get; set; }

        // Plan fields
        public string? PlanName { get; set; }
        public string? PlanDisplayName { get; set; }
        public int? PlanTier { get; set; }
        public bool RagAccessEnabled { get; set; }
        public bool AnalyticsAccessEnabled { get; set; }
    }

    // ============================================================
    // 4) QUICK STATS
    // ============================================================
    public class DashboardQuickStatsGql
    {
        public int ActiveClones { get; set; }
        public int InteractionsToday { get; set; }
        public decimal EarningsThisMonth { get; set; }
    }

    // ============================================================
    // 5) CLONE SUMMARIES
    // ============================================================
    public class DashboardCloneSummaryGql
    {
        public Guid CloneId { get; set; }
        public string CloneName { get; set; } = string.Empty;
        public string ShortCode { get; set; } = string.Empty;
        public string Color { get; set; } = "#1877f2";
        public bool IsOnline { get; set; }
        public int InteractionsToday { get; set; }
        public decimal EarningsThisMonth { get; set; }
    }

    // ============================================================
    // 6) FEED POSTS
    // ============================================================
    public class DashboardFeedPostGql
    {
        public int Id { get; set; }
        public string Author { get; set; } = string.Empty;
        public string Avatar { get; set; } = string.Empty;
        public string AvatarBg { get; set; } = "#1877f2";
        public string Time { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public bool HasImage { get; set; }
        public int Reactions { get; set; }
        public int Comments { get; set; }
        public int Shares { get; set; }
        public bool IsClone { get; set; }
    }

    // ============================================================
    // 7) NOTIFICATIONS SUMMARY
    // ============================================================
    public class DashboardNotificationSummaryGql
    {
        public Guid? NotificationId { get; set; }
        public string? Title { get; set; }
        public string? Body { get; set; }
        public string? NotificationType { get; set; }
        public bool? IsRead { get; set; }
        public DateTime? CreatedAt { get; set; }
        public int UnreadCount { get; set; }
    }

    // ============================================================
    // 8) USER PROFILE EXTENDED (from sp_dashboard_init_existing_loader)
    // ============================================================
    public class DashboardUserProfileExtendedGql
    {
        public Guid UserId { get; set; }
        public Guid TenantId { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? DisplayName { get; set; }
        public string? Bio { get; set; }
        public string? AvatarUrl { get; set; }
        public string? CoverImageUrl { get; set; }
        public string? Location { get; set; }
        public string? Website { get; set; }
        public string? SocialLinks { get; set; }
        public string? Gender { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public string? Timezone { get; set; }
        public string? Language { get; set; }
        public bool? IsPublic { get; set; }
        public bool? IsVerified { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public bool IsActive { get; set; }
        public bool? IsLocked { get; set; }
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }

    // ============================================================
    // 9) ACHIEVEMENTS SUMMARY
    // ============================================================
    public class DashboardAchievementsSummaryGql
    {
        public int AchievementsCount { get; set; }
    }

    // ============================================================
    // 10) SOCIAL GRAPH SUMMARY
    // ============================================================
    public class DashboardSocialGraphGql
    {
        public int Followers { get; set; }
        public int Following { get; set; }
    }

    // ============================================================
    // ROOT PAYLOAD – EXISTING USER (sp_dashboard_init_existing_loader)
    // Returns 11 result sets
    // ============================================================
    public class PersonalDashboardGqlPayload
    {
        // Standard envelope
        public bool Success { get; set; }
        public string? Error { get; set; }
        public string? Message { get; set; }

        // Core profile blocks
        public DashboardUserProfileGql? Profile { get; set; }
        public DashboardUserProfileExtendedGql? ProfileExtended { get; set; }
        public DashboardUserPreferencesGql? Preferences { get; set; }

        // Tenant & subscription
        public DashboardTenantSnapshotGql? Tenant { get; set; }

        // Stats & activity
        public DashboardQuickStatsGql? QuickStats { get; set; }
        public DashboardAchievementsSummaryGql? Achievements { get; set; }
        public DashboardSocialGraphGql? SocialGraph { get; set; }

        // Collections
        public List<DashboardCloneSummaryGql> Clones { get; set; } = new();
        public List<DashboardFeedPostGql> Posts { get; set; } = new();

        // Notifications
        public DashboardNotificationSummaryGql? Notifications { get; set; }
    }

    // ============================================================
    // ROOT PAYLOAD – NEW USER (sp_dashboard_init_new_loader)
    // Lighter payload for first-time users
    // ============================================================
    public class NewUserDashboardGqlPayload
    {
        // Standard envelope
        public bool Success { get; set; }
        public string? Error { get; set; }
        public string? Message { get; set; }

        // Stats first (result set 1)
        public DashboardQuickStatsGql? QuickStats { get; set; }

        // Clones (result set 2)
        public List<DashboardCloneSummaryGql> Clones { get; set; } = new();

        // Posts (result set 3)
        public List<DashboardFeedPostGql> Posts { get; set; } = new();

        // Profile (result set 4)
        public DashboardUserProfileExtendedGql? Profile { get; set; }

        // Preferences (result set 5)
        public DashboardUserPreferencesGql? Preferences { get; set; }

        // Tenant (result set 6)
        public DashboardTenantSnapshotGql? Tenant { get; set; }

        // Achievements (result set 7)
        public DashboardAchievementsSummaryGql? Achievements { get; set; }

        // Social (result set 8)
        public DashboardSocialGraphGql? SocialGraph { get; set; }

        // Notifications (result set 9)
        public DashboardNotificationSummaryGql? Notifications { get; set; }
    }

    #endregion

    #region REPOSITORY INTERFACE

    public interface IPersonalDashboardGraphQLRepository
    {
        /// <summary>
        /// Load dashboard for existing users (sp_dashboard_init_existing_loader)
        /// Returns 11 result sets
        /// </summary>
        Task<PersonalDashboardGqlPayload> LoadExistingUserDashboardAsync(
            Guid tenantId,
            Guid userId,
            CancellationToken cancellationToken);

        /// <summary>
        /// Load dashboard for new users (sp_dashboard_init_new_loader)
        /// Returns 9 result sets, lighter query
        /// </summary>
        Task<NewUserDashboardGqlPayload> LoadNewUserDashboardAsync(
            Guid userId,
            Guid? tenantId,
            CancellationToken cancellationToken);

        /// <summary>
        /// Check if user is new (no clones, minimal activity)
        /// </summary>
        Task<bool> IsNewUserAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken);
    }

    #endregion

    #region REPOSITORY IMPLEMENTATION

    public class PersonalDashboardGraphQLRepository : IPersonalDashboardGraphQLRepository
    {
        private readonly IDbConnectionFactory _connectionFactory;
        private readonly ILogger<PersonalDashboardGraphQLRepository> _logger;

        public PersonalDashboardGraphQLRepository(
            IDbConnectionFactory connectionFactory,
            ILogger<PersonalDashboardGraphQLRepository> logger)
        {
            _connectionFactory = connectionFactory;
            _logger = logger;
        }

        /// <summary>
        /// Existing user dashboard - calls sp_dashboard_init_existing_loader
        /// Reads 11 result sets
        /// </summary>
        public async Task<PersonalDashboardGqlPayload> LoadExistingUserDashboardAsync(
            Guid tenantId,
            Guid userId,
            CancellationToken cancellationToken)
        {
            const string procName = "core.sp_dashboard_init_existing_loader";

            try
            {
                using IDbConnection conn = _connectionFactory.CreateConnection();

                var parameters = new
                {
                    UserId = userId,
                    TenantId = tenantId
                };

                using var grid = await conn.QueryMultipleAsync(
                    sql: procName,
                    param: parameters,
                    commandType: CommandType.StoredProcedure);

                // 1) Profile (basic)
                var profile = await grid.ReadFirstOrDefaultAsync<DashboardUserProfileGql>();

                // 2) Preferences
                var preferences = await grid.ReadFirstOrDefaultAsync<DashboardUserPreferencesGql>();

                // 3) Tenant snapshot
                var tenant = await grid.ReadFirstOrDefaultAsync<DashboardTenantSnapshotGql>();

                // 4) Quick stats
                var quickStats = await grid.ReadFirstOrDefaultAsync<DashboardQuickStatsGql>();

                // 5) Clones
                var clones = (await grid.ReadAsync<DashboardCloneSummaryGql>()).ToList();

                // 6) Posts
                var posts = (await grid.ReadAsync<DashboardFeedPostGql>()).ToList();

                // 7) Notifications placeholder (empty result set from WHERE 1=0)
                await grid.ReadAsync<DashboardNotificationSummaryGql>(); // Skip empty placeholder

                // 8) Profile extended
                var profileExtended = await grid.ReadFirstOrDefaultAsync<DashboardUserProfileExtendedGql>();

                // 9) Achievements
                var achievements = await grid.ReadFirstOrDefaultAsync<DashboardAchievementsSummaryGql>();

                // 10) Social graph
                var socialGraph = await grid.ReadFirstOrDefaultAsync<DashboardSocialGraphGql>();

                // 11) Notifications (real)
                var notifications = await grid.ReadFirstOrDefaultAsync<DashboardNotificationSummaryGql>();

                return new PersonalDashboardGqlPayload
                {
                    Success = true,
                    Error = null,
                    Message = null,
                    Profile = profile,
                    ProfileExtended = profileExtended,
                    Preferences = preferences,
                    Tenant = tenant,
                    QuickStats = quickStats,
                    Achievements = achievements,
                    SocialGraph = socialGraph,
                    Clones = clones ?? new List<DashboardCloneSummaryGql>(),
                    Posts = posts ?? new List<DashboardFeedPostGql>(),
                    Notifications = notifications
                };
            }
            catch (SqlException ex)
            {
                _logger.LogError(ex,
                    "SQL error executing {ProcName} for TenantId={TenantId}, UserId={UserId}",
                    procName, tenantId, userId);

                return new PersonalDashboardGqlPayload
                {
                    Success = false,
                    Error = "DASHBOARD_SQL_ERROR",
                    Message = "An error occurred while loading the dashboard."
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Unexpected error executing {ProcName} for TenantId={TenantId}, UserId={UserId}",
                    procName, tenantId, userId);

                return new PersonalDashboardGqlPayload
                {
                    Success = false,
                    Error = "DASHBOARD_UNEXPECTED_ERROR",
                    Message = "An unexpected error occurred while loading the dashboard."
                };
            }
        }

        /// <summary>
        /// New user dashboard - calls sp_dashboard_init_new_loader
        /// Lighter load for first-time users
        /// </summary>
        public async Task<NewUserDashboardGqlPayload> LoadNewUserDashboardAsync(
            Guid userId,
            Guid? tenantId,
            CancellationToken cancellationToken)
        {
            const string procName = "core.sp_dashboard_init_new_loader";

            try
            {
                using IDbConnection conn = _connectionFactory.CreateConnection();

                var parameters = new
                {
                    UserId = userId,
                    TenantId = tenantId
                };

                using var grid = await conn.QueryMultipleAsync(
                    sql: procName,
                    param: parameters,
                    commandType: CommandType.StoredProcedure);

                // 1) Stats
                var quickStats = await grid.ReadFirstOrDefaultAsync<DashboardQuickStatsGql>();

                // 2) Clones
                var clones = (await grid.ReadAsync<DashboardCloneSummaryGql>()).ToList();

                // 3) Posts
                var posts = (await grid.ReadAsync<DashboardFeedPostGql>()).ToList();

                // 4) Profile (extended format)
                var profile = await grid.ReadFirstOrDefaultAsync<DashboardUserProfileExtendedGql>();

                // 5) Preferences
                var preferences = await grid.ReadFirstOrDefaultAsync<DashboardUserPreferencesGql>();

                // 6) Tenant
                var tenant = await grid.ReadFirstOrDefaultAsync<DashboardTenantSnapshotGql>();

                // 7) Achievements
                var achievements = await grid.ReadFirstOrDefaultAsync<DashboardAchievementsSummaryGql>();

                // 8) Social graph
                var socialGraph = await grid.ReadFirstOrDefaultAsync<DashboardSocialGraphGql>();

                // 9) Notifications
                var notifications = await grid.ReadFirstOrDefaultAsync<DashboardNotificationSummaryGql>();

                return new NewUserDashboardGqlPayload
                {
                    Success = true,
                    Error = null,
                    Message = null,
                    QuickStats = quickStats,
                    Clones = clones ?? new List<DashboardCloneSummaryGql>(),
                    Posts = posts ?? new List<DashboardFeedPostGql>(),
                    Profile = profile,
                    Preferences = preferences,
                    Tenant = tenant,
                    Achievements = achievements,
                    SocialGraph = socialGraph,
                    Notifications = notifications
                };
            }
            catch (SqlException ex)
            {
                _logger.LogError(ex,
                    "SQL error executing {ProcName} for UserId={UserId}, TenantId={TenantId}",
                    procName, userId, tenantId);

                return new NewUserDashboardGqlPayload
                {
                    Success = false,
                    Error = "DASHBOARD_SQL_ERROR",
                    Message = "An error occurred while loading the dashboard."
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Unexpected error executing {ProcName} for UserId={UserId}, TenantId={TenantId}",
                    procName, userId, tenantId);

                return new NewUserDashboardGqlPayload
                {
                    Success = false,
                    Error = "DASHBOARD_UNEXPECTED_ERROR",
                    Message = "An unexpected error occurred while loading the dashboard."
                };
            }
        }

        /// <summary>
        /// Check if user is "new" (no clones created yet)
        /// Used to decide which SP to call
        /// </summary>
        public async Task<bool> IsNewUserAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken)
        {
            const string sql = @"
                SELECT CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM clone.clones 
                        WHERE tenant_id = @TenantId 
                          AND owner_id = @UserId 
                          AND deleted_at IS NULL
                    ) THEN 0 
                    ELSE 1 
                END";

            try
            {
                using IDbConnection conn = _connectionFactory.CreateConnection();
                return await conn.ExecuteScalarAsync<bool>(sql, new { TenantId = tenantId, UserId = userId });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking if user is new, defaulting to existing user flow");
                return false; // Default to existing user (more data)
            }
        }
    }

    #endregion

    #region SERVICE

    public class DashboardGraphQLService
    {
        private readonly IPersonalDashboardGraphQLRepository _repository;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<DashboardGraphQLService> _logger;

        public DashboardGraphQLService(
            IPersonalDashboardGraphQLRepository repository,
            IHttpContextAccessor httpContextAccessor,
            ILogger<DashboardGraphQLService> logger)
        {
            _repository = repository;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        /// <summary>
        /// Get dashboard for existing users
        /// </summary>
        public async Task<PersonalDashboardGqlPayload> GetPersonalDashboardAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext == null)
                {
                    return new PersonalDashboardGqlPayload
                    {
                        Success = false,
                        Error = "NO_HTTP_CONTEXT",
                        Message = "Unable to resolve the current HTTP context."
                    };
                }

                (Guid tenantId, Guid userId) = TokenClaimHelper.FromClaimsPrincipal(httpContext.User);

                return await _repository.LoadExistingUserDashboardAsync(tenantId, userId, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in GetPersonalDashboardAsync");

                return new PersonalDashboardGqlPayload
                {
                    Success = false,
                    Error = "DASHBOARD_ERROR",
                    Message = "An error occurred while loading your dashboard."
                };
            }
        }

        /// <summary>
        /// Get dashboard for new users (lighter payload)
        /// </summary>
        public async Task<NewUserDashboardGqlPayload> GetNewUserDashboardAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext == null)
                {
                    return new NewUserDashboardGqlPayload
                    {
                        Success = false,
                        Error = "NO_HTTP_CONTEXT",
                        Message = "Unable to resolve the current HTTP context."
                    };
                }

                (Guid tenantId, Guid userId) = TokenClaimHelper.FromClaimsPrincipal(httpContext.User);

                return await _repository.LoadNewUserDashboardAsync(userId, tenantId, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in GetNewUserDashboardAsync");

                return new NewUserDashboardGqlPayload
                {
                    Success = false,
                    Error = "DASHBOARD_ERROR",
                    Message = "An error occurred while loading your dashboard."
                };
            }
        }

        /// <summary>
        /// Auto-detect which dashboard to load based on user state
        /// </summary>
        public async Task<PersonalDashboardGqlPayload> GetSmartDashboardAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext == null)
                {
                    return new PersonalDashboardGqlPayload
                    {
                        Success = false,
                        Error = "NO_HTTP_CONTEXT",
                        Message = "Unable to resolve the current HTTP context."
                    };
                }

                (Guid tenantId, Guid userId) = TokenClaimHelper.FromClaimsPrincipal(httpContext.User);

                // Check if user is new
                bool isNewUser = await _repository.IsNewUserAsync(tenantId, userId, cancellationToken);

                if (isNewUser)
                {
                    // Use lighter query for new users, then map to full payload
                    var newUserData = await _repository.LoadNewUserDashboardAsync(userId, tenantId, cancellationToken);

                    return new PersonalDashboardGqlPayload
                    {
                        Success = newUserData.Success,
                        Error = newUserData.Error,
                        Message = newUserData.Message,
                        Profile = newUserData.Profile != null ? new DashboardUserProfileGql
                        {
                            UserId = newUserData.Profile.UserId,
                            TenantId = newUserData.Profile.TenantId,
                            Username = newUserData.Profile.Username,
                            Email = newUserData.Profile.Email,
                            FirstName = newUserData.Profile.FirstName,
                            LastName = newUserData.Profile.LastName,
                            DisplayName = newUserData.Profile.DisplayName,
                            AvatarUrl = newUserData.Profile.AvatarUrl,
                            CoverImageUrl = newUserData.Profile.CoverImageUrl,
                            Timezone = newUserData.Profile.Timezone,
                            Language = newUserData.Profile.Language,
                            LastLoginAt = newUserData.Profile.LastLoginAt,
                            IsActive = newUserData.Profile.IsActive,
                            IsLocked = newUserData.Profile.IsLocked
                        } : null,
                        ProfileExtended = newUserData.Profile,
                        Preferences = newUserData.Preferences,
                        Tenant = newUserData.Tenant,
                        QuickStats = newUserData.QuickStats,
                        Achievements = newUserData.Achievements,
                        SocialGraph = newUserData.SocialGraph,
                        Clones = newUserData.Clones,
                        Posts = newUserData.Posts,
                        Notifications = newUserData.Notifications
                    };
                }

                // Use full query for existing users
                return await _repository.LoadExistingUserDashboardAsync(tenantId, userId, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in GetSmartDashboardAsync");

                return new PersonalDashboardGqlPayload
                {
                    Success = false,
                    Error = "DASHBOARD_ERROR",
                    Message = "An error occurred while loading your dashboard."
                };
            }
        }
    }

    #endregion

    #region GRAPHQL QUERY TYPE

    public class DashboardQuery
    {
        private readonly DashboardGraphQLService _service;

        public DashboardQuery(DashboardGraphQLService service)
        {
            _service = service;
        }

        /// <summary>
        /// Main dashboard query - auto-detects new vs existing user
        /// 
        /// query {
        ///   personalDashboard {
        ///     success
        ///     profile { userId displayName avatarUrl }
        ///     profileExtended { bio location website isVerified }
        ///     preferences { theme language timezone }
        ///     tenant { tenantName planName subscriptionStatus }
        ///     quickStats { activeClones interactionsToday earningsThisMonth }
        ///     achievements { achievementsCount }
        ///     socialGraph { followers following }
        ///     clones { cloneId cloneName isOnline interactionsToday }
        ///     posts { id author content time reactions }
        ///     notifications { unreadCount }
        ///   }
        /// }
        /// </summary>
        [GraphQLName("personalDashboard")]
        [Authorize]
        [GraphQLDescription("Load personal dashboard with auto-detection for new vs existing users")]
        public Task<PersonalDashboardGqlPayload> GetPersonalDashboardAsync(
            CancellationToken cancellationToken) =>
            _service.GetSmartDashboardAsync(cancellationToken);

        /// <summary>
        /// Force existing user dashboard (for testing or explicit use)
        /// </summary>
        [GraphQLName("existingUserDashboard")]
        [Authorize]
        [GraphQLDescription("Load full dashboard for existing users with all data")]
        public Task<PersonalDashboardGqlPayload> GetExistingUserDashboardAsync(
            CancellationToken cancellationToken) =>
            _service.GetPersonalDashboardAsync(cancellationToken);

        /// <summary>
        /// Force new user dashboard (lighter payload)
        /// </summary>
        [GraphQLName("newUserDashboard")]
        [Authorize]
        [GraphQLDescription("Load lightweight dashboard for new users")]
        public Task<NewUserDashboardGqlPayload> GetNewUserDashboardAsync(
            CancellationToken cancellationToken) =>
            _service.GetNewUserDashboardAsync(cancellationToken);
    }

    #endregion
}