// ==========================================================================
// AUTH MODULE — Authentication & Token Management
// Single file: Repository + Service + Controller
// NO DTOs, NO Interfaces - Simple request/response classes
// HTTP Cookies + JWT Token Generation
// ==========================================================================

using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Core.Helpers;
using KeiroGenesis.API.Ratings;
using KeiroGenesis.API.Services;
using KeiroGenesis.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using static Dapper.SqlMapper;
using static HotChocolate.ErrorCodes;

// ==========================================================================
// REPOSITORY
// ==========================================================================
namespace KeiroGenesis.API.Repositories
{
    public class AuthRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<AuthRepository> _logger;

        public AuthRepository(IDbConnectionFactory db, ILogger<AuthRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<RegisterResponse> RegisterUserAsync(RegisterRequest dto)
        {
            using var conn = _db.CreateConnection();
            try
            {
                var result = await conn.QuerySingleOrDefaultAsync<RegisterResponse>(@"
            SELECT 
                user_id AS UserId,
                tenant_id AS TenantId,
                username AS Username,
                email AS Email,
                first_name AS FirstName,
                last_name AS LastName,
                tenant_name AS TenantName,
                content_eligibility_level AS ContentEligibilityLevel,
                age AS Age
            FROM auth.fn_register_user(
                @p_email, 
                @p_username, 
                @p_password_hash, 
                @p_first_name, 
                @p_last_name, 
                @p_tenant_name,
                @p_date_of_birth::date,
                @p_gender,
                @p_mobile_number
            )
        ", new
                {
                    p_email = dto.Email,
                    p_username = dto.Username,
                    p_password_hash = dto.PasswordHash,
                    p_first_name = dto.FirstName ?? "",
                    p_last_name = dto.LastName ?? "",
                    p_tenant_name = dto.TenantName ?? dto.Username,
                    p_date_of_birth = dto.DateOfBirth?.Date,
                    p_gender = dto.Gender,
                    p_mobile_number = dto.MobileNumber
                });

                if (result != null)
                {
                    result.Success = true;
                    result.Message = "User registered successfully";
                    return result;
                }

                return new RegisterResponse
                {
                    Success = false,
                    Message = "Registration failed - no data returned from database"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database error during user registration");
                return new RegisterResponse
                {
                    Success = false,
                    Message = ex.Message.Contains("COPPA")
                        ? "You must be at least 13 years old to register (COPPA compliance)"
                        : $"Registration failed: {ex.Message}"
                };
            }
        }

        // Login - get user by email
        public async Task<dynamic?> GetUserByEmailAsync(string email)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(@"
                SELECT user_id, username, email, password_hash, first_name, last_name, 
                       is_active, created_at, updated_at, is_email_verified, 
                       tenant_id, tenant_name, subscription_tier
                FROM auth.fn_get_user_by_email(@email)
            ", new { email });

            return result.FirstOrDefault();
        }

        // Store refresh token
        public async Task<Guid> StoreRefreshTokenAsync(
            Guid userId, Guid tenantId, string tokenHash, DateTime expiresAt)
        {
            using var conn = _db.CreateConnection();

            return await conn.ExecuteScalarAsync<Guid>(
                "SELECT security.fn_store_refresh_token(@user_id, @tenant_id, @token_hash, @expires_at)",
                new { user_id = userId, tenant_id = tenantId, token_hash = tokenHash, expires_at = expiresAt });
        }

        // Validate refresh token
        public async Task<dynamic?> ValidateRefreshTokenAsync(string tokenHash)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(@"
                SELECT token_id, user_id, tenant_id, expires_at
                FROM security.fn_validate_refresh_token(@token_hash)
            ", new { token_hash = tokenHash });

            return result.FirstOrDefault();
        }

        // Revoke refresh token
        public async Task RevokeRefreshTokenAsync(Guid tokenId)
        {
            using var conn = _db.CreateConnection();

            await conn.ExecuteAsync(
                "SELECT security.fn_revoke_refresh_token(@token_id)",
                new { token_id = tokenId });
        }

        // Revoke all user tokens
        public async Task RevokeAllUserTokensAsync(Guid userId, Guid tenantId)
        {
            using var conn = _db.CreateConnection();

            await conn.ExecuteAsync(
                "SELECT security.fn_revoke_all_user_tokens(@user_id, @tenant_id)",
                new { user_id = userId, tenant_id = tenantId });
        }

        // Check if email exists
        public async Task<bool> EmailExistsAsync(string email)
        {
            using var conn = _db.CreateConnection();

            return await conn.ExecuteScalarAsync<bool>(
                "SELECT auth.fn_email_exists(@email)",
                new { email });
        }

        // Check if username exists
        public async Task<bool> UsernameExistsAsync(string username)
        {
            using var conn = _db.CreateConnection();

            return await conn.ExecuteScalarAsync<bool>(
                "SELECT auth.fn_username_exists(@username)",
                new { username });
        }

        // Get user by ID
        public async Task<dynamic?> GetUserByIdAsync(Guid userId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(@"
                SELECT user_id, tenant_id, email, username, password_hash, first_name, last_name
                FROM auth.fn_get_user_by_id(@user_id)
            ", new { user_id = userId });

            return result.FirstOrDefault();
        }

        // Get user roles
        public async Task<IEnumerable<int>> GetUserRolesAsync(Guid userId, Guid tenantId)
        {
            using var conn = _db.CreateConnection();

            var roles = await conn.QueryAsync<int>(
                "SELECT role_id FROM security.fn_get_user_roles(@user_id, @tenant_id)",
                new { user_id = userId, tenant_id = tenantId });

            return roles;
        }

        // UserRoleDetail class
        public class UserRoleDetail
        {
            public int RoleId { get; set; }
            public string RoleName { get; set; } = string.Empty;
        }

        // Get user role details
        public async Task<IEnumerable<UserRoleDetail>> GetUserRoleDetailsAsync(Guid userId, Guid tenantId)
        {
            using var conn = _db.CreateConnection();

            var roles = await conn.QueryAsync<UserRoleDetail>(@"
                SELECT role_id AS RoleId, role_name AS RoleName
                FROM security.fn_get_user_role_details(@user_id, @tenant_id)
            ", new { user_id = userId, tenant_id = tenantId });

            return roles;
        }

        // ============================================================
        // PASSWORD MANAGEMENT - WITH TENANT_ID
        // ============================================================

        public async Task<bool> StorePasswordResetTokenAsync(
            string email,
            Guid tenantId,
            string token,
            DateTime expiresAt)
        {
            using var conn = _db.CreateConnection();
            var tokenHash = HashToken(token);

            var result = await conn.QueryAsync(@"
                SELECT success, user_id, tenant_id
                FROM auth.fn_store_password_reset_token(@email, @tenantId, @tokenHash, @expiresAt)
            ", new { email, tenantId, tokenHash, expiresAt });

            var data = result.FirstOrDefault();
            if (data == null) return false;

            return DapperHelper.GetValue<bool>(data, "success");
        }

        public async Task<dynamic?> ValidatePasswordResetTokenAsync(string token, Guid tenantId)
        {
            using var conn = _db.CreateConnection();
            var tokenHash = HashToken(token);

            var result = await conn.QueryAsync(@"
                SELECT user_id, tenant_id, email, expires_at, is_used
                FROM auth.fn_validate_password_reset_token(@tokenHash, @tenantId)
            ", new { tokenHash, tenantId });

            return result.FirstOrDefault();
        }

        public async Task InvalidatePasswordResetTokenAsync(string token, Guid tenantId)
        {
            using var conn = _db.CreateConnection();
            var tokenHash = HashToken(token);

            await conn.ExecuteAsync(@"
                SELECT auth.fn_invalidate_password_reset_token(@tokenHash, @tenantId)
            ", new { tokenHash, tenantId });
        }

        public async Task<(bool success, Guid? userId, Guid? tenantId)> UpdatePasswordByEmailAsync(
            string email,
            Guid tenantId,
            string passwordHash)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(@"
                SELECT success, user_id, tenant_id
                FROM auth.fn_update_password_by_email(@email, @tenantId, @passwordHash)
            ", new { email, tenantId, passwordHash });

            var data = result.FirstOrDefault();
            if (data == null) return (false, null, null);

            var success = DapperHelper.GetValue<bool>(data, "success");
            var userId = success ? DapperHelper.GetValue<Guid>(data, "user_id") : (Guid?)null;
            var returnedTenantId = success ? DapperHelper.GetValue<Guid>(data, "tenant_id") : (Guid?)null;

            return (success, userId, returnedTenantId);
        }

        public async Task<bool> UpdatePasswordByUserIdAsync(Guid userId, Guid tenantId, string passwordHash)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.ExecuteScalarAsync<bool>(@"
                SELECT auth.fn_update_password_by_user_id(@userId, @tenantId, @passwordHash)
            ", new { userId, tenantId, passwordHash });

            return result;
        }

        public async Task<string?> GetUsernameByEmailAsync(string email, Guid tenantId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.ExecuteScalarAsync<string>(@"
                SELECT auth.fn_get_username_by_email(@email, @tenantId)
            ", new { email, tenantId });

            return result;
        }

        public async Task<Guid?> GetTenantIdByEmailAsync(string email)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.ExecuteScalarAsync<Guid?>(@"
                SELECT auth.fn_get_tenant_id_by_email(@email)
            ", new { email });

            return result;
        }

        public async Task<Guid?> GetTenantIdFromResetTokenAsync(string token)
        {
            using var conn = _db.CreateConnection();
            var tokenHash = HashToken(token);

            var result = await conn.ExecuteScalarAsync<Guid?>(@"
                SELECT auth.fn_get_tenant_id_from_reset_token(@tokenHash)
            ", new { tokenHash });

            return result;
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashBytes);
        }
    }
}
// ==========================================================================
// SERVICE
// ==========================================================================
namespace KeiroGenesis.API.Services
{
    public class AuthService
    {
        private readonly Repositories.AuthRepository _repo;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthService> _logger;
        private readonly IEmailProvider _emailService;
        private readonly IdentitySignalsService _identityService;
        private readonly ContentRatingsService _ratingService;



        public AuthService(
            Repositories.AuthRepository repo,
            IConfiguration config,
            ILogger<AuthService> logger,
            IEmailProvider emailService, IdentitySignalsService identityService,
            ContentRatingsService ratingService)
        {
            _repo = repo;
            _config = config;
            _identityService = identityService;
            _ratingService = ratingService;
            _logger = logger;
            _emailService = emailService;
        }


        // Hash password using BCrypt
        private string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, 12);
        }

        // Verify password using BCrypt
        private bool VerifyPassword(string password, string passwordHash)
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }

        public async Task<string> GenerateAccessTokenAsync(
            Guid userId,
            Guid tenantId,
            string email,
            string username,
            string? contentRating = null,  // ← Optional: pass rating during registration
            string[]? roles = null)
        {
            var secret = _config["Auth:Secret"]
                ?? throw new InvalidOperationException("Auth:Secret not configured");

            var issuer = _config["Auth:Issuer"]
                ?? throw new InvalidOperationException("Auth:Issuer not configured");

            var audience = _config["Auth:Audience"]
                ?? throw new InvalidOperationException("Auth:Audience not configured");

            var securityKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(secret)
            );

            var credentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha256
            );

            // ✅ Fetch identity verification status
            var identityStatus = await _identityService.GetProfileStatusAsync(tenantId, userId);

            // ✅ Fetch or use provided content rating
            string allowedRating;
            if (contentRating != null)
            {
                // Registration scenario - rating was just created and passed in
                allowedRating = contentRating;
            }
            else
            {
                // Token refresh scenario - fetch existing rating
                var ratingStatus = await _ratingService.GetRatingStatusAsync(tenantId, userId);
                allowedRating = ratingStatus.AllowedRating ?? "G";
            }

            var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
        new Claim(JwtRegisteredClaimNames.Email, email),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim("user_id", userId.ToString()),
        new Claim("tenant_id", tenantId.ToString()),
        new Claim("username", username),

        // -------------------------------
        // IDENTITY VERIFICATION (SIGNALS)
        // -------------------------------
        new Claim("verification_level", identityStatus.VerificationLevel.ToString()),
        new Claim("age_verified", identityStatus.AgeVerified.ToString().ToLower()),
        new Claim("age_category", identityStatus.AgeCategory.ToString()),
        new Claim("human_verified", identityStatus.HumanVerified.ToString().ToLower()),
        new Claim("government_id_verified", identityStatus.GovernmentIDVerified.ToString().ToLower()),
        
        // -------------------------------
        // CONTENT RATING (DECISIONS)
        // -------------------------------
        new Claim("allowed_rating", allowedRating),
        new Claim("content_level", MapRatingToContentLevel(allowedRating))
    };

            if (roles != null)
            {
                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_config.GetValue<int>("Auth:AccessTokenExpiryMinutes", 15)),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Generate JWT Access Token with roles
        // Generate JWT Access Token with roles
        //        public async Task<string> GenerateAccessTokenAsync(
        //            Guid userId,
        //            Guid tenantId,
        //            string email,
        //            string username, 
        //            string contentRating,
        //            string[]? roles = null)
        //        {
        //            var secret = _config["Auth:Secret"]
        //                ?? throw new InvalidOperationException("Auth:Secret not configured");

        //            var issuer = _config["Auth:Issuer"]
        //                ?? throw new InvalidOperationException("Auth:Issuer not configured");

        //            var audience = _config["Auth:Audience"]
        //                ?? throw new InvalidOperationException("Auth:Audience not configured");

        //            var securityKey = new SymmetricSecurityKey(
        //                Encoding.UTF8.GetBytes(secret)
        //            );

        //            var credentials = new SigningCredentials(
        //                securityKey,
        //                SecurityAlgorithms.HmacSha256
        //            );

        //            // ✅ Fetch identity verification status
        //            var identityStatus = await _identityService.GetProfileStatusAsync(tenantId, userId);

        //            // ✅ Fetch content rating status  
        //            var ratingStatus = await _ratingService.GetRatingStatusAsync(tenantId, userId);

        //            var claims = new List<Claim>
        //        {
        //        new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
        //        new Claim(JwtRegisteredClaimNames.Email, email),
        //        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //        new Claim("user_id", userId.ToString()),
        //        new Claim("tenant_id", tenantId.ToString()),
        //        new Claim("username", username),

        //        // -------------------------------
        //        // IDENTITY VERIFICATION (SIGNALS)
        //        // -------------------------------
        //        new Claim("verification_level", identityStatus.VerificationLevel.ToString()),
        //        new Claim("age_verified", identityStatus.AgeVerified.ToString().ToLower()),
        //        new Claim("age_category", identityStatus.AgeCategory.ToString()),
        //        new Claim("human_verified", identityStatus.HumanVerified.ToString().ToLower()),
        //        new Claim("government_id_verified", identityStatus.GovernmentIDVerified.ToString().ToLower()),

        //        // -------------------------------
        //        // CONTENT RATING (DECISIONS)
        //        // -------------------------------
        //        new Claim("allowed_rating", contentRating ?? "G"),


        //new Claim("allowed_rating", contentRating ?? "G"),
        //        new Claim("content_level", MapRatingToContentLevel(contentRating ?? "G"))
        //    };

        //            if (roles != null)
        //            {
        //                foreach (var role in roles)
        //                {
        //                    claims.Add(new Claim(ClaimTypes.Role, role));
        //                }
        //            }

        //            // ✅ Get token expiry from config (your existing pattern)
        //            var accessTokenExpiryMinutes = _config.GetValue<int>("Auth:AccessTokenExpiryMinutes", 15);

        //            var token = new JwtSecurityToken(
        //                issuer: issuer,
        //                audience: audience,
        //                claims: claims,
        //                expires: DateTime.UtcNow.AddMinutes(accessTokenExpiryMinutes),
        //                signingCredentials: credentials
        //            );

        //            return new JwtSecurityTokenHandler().WriteToken(token);
        //        }

        // ✅ Add this helper method to AuthService
        private static string MapRatingToContentLevel(string allowedRating)
        {
            return allowedRating?.ToUpper() switch
            {
                "G" => "general",
                "PG" => "general",
                "PG-13" => "mature",
                "R" => "mature",
                "NC-17" => "mature",
                _ => "restricted"
            };
        }

        // Generate Refresh Token
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        // Hash refresh token
        private string HashRefreshToken(string token)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashBytes);
        }


        // Register user
        public async Task<RegisterResponse> RegisterAsync(RegisterRequest request)
        {
            try
            {
                if (await _repo.EmailExistsAsync(request.Email))
                {
                    return new RegisterResponse
                    {
                        Success = false,
                        Message = "Email already exists"
                    };
                }

                if (await _repo.UsernameExistsAsync(request.Username))
                {
                    return new RegisterResponse
                    {
                        Success = false,
                        Message = "Username already exists"
                    };
                }

                // Optional: Client-side age validation
                if (request.DateOfBirth.HasValue)
                {
                    var age = DateTime.UtcNow.Year - request.DateOfBirth.Value.Year;
                    if (request.DateOfBirth.Value > DateTime.UtcNow.AddYears(-age)) age--;

                    if (age < 13)
                    {
                        return new RegisterResponse
                        {
                            Success = false,
                            Message = "You must be at least 13 years old to register (COPPA compliance)"
                        };
                    }

                    if (request.DateOfBirth.Value > DateTime.UtcNow)
                    {
                        return new RegisterResponse
                        {
                            Success = false,
                            Message = "Date of birth cannot be in the future"
                        };
                    }

                    if (age > 120)
                    {
                        return new RegisterResponse
                        {
                            Success = false,
                            Message = "Invalid date of birth"
                        };
                    }
                }

                // Hash password and set it on request
                request.PasswordHash = HashPassword(request.Password);

                // Call repository
                var result = await _repo.RegisterUserAsync(request);

                if (!result.Success || result.UserId == null || result.TenantId == null)
                {
                    return result;
                }

                // ✅ CREATE rating profile during registration
                var contentRating = await _ratingService.InitializeRatingProfileAsync(
                    result.TenantId.Value,
                    result.UserId.Value,
                    request.DateOfBirth
                );


                // ✅ CREATE identity profile
                await _identityService.CreateIdentityProfileAsync(result.TenantId.Value, result.UserId.Value);


                // Generate tokens
                var accessToken = await GenerateAccessTokenAsync(
                    result.UserId.Value,
                    result.TenantId.Value,
                    result.Email ?? request.Email,
                    result.Username ?? request.Username,
                    contentRating,
                    new[] { "owner" }
                );

                var refreshToken = GenerateRefreshToken();
                var refreshTokenHash = HashRefreshToken(refreshToken);

                var refreshTokenExpiryDays = _config.GetValue<int>("Auth:RefreshTokenExpiryDays", 7);

                await _repo.StoreRefreshTokenAsync(
                    result.UserId.Value,
                    result.TenantId.Value,
                    refreshTokenHash,
                    DateTime.UtcNow.AddDays(refreshTokenExpiryDays)
                );

                // Add tokens to result
                result.AccessToken = accessToken;
                result.RefreshToken = refreshToken;
                result.ContentEligibilityLevel = contentRating;
                result.Success = true;
                result.Message = "Registration successful";

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration");

                if (ex.Message.Contains("COPPA") || ex.Message.Contains("13 years old"))
                {
                    return new RegisterResponse
                    {
                        Success = false,
                        Message = "You must be at least 13 years old to register (COPPA compliance)"
                    };
                }

                return new RegisterResponse
                {
                    Success = false,
                    Message = "Registration failed: " + ex.Message
                };
            }
        }

        // Login user
        public async Task<LoginResponse> LoginAsync(LoginRequest request)
        {
            try
            {
                var user = await _repo.GetUserByEmailAsync(request.Email);

                if (user == null)
                {
                    return new LoginResponse
                    {
                        Success = false,
                        Message = "Invalid email or password"
                    };
                }

                if (!VerifyPassword(request.Password, user.password_hash))
                {
                    return new LoginResponse
                    {
                        Success = false,
                        Message = "Invalid email or password"
                    };
                }

                if (!user.is_active)
                {
                    return new LoginResponse
                    {
                        Success = false,
                        Message = "Account is inactive"
                    };
                }

                var userId = (Guid)user.user_id;
                var tenantId = (Guid)user.tenant_id;
                var username = (string)user.username;
                var email = (string)user.email;
                

                IEnumerable<int> roleIds = await _repo.GetUserRolesAsync(userId, tenantId);
                var roleArray = roleIds.Select(id => id switch
                {
                    1 => "owner",
                    2 => "admin",
                    3 => "member",
                    _ => "member"
                }).ToArray();

                var contentRating = await _ratingService.GetRatingStatusAsync(tenantId, userId);


                var accessToken = await GenerateAccessTokenAsync(
                    userId,
                    tenantId,
                    email,
                    username,
                    null,
                    roleArray
                );

                var refreshToken = GenerateRefreshToken();
                var refreshTokenHash = HashRefreshToken(refreshToken);

                var refreshTokenExpiryDays = request.RememberMe
                    ? _config.GetValue<int>("Auth:RememberMeRefreshTokenExpiryDays", 90)
                    : _config.GetValue<int>("Auth:RefreshTokenExpiryDays", 7);

                await _repo.StoreRefreshTokenAsync(
                    userId,
                    tenantId,
                    refreshTokenHash,
                    DateTime.UtcNow.AddDays(refreshTokenExpiryDays)
                );

                return new LoginResponse
                {
                    Success = true,
                    Message = "Login successful",
                    UserId = userId,
                    TenantId = tenantId,
                    Username = username,
                    Email = email,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    RememberMe = request.RememberMe
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return new LoginResponse
                {
                    Success = false,
                    Message = "Login failed: " + ex.Message
                };
            }
        }

        // Refresh token
        public async Task<RefreshTokenResponse> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                var tokenHash = HashRefreshToken(refreshToken);
                var storedToken = await _repo.ValidateRefreshTokenAsync(tokenHash);

                if (storedToken == null)
                {
                    return new RefreshTokenResponse
                    {
                        Success = false,
                        Message = "Invalid or expired refresh token"
                    };
                }

                var userId = (Guid)storedToken.user_id;
                var tenantId = (Guid)storedToken.tenant_id;

                await _repo.RevokeRefreshTokenAsync((Guid)storedToken.token_id);

                var user = await _repo.GetUserByIdAsync(userId);

                if (user == null)
                {
                    return new RefreshTokenResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                var email = (string)user.email;
                var username = (string)user.username;
               

                IEnumerable<int> roleIds = await _repo.GetUserRolesAsync(userId, tenantId);
                var roleArray = roleIds.Select(id => id switch
                {
                    1 => "owner",
                    2 => "admin",
                    3 => "member",
                    _ => "member"
                }).ToArray();


                // GET CONTENT RATINGS

                var contentRating = await _ratingService.GetRatingStatusAsync(tenantId, userId);

                var newAccessToken = await GenerateAccessTokenAsync(
                    userId,
                    tenantId,
                    email,
                    username,
                    null,
                    roleArray
                );

                var newRefreshToken = GenerateRefreshToken();
                var newRefreshTokenHash = HashRefreshToken(newRefreshToken);

                var NewRefreshTokenExpiryDays = _config.GetValue<int>("Auth:NewRefreshTokenExpiryDays", 7);

                await _repo.StoreRefreshTokenAsync(
                    userId,
                    tenantId,
                    newRefreshTokenHash,
                    DateTime.UtcNow.AddDays(NewRefreshTokenExpiryDays)
                );

                return new RefreshTokenResponse
                {
                    Success = true,
                    Message = "Token refreshed",
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token refresh");
                return new RefreshTokenResponse { Success = false, Message = "Token refresh failed: " + ex.Message };
            }
        }

        // Revoke Token
        public async Task<bool> RevokeTokenAsync(string refreshToken)
        {
            try
            {
                var tokenHash = HashRefreshToken(refreshToken);
                var storedToken = await _repo.ValidateRefreshTokenAsync(tokenHash);

                if (storedToken != null)
                {
                    await _repo.RevokeRefreshTokenAsync((Guid)storedToken.token_id);
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking token");
                return false;
            }
        }

        // Logout (revoke all tokens)
        public async Task LogoutAsync(Guid userId, Guid tenantId)
        {
            await _repo.RevokeAllUserTokensAsync(userId, tenantId);
        }

        // ============================================================
        // PASSWORD MANAGEMENT
        // ============================================================

        public async Task<ForgotPasswordResponse> ForgotPasswordAsync(string email)
        {
            try
            {
                var tenantId = await _repo.GetTenantIdByEmailAsync(email);
                if (tenantId == null || tenantId == Guid.Empty)
                {
                    _logger.LogWarning("Password reset requested for non-existent email: {Email}", email);
                    return new ForgotPasswordResponse
                    {
                        Success = true,
                        Message = "If an account exists with that email, a password reset link has been sent."
                    };
                }

                var tokenBytes = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(tokenBytes);
                }
                var resetToken = Convert.ToBase64String(tokenBytes)
                    .Replace("+", "-")
                    .Replace("/", "_")
                    .Replace("=", "");

                var expiresAt = DateTime.UtcNow.AddHours(1);
                var stored = await _repo.StorePasswordResetTokenAsync(email, tenantId.Value, resetToken, expiresAt);

                if (!stored)
                {
                    _logger.LogWarning("Failed to store reset token for {Email}", email);
                    return new ForgotPasswordResponse
                    {
                        Success = true,
                        Message = "If an account exists with that email, a password reset link has been sent."
                    };
                }

                // ✅ SEND ACTUAL EMAIL
                var resetLink = $"{_config["App:BaseUrl"]}/reset-password?token={resetToken}";

                // Get username for email
                var user = await _repo.GetUserByEmailAsync(email);
                var username = user != null ? DapperHelper.GetValue<string>(user, "username") : "User";

                await _emailService.SendPasswordResetEmailAsync(email, username, resetLink);

                _logger.LogInformation("Password reset email sent to {Email}", email);

                return new ForgotPasswordResponse
                {
                    Success = true,
                    Message = "If an account exists with that email, a password reset link has been sent."
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ForgotPasswordAsync");
                return new ForgotPasswordResponse
                {
                    Success = true,
                    Message = "If an account exists with that email, a password reset link has been sent."
                };
            }
        }

        public async Task<ValidateResetTokenResponse> ValidateResetTokenAsync(string token)
        {
            try
            {
                var tenantId = await _repo.GetTenantIdFromResetTokenAsync(token);
                if (tenantId == null || tenantId == Guid.Empty)
                {
                    return new ValidateResetTokenResponse
                    {
                        Success = true,
                        IsValid = false,
                        Message = "Invalid or expired token"
                    };
                }

                var tokenData = await _repo.ValidatePasswordResetTokenAsync(token, tenantId.Value);
                var isValid = tokenData != null;

                return new ValidateResetTokenResponse
                {
                    Success = true,
                    IsValid = isValid,
                    Message = isValid ? "Token is valid" : "Invalid or expired token"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating reset token");
                return new ValidateResetTokenResponse
                {
                    Success = false,
                    IsValid = false,
                    Message = "Error validating token"
                };
            }
        }

        public async Task<ResetPasswordResponse> ResetPasswordAsync(string token, string newPassword)
        {
            try
            {
                var tenantId = await _repo.GetTenantIdFromResetTokenAsync(token);
                if (tenantId == null || tenantId == Guid.Empty)
                {
                    return new ResetPasswordResponse
                    {
                        Success = false,
                        Message = "Invalid or expired reset token"
                    };
                }

                var tokenData = await _repo.ValidatePasswordResetTokenAsync(token, tenantId.Value);
                if (tokenData == null)
                {
                    return new ResetPasswordResponse
                    {
                        Success = false,
                        Message = "Invalid or expired reset token"
                    };
                }

                var email = DapperHelper.GetValue<string>(tokenData, "email");
                var passwordHash = HashPassword(newPassword);

                // FIX: Don't deconstruct - access properties directly
                var updateResult = await _repo.UpdatePasswordByEmailAsync(email, tenantId.Value, passwordHash);
                bool success = updateResult.success;
                Guid? userId = updateResult.userId;

                if (success && userId.HasValue)
                {
                    await _repo.InvalidatePasswordResetTokenAsync(token, tenantId.Value);
                    await _repo.RevokeAllUserTokensAsync(userId.Value, tenantId.Value);

                    _logger.LogInformation("Password reset successful for email: {Email}", (string) email);

                    return new ResetPasswordResponse
                    {
                        Success = true,
                        Message = "Password has been reset successfully. You can now login."
                    };
                }

                return new ResetPasswordResponse
                {
                    Success = false,
                    Message = "Failed to reset password"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password");
                return new ResetPasswordResponse
                {
                    Success = false,
                    Message = "Failed to reset password"
                };
            }
        }

        public async Task<ChangePasswordResponse> ChangePasswordAsync(
            Guid userId,
            Guid tenantId,
            string currentPassword,
            string newPassword)
        {
            try
            {
                var user = await _repo.GetUserByIdAsync(userId);
                if (user == null)
                {
                    return new ChangePasswordResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                var storedPasswordHash = DapperHelper.GetValue<string>(user, "password_hash");

                if (!VerifyPassword(currentPassword, storedPasswordHash))
                {
                    _logger.LogWarning("Change password failed - incorrect current password for user: {UserId}", userId);
                    return new ChangePasswordResponse
                    {
                        Success = false,
                        Message = "Current password is incorrect"
                    };
                }

                var newPasswordHash = HashPassword(newPassword);
                var updated = await _repo.UpdatePasswordByUserIdAsync(userId, tenantId, newPasswordHash);

                if (updated)
                {
                    _logger.LogInformation("Password changed successfully for user: {UserId}", userId);
                    return new ChangePasswordResponse
                    {
                        Success = true,
                        Message = "Password changed successfully"
                    };
                }

                return new ChangePasswordResponse
                {
                    Success = false,
                    Message = "Failed to change password"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password for user: {UserId}", userId);
                return new ChangePasswordResponse
                {
                    Success = false,
                    Message = "Failed to change password"
                };
            }
        }

        public async Task<ForgotUsernameResponse> ForgotUsernameAsync(string email)
        {
            try
            {
                var tenantId = await _repo.GetTenantIdByEmailAsync(email);
                if (tenantId == null || tenantId == Guid.Empty)
                {
                    _logger.LogWarning("Username reminder requested for non-existent email: {Email}", email);
                    return new ForgotUsernameResponse
                    {
                        Success = true,
                        Message = "If an account exists with that email, your username has been sent."
                    };
                }

                var username = await _repo.GetUsernameByEmailAsync(email, tenantId.Value);

                if (string.IsNullOrEmpty(username))
                {
                    _logger.LogWarning("Username not found for email: {Email}", email);
                    return new ForgotUsernameResponse
                    {
                        Success = true,
                        Message = "If an account exists with that email, your username has been sent."
                    };
                }

                _logger.LogInformation("Username reminder sent for {Email}", email);

                return new ForgotUsernameResponse
                {
                    Success = true,
                    Message = "If an account exists with that email, your username has been sent."
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ForgotUsernameAsync");
                return new ForgotUsernameResponse
                {
                    Success = true,
                    Message = "If an account exists with that email, your username has been sent."
                };
            }
        }
    }

    // ============================================================
    // REQUEST/RESPONSE CLASSES
    // ============================================================

    public class RegisterRequest
    {
        [JsonPropertyName("email")]
        public string Email { get; set; } = string.Empty;

        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        [JsonPropertyName("password")]
        public string Password { get; set; } = string.Empty;

        [JsonPropertyName("first_name")]
        public string? FirstName { get; set; }

        [JsonPropertyName("last_name")]
        public string? LastName { get; set; }

        [JsonPropertyName("tenant_name")]
        public string? TenantName { get; set; }

        public string PasswordHash { get; set; }  // Internal - not from JSON

        [JsonPropertyName("date_of_birth")]
        public DateTime? DateOfBirth { get; set; }

        [JsonPropertyName("gender")]
        public string? Gender { get; set; }

        [JsonPropertyName("mobile_number")]
        public string? MobileNumber { get; set; }
    }

    public class RegisterResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public Guid? UserId { get; set; }
        public Guid? TenantId { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }

        // NEW FIELDS - User profile info
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? TenantName { get; set; }

        // NEW FIELDS - Content rating & age
        public string? ContentEligibilityLevel { get; set; }  // "G", "PG", "PG-13", "R", "NC-17"
        public int? Age { get; set; }
    }

    public class LoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool RememberMe { get; set; }
    }

    public class LoginResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public Guid? UserId { get; set; }
        public Guid? TenantId { get; set; }
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public bool RememberMe { get; set; }
    }

    public class RefreshTokenResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }

    public class ForgotPasswordRequest
    {
        public string Email { get; set; } = string.Empty;
    }

    public class ForgotPasswordResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class ValidateResetTokenRequest
    {
        public string Token { get; set; } = string.Empty;
    }

    public class ValidateResetTokenResponse
    {
        public bool Success { get; set; }
        public bool IsValid { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class ResetPasswordRequest
    {
        public string Token { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }

    public class ResetPasswordResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class ChangePasswordRequest
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }

    public class ChangePasswordResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class ForgotUsernameRequest
    {
        public string Email { get; set; } = string.Empty;
    }

    public class ForgotUsernameResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
// ==========================================================================
// CONTROLLER
// ==========================================================================
namespace KeiroGenesis.API.Controllers.V1
{
    [Route("api/v1/[controller]")]
    [Authorize]
    public class AuthController : ControllerBase
    {
        private readonly Services.AuthService _service;
        private readonly IWebHostEnvironment _env;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            Services.AuthService service,
            IWebHostEnvironment env,
            IConfiguration config,
            ILogger<AuthController> logger)
        {
            _service = service;
            _env = env;
            _config = config;
            _logger = logger;
        }

        // Build cookie options based on environment
        private CookieOptions BuildRefreshCookieOptions(bool rememberMe)
        {
            var rememberMeExpiryDays = _config.GetValue<int>("Auth:RememberMeRefreshTokenExpiryDays", 90);

            if (_env.IsDevelopment() || _env.EnvironmentName == "Local")
            {
                return new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false,
                    SameSite = SameSiteMode.Lax,
                    Domain = null,
                    Path = "/",
                    Expires = rememberMe ? DateTime.UtcNow.AddDays(rememberMeExpiryDays) : null
                };
            }

            var cookieDomain = _config["Auth:CookieDomain"] ?? ".keirogenesis.com";

            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Domain = cookieDomain,
                Path = "/",
                Expires = rememberMe ? DateTime.UtcNow.AddDays(rememberMeExpiryDays) : null
            };
        }

   


        private Guid GetCurrentUserId()
        {
            var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                     ?? User.FindFirst("sub")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var userId))
                throw new UnauthorizedAccessException("Invalid user claim");
            return userId;
        }
        // Helper to get claims
        private Guid GetTenantId()
        {
            var claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var tenantId))
                throw new UnauthorizedAccessException("Invalid tenant claim");
            return tenantId;
        }


        /// <summary>
        /// Register a new user
        /// </summary>
        [HttpPost("register")]
        [AllowAnonymous]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> Register([FromBody] Services.RegisterRequest request)
        {
            var result = await _service.RegisterAsync(request);

            if (result.Success && !string.IsNullOrWhiteSpace(result.RefreshToken))
            {
                Response.Cookies.Append("refresh_token", result.RefreshToken, BuildRefreshCookieOptions(false));
            }

            return result.Success ? Ok(result) : BadRequest(result);
        }

        /// <summary>
        /// Login user
        /// </summary>
        [HttpPost("login")]
        [AllowAnonymous]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> Login([FromBody] Services.LoginRequest request)
        {
            var result = await _service.LoginAsync(request);

            if (result.Success && !string.IsNullOrWhiteSpace(result.RefreshToken))
            {
                Response.Cookies.Append("refresh_token", result.RefreshToken, BuildRefreshCookieOptions(request.RememberMe));
            }

            return result.Success ? Ok(result) : Unauthorized(result);
        }

        /// <summary>
        /// Refresh access token using refresh token from cookie
        /// </summary>
        [HttpPost("refresh")]
        [AllowAnonymous]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> Refresh()
        {
            var refreshToken = Request.Cookies["refresh_token"];

            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return BadRequest(new { Success = false, Message = "Refresh token not found" });
            }

            var result = await _service.RefreshTokenAsync(refreshToken);

            if (result.Success && !string.IsNullOrWhiteSpace(result.RefreshToken))
            {
                Response.Cookies.Append("refresh_token", result.RefreshToken, BuildRefreshCookieOptions(true));
            }

            return result.Success ? Ok(result) : BadRequest(result);
        }

        /// <summary>
        /// Logout user (revoke all refresh tokens)
        /// </summary>
        [HttpPost("logout")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> Logout()
        {
            var userId = GetCurrentUserId();
            var tenantId = GetTenantId();

            await _service.LogoutAsync(userId, tenantId);
            Response.Cookies.Delete("refresh_token");

            return Ok(new { Success = true, Message = "Logged out successfully" });
        }

        /// <summary>
        /// Revoke a specific refresh token
        /// </summary>
        [HttpPost("revoke")]
        [AllowAnonymous]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> Revoke()
        {
            var refreshToken = Request.Cookies["refresh_token"];

            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return BadRequest(new { Success = false, Message = "Refresh token not found" });
            }

            var success = await _service.RevokeTokenAsync(refreshToken);

            if (success)
            {
                Response.Cookies.Delete("refresh_token");
            }

            return success
                ? Ok(new { Success = true, Message = "Token revoked" })
                : BadRequest(new { Success = false, Message = "Invalid token" });
        }

        /// <summary>
        /// Get current user info from JWT claims
        /// </summary>
        [HttpGet("profile")]
        [ProducesResponseType(200)]
        public IActionResult Profile()
        {
            var userId = GetCurrentUserId();
            var tenantId = GetTenantId();
            var email = User.FindFirst(ClaimTypes.Email)?.Value ?? User.FindFirst(JwtRegisteredClaimNames.Email)?.Value;
            var username = User.FindFirst("username")?.Value;

            return Ok(new
            {
                userId,
                tenantId,
                email,
                username
            });
        }

        /// <summary>
        /// Request password reset email
        /// </summary>
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> ForgotPassword([FromBody] Services.ForgotPasswordRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.Email))
            {
                return BadRequest(new { Success = false, Message = "Email is required" });
            }

            var result = await _service.ForgotPasswordAsync(request.Email);
            return Ok(result);
        }

        /// <summary>
        /// Validate password reset token
        /// </summary>
        [HttpPost("validate-reset-token")]
        [AllowAnonymous]
        [ProducesResponseType(200)]
        public async Task<IActionResult> ValidateResetToken([FromBody] Services.ValidateResetTokenRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.Token))
            {
                return BadRequest(new { Success = false, Message = "Token is required" });
            }

            var result = await _service.ValidateResetTokenAsync(request.Token);
            return Ok(result);
        }

        /// <summary>
        /// Reset password using token from email
        /// </summary>
        [HttpPost("reset-password")]
        [AllowAnonymous]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> ResetPassword([FromBody] Services.ResetPasswordRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.NewPassword))
            {
                return BadRequest(new { Success = false, Message = "Token and new password are required" });
            }

            if (request.NewPassword.Length < 8)
            {
                return BadRequest(new { Success = false, Message = "Password must be at least 8 characters" });
            }

            var result = await _service.ResetPasswordAsync(request.Token, request.NewPassword);
            return result.Success ? Ok(result) : BadRequest(result);
        }

        /// <summary>
        /// Change password for authenticated user
        /// </summary>
        [HttpPost("change-password")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> ChangePassword([FromBody] Services.ChangePasswordRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.CurrentPassword) || string.IsNullOrWhiteSpace(request.NewPassword))
            {
                return BadRequest(new { Success = false, Message = "Current and new passwords are required" });
            }

            if (request.NewPassword.Length < 8)
            {
                return BadRequest(new { Success = false, Message = "New password must be at least 8 characters" });
            }

            var userId = GetCurrentUserId();
            var tenantId = GetTenantId();

            var result = await _service.ChangePasswordAsync(userId, tenantId, request.CurrentPassword, request.NewPassword);
            return result.Success ? Ok(result) : BadRequest(result);
        }

        /// <summary>
        /// Request username reminder email
        /// </summary>
        [HttpPost("forgot-username")]
        [AllowAnonymous]
        [ProducesResponseType(200)]
        public async Task<IActionResult> ForgotUsername([FromBody] Services.ForgotUsernameRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.Email))
            {
                return BadRequest(new { Success = false, Message = "Email is required" });
            }

            var result = await _service.ForgotUsernameAsync(request.Email);
            return Ok(result);
        }

        /// <summary>
        /// JWT INSPECT (jwt.io equivalent)
        /// </summary>
        [HttpPost("jwt/inspect")]
        [Authorize]
        public IActionResult InspectJwt([FromBody] dynamic body)
        {
            if (body == null || body.token == null)
            {
                return BadRequest(new { error = "Token is required" });
            }

            string token = (string)body.token;
            bool verify = body.verifySignature != null && (bool)body.verifySignature;

            var handler = new JwtSecurityTokenHandler();

            try
            {
                JwtSecurityToken jwt;

                if (verify)
                {
                    var secret = _config["Auth:SecretKey"]
                        ?? throw new InvalidOperationException("JWT SecretKey missing");

                    handler.ValidateToken(
                        token,
                        new TokenValidationParameters
                        {
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = new SymmetricSecurityKey(
                                Encoding.UTF8.GetBytes(secret)
                            ),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false
                        },
                        out var validatedToken
                    );

                    jwt = (JwtSecurityToken)validatedToken;
                }
                else
                {
                    jwt = handler.ReadJwtToken(token);
                }

                return Ok(new
                {
                    valid = true,
                    header = jwt.Header,
                    payload = jwt.Payload,
                    claims = jwt.Claims.Select(c => new
                    {
                        c.Type,
                        c.Value
                    }),
                    issuer = jwt.Issuer,
                    audience = jwt.Audiences,
                    expiresAtUtc = jwt.ValidTo,
                    issuedAtUtc = jwt.ValidFrom
                });
            }
            catch (Exception ex)
            {
                return Ok(new
                {
                    valid = false,
                    error = ex.Message
                });
            }
        }
    }
}