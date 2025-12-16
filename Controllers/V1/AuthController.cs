// ==========================================================================
// AUTH MODULE — Authentication & Token Management
// Single file: Repository + Service + Controller
// NO DTOs, NO Interfaces - Simple request/response classes
// HTTP Cookies + JWT Token Generation
// ==========================================================================

using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Core.Helpers;
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
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

// ==========================================================================
// ==========================================================================
// ==========================================================================
#region Repository
// ==========================================================================
// ==========================================================================
#region Repository - FIXED - ALL FUNCTIONS, NO RAW SQL
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

        // Register new user + tenant
        public async Task<dynamic?> RegisterUserAsync(
            string email, string username, string passwordHash,
            string firstName, string lastName, string tenantName)
        {
            using var conn = _db.CreateConnection();

            var sql = @"
                SELECT 
                    user_id,
                    tenant_id,
                    email,
                    username,
                    first_name,
                    last_name,
                    tenant_name
                FROM auth.fn_register_user(
                    @p_email,
                    @p_username,
                    @p_password_hash,
                    @p_first_name,
                    @p_last_name,
                    @p_tenant_name
                );
            ";

            var result = await conn.QueryAsync(sql, new
            {
                p_email = email,
                p_username = username,
                p_password_hash = passwordHash,
                p_first_name = firstName,
                p_last_name = lastName,
                p_tenant_name = tenantName
            });

            return result.FirstOrDefault();
        }

        // Login - get user by email
        public async Task<dynamic?> GetUserByEmailAsync(string email)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                @"SELECT 
                    user_id,
                    username,
                    email,
                    password_hash,
                    first_name,
                    last_name,
                    is_active,
                    created_at,
                    updated_at,
                    is_email_verified,
                    tenant_id,
                    tenant_name,
                    subscription_tier
                FROM auth.fn_get_user_by_email(@email)",
                new { email });

            return result.FirstOrDefault();
        }

        // Store refresh token - FIXED: Uses function
        public async Task<Guid> StoreRefreshTokenAsync(
            Guid userId, Guid tenantId, string tokenHash, DateTime expiresAt)
        {
            using var conn = _db.CreateConnection();

            return await conn.ExecuteScalarAsync<Guid>(
                "SELECT security.fn_store_refresh_token(@user_id, @tenant_id, @token_hash, @expires_at)",
                new
                {
                    user_id = userId,
                    tenant_id = tenantId,
                    token_hash = tokenHash,
                    expires_at = expiresAt
                });
        }

        // Validate refresh token - FIXED: Uses security schema
        public async Task<dynamic?> ValidateRefreshTokenAsync(string tokenHash)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                @"SELECT 
                    token_id,
                    user_id,
                    tenant_id,
                    expires_at
                FROM security.fn_validate_refresh_token(@token_hash)",
                new { token_hash = tokenHash });

            return result.FirstOrDefault();
        }

        // Revoke refresh token - FIXED: Uses security schema
        public async Task RevokeRefreshTokenAsync(Guid tokenId)
        {
            using var conn = _db.CreateConnection();

            await conn.ExecuteAsync(
                "SELECT security.fn_revoke_refresh_token(@token_id)",
                new { token_id = tokenId });
        }

        // Revoke all user tokens - FIXED: Uses security schema
        public async Task RevokeAllUserTokensAsync(Guid userId, Guid tenantId)
        {
            using var conn = _db.CreateConnection();

            await conn.ExecuteAsync(
                "SELECT security.fn_revoke_all_user_tokens(@user_id, @tenant_id)",
                new { user_id = userId, tenant_id = tenantId });
        }

        // Check if email exists - FIXED: Uses function
        public async Task<bool> EmailExistsAsync(string email)
        {
            using var conn = _db.CreateConnection();

            return await conn.ExecuteScalarAsync<bool>(
                "SELECT auth.fn_email_exists(@email)",
                new { email });
        }

        // Check if username exists - FIXED: Uses function
        public async Task<bool> UsernameExistsAsync(string username)
        {
            using var conn = _db.CreateConnection();

            return await conn.ExecuteScalarAsync<bool>(
                "SELECT auth.fn_username_exists(@username)",
                new { username });
        }

        // Get user by ID (for token refresh)
        public async Task<dynamic?> GetUserByIdAsync(Guid userId)
        {
            using var conn = _db.CreateConnection();

            var result = await conn.QueryAsync(
                @"SELECT 
                    user_id,
                    tenant_id,
                    email,
                    username,
                    password_hash,
                    first_name,
                    last_name
                FROM auth.fn_get_user_by_id(@user_id)",
                new { user_id = userId });

            return result.FirstOrDefault();
        }

        // Get user roles
        public async Task<IEnumerable<int>> GetUserRolesAsync(Guid userId, Guid tenantId)
        {
            using var conn = _db.CreateConnection();

            var roles = await conn.QueryAsync<int>(
                "SELECT role_id FROM security.fn_get_user_roles(@user_id, @tenant_id)",
                new { user_id = userId, tenant_id = tenantId }
            );

            return roles;
        }

        // UserRoleDetail class
        public class UserRoleDetail
        {
            public int RoleId { get; set; }
            public string RoleName { get; set; } = string.Empty;
        }

        // Get user role details - FIXED: Uses function
        public async Task<IEnumerable<UserRoleDetail>> GetUserRoleDetailsAsync(Guid userId, Guid tenantId)
        {
            using var conn = _db.CreateConnection();

            var roles = await conn.QueryAsync<UserRoleDetail>(
                @"SELECT 
                    role_id AS RoleId,
                    role_name AS RoleName
                FROM security.fn_get_user_role_details(@user_id, @tenant_id)",
                new { user_id = userId, tenant_id = tenantId }
            );

            return roles;
        }
    }
}
#endregion
#endregion

// ==========================================================================gen
#region Service
// ==========================================================================
namespace KeiroGenesis.API.Services
{
    public class AuthService
    {
        private readonly Repositories.AuthRepository _repo;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            Repositories.AuthRepository repo,
            IConfiguration config,
            ILogger<AuthService> logger)
        {
            _repo = repo;
            _config = config;
            _logger = logger;
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


        // Generate JWT Access Token with roles
        public string GenerateAccessToken(
          Guid userId,
          Guid tenantId,
          string email,
          string username,
          string[]? roles = null)
        {
            // 🔑 SINGLE SOURCE OF TRUTH
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

            var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
        new Claim(JwtRegisteredClaimNames.Email, email),
        new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        new Claim("tenant_id", tenantId.ToString()),
        new Claim("username", username),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

            // ✅ ROLE CLAIMS
            if (roles != null && roles.Length > 0)
            {
                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                    _logger.LogDebug("Added role claim: {Role}", role);
                }
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.Role, "member"));
                _logger.LogDebug("No roles provided, defaulting to member");
            }

            // ✅ READ FROM CONFIG - 240 - minutes/ 4 hours
            var accessTokenExpiryMinutes = _config.GetValue<int>("Auth:AccessTokenExpiryMinutes", 240);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(accessTokenExpiryMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Generate Refresh Token
        public string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        // Hash refresh token for storage
        private string HashRefreshToken(string token)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashBytes);
        }

        // Register User
        // ==========================================================================
        // COMPLETE FIX: RegisterAsync, LoginAsync, RefreshTokenAsync
        // All three methods now include roles in JWT tokens
        // Replace these methods in your AuthService
        // ==========================================================================

        // ========================================
        // FIX #1: RegisterAsync
        // ========================================
        public async Task<RegisterResponse> RegisterAsync(RegisterRequest request)
        {
            try
            {   
                // Validate
                if (string.IsNullOrWhiteSpace(request.Email) ||
                    string.IsNullOrWhiteSpace(request.Password) ||
                    string.IsNullOrWhiteSpace(request.Username))
                {
                    return new RegisterResponse { Success = false, Message = "Email, username, and password are required" };
                }

                // Check if email exists
                if (await _repo.EmailExistsAsync(request.Email))
                {
                    return new RegisterResponse { Success = false, Message = "Email already exists" };
                }

                // Check if username exists
                if (await _repo.UsernameExistsAsync(request.Username))
                {
                    return new RegisterResponse { Success = false, Message = "Username already exists" };
                }

                // Hash password
                var passwordHash = HashPassword(request.Password);

                // Business Rule: Username becomes the tenant name
                var tenantName = request.TenantName ?? request.Username;

                // Register user
                var user = await _repo.RegisterUserAsync(
                    request.Email,
                    request.Username,
                    passwordHash,
                    request.FirstName ?? "",
                    request.LastName ?? "",
                    tenantName
                );

                if (user == null)
                {
                    return new RegisterResponse { Success = false, Message = "Registration failed" };
                }

                // ✅ Extract user info using DapperHelper
                var userId = DapperHelper.GetValue<Guid>(user, "user_id");
                var tenantId = DapperHelper.GetValue<Guid>(user, "tenant_id");
                var email = DapperHelper.GetValue<string>(user, "email");
                var username = DapperHelper.GetValue<string>(user, "username");
                // Get Expire


              
                // ✅ Fetch role IDs and map to role names
                IEnumerable<int> roleIds = await _repo.GetUserRolesAsync(userId, tenantId);
                var roleArray = roleIds.Select(id => id switch
                {
                    1 => "owner",
                    2 => "admin",
                    3 => "member",
                    _ => "member"
                }).ToArray();

                _logger.LogInformation("User registered with roles: {Roles}", string.Join(", ", roleArray));

                // ✅ Generate tokens with roles
                var accessToken = GenerateAccessToken(
                    userId,
                    tenantId,
                    email,
                    username,
                    roleArray
                );

                var refreshToken = GenerateRefreshToken();
                var refreshTokenHash = HashRefreshToken(refreshToken);

                // ✅ READ FROM CONFIG
                var RefreshTokenExpiryDays = _config.GetValue<int>("Auth:RefreshTokenExpiryMinutes", 30);

                // Store refresh token
                await _repo.StoreRefreshTokenAsync(
                    userId,
                    tenantId,
                    refreshTokenHash,
                    DateTime.UtcNow.AddDays(RefreshTokenExpiryDays)
                );

                return new RegisterResponse
                {
                    Success = true,
                    Message = "Registration successful",
                    UserId = userId,
                    TenantId = tenantId,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration");
                return new RegisterResponse { Success = false, Message = "Registration failed: " + ex.Message };
            }
        }

        // ========================================
        // FIX #2: LoginAsync
        // ========================================
        public async Task<LoginResponse> LoginAsync(LoginRequest request)
        {
            try
            {
                // Get user
                var user = await _repo.GetUserByEmailAsync(request.Email);

                if (user == null)
                {
                    return new LoginResponse { Success = false, Message = "Invalid email or password" };
                }

                // Extract user info using DapperHelper
                var userId = DapperHelper.GetValue<Guid>(user, "user_id");
                var tenantId = DapperHelper.GetValue<Guid>(user, "tenant_id");
                var email = DapperHelper.GetValue<string>(user, "email");
                var username = DapperHelper.GetValue<string>(user, "username");
                var passwordHash = DapperHelper.GetValue<string>(user, "password_hash");

                // Verify password
                if (!VerifyPassword(request.Password, passwordHash))
                {
                    return new LoginResponse { Success = false, Message = "Invalid email or password" };
                }

                // ✅ NEW: Fetch role IDs and map to role names
                IEnumerable<int> roleIds = await _repo.GetUserRolesAsync(userId, tenantId);
                var roleArray = roleIds.Select(id => id switch
                {
                    1 => "owner",
                    2 => "admin",
                    3 => "member",
                    _ => "member"
                }).ToArray();

                _logger.LogInformation("User logged in with roles: {Roles}", string.Join(", ", roleArray));

                // ✅ Generate tokens with roles
                var accessToken = GenerateAccessToken(
                    userId,
                    tenantId,
                    email,
                    username,
                    roleArray
                );

                var refreshToken = GenerateRefreshToken();
                var refreshTokenHash = HashRefreshToken(refreshToken);
                // ✅ READ FROM CONFIG - Use correct key name
                var rememberMeExpiryDays = _config.GetValue<int>("Auth:RememberMeRefreshTokenExpiryDays", 90);
                var refreshTokenExpiryDays = _config.GetValue<int>("Auth:RefreshTokenExpiryDays", 30);

                // Store refresh token
                await _repo.StoreRefreshTokenAsync(
                    userId,
                    tenantId,
                    refreshTokenHash,
                    DateTime.UtcNow.AddDays(request.RememberMe ? rememberMeExpiryDays : refreshTokenExpiryDays)
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
                return new LoginResponse { Success = false, Message = "Login failed: " + ex.Message };
            }
        }

        // ========================================
        // FIX #3: RefreshTokenAsync
        // ========================================
        public async Task<RefreshTokenResponse> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                var tokenHash = HashRefreshToken(refreshToken);
                var storedToken = await _repo.ValidateRefreshTokenAsync(tokenHash);

                if (storedToken == null)
                {
                    return new RefreshTokenResponse { Success = false, Message = "Invalid refresh token" };
                }

                // Extract token info using DapperHelper
                var userId = DapperHelper.GetValue<Guid>(storedToken, "user_id");
                var tenantId = DapperHelper.GetValue<Guid>(storedToken, "tenant_id");
                var tokenId = DapperHelper.GetValue<Guid>(storedToken, "token_id");

                // Get current user info for JWT claims
                var user = await _repo.GetUserByIdAsync(userId);

                if (user == null)
                {
                    return new RefreshTokenResponse { Success = false, Message = "User not found" };
                }

                // Extract user info
                var email = DapperHelper.GetValue<string>(user, "email");
                var username = DapperHelper.GetValue<string>(user, "username");

                // Revoke old token (token rotation)
                await _repo.RevokeRefreshTokenAsync(tokenId);

                // ✅ Fetch role IDs and map to role names
                IEnumerable<int> roleIds = await _repo.GetUserRolesAsync(userId, tenantId);
                var roleArray = roleIds.Select(id => id switch
                {
                    1 => "owner",
                    2 => "admin",
                    3 => "member",
                    _ => "member"
                }).ToArray();

                _logger.LogInformation("Token refreshed with roles: {Roles}", string.Join(", ", roleArray));

                // ✅ Generate new tokens with roles
                var newAccessToken = GenerateAccessToken(
                    userId,
                    tenantId,
                    email,
                    username,
                    roleArray
                );

                var newRefreshToken = GenerateRefreshToken();
                var newRefreshTokenHash = HashRefreshToken(newRefreshToken);

                // ✅ READ FROM CONFIG - 7 days 
                var NewRefreshTokenExpiryDays = _config.GetValue<int>("Auth:NewRefreshTokenExpiryDays", 7);
                // Store new refresh token
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
    }

    // Simple Request/Response Classes (NO DTOs)
    public class RegisterRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? TenantName { get; set; }
    }

    public class RegisterResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public Guid? UserId { get; set; }
        public Guid? TenantId { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
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
}
#endregion

// ==========================================================================
#region Controller
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

            // ✅ READ FROM CONFIG
            var rememberMeExpiryDays = _config.GetValue<int>("Auth:RememberMeRefreshTokenExpiryDays", 90);
            // LOCAL DEV (localhost:5173 ↔ localhost:8080)
            if (_env.IsDevelopment() || _env.EnvironmentName == "Local")
            {
                return new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false,                // HTTP only
                    SameSite = SameSiteMode.Lax,   // CORRECT for localhost
                    Domain = null,                 // MUST be null
                    Path = "/",
                    Expires = rememberMe
                        ? DateTime.UtcNow.AddDays(rememberMeExpiryDays)
                        : null
                };
            }

            // PROD (keirogenesis.com)
            var cookieDomain = _config["Auth:CookieDomain"] ?? ".keirogenesis.com";

            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Domain = cookieDomain,
                Path = "/",
                Expires = rememberMe
                    ? DateTime.UtcNow.AddDays(rememberMeExpiryDays)
                    : null
            };
        }

        // Helper to get claims
        private Guid GetTenantId()
        {
            var claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var tenantId))
                throw new UnauthorizedAccessException("Invalid tenant claim");
            return tenantId;
        }

        private Guid GetCurrentUserId()
        {
            var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var userId))
                throw new UnauthorizedAccessException("Invalid user claim");
            return userId;
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
                // Set refresh token cookie
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
                // Set refresh token HTTP-only cookie
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
            // Get refresh token from cookie
            var refreshToken = Request.Cookies["refresh_token"];

            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return BadRequest(new { Success = false, Message = "Refresh token not found" });
            }

            var result = await _service.RefreshTokenAsync(refreshToken);

            if (result.Success && !string.IsNullOrWhiteSpace(result.RefreshToken))
            {
                // Set new refresh token cookie
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

            // Delete refresh token cookie
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
        [HttpGet("me")]
        [ProducesResponseType(200)]
        public IActionResult Me()
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

        // =========================================================================
        // JWT INSPECT (jwt.io equivalent)
        // =========================================================================
        [HttpPost("jwt/inspect")]
        [Authorize] // 🔒 remove if you want it fully open
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

                // -------------------------------------------------------------
                // OPTIONAL SIGNATURE VALIDATION (jwt.io style)
                // -------------------------------------------------------------
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
                            ValidateLifetime = false // jwt.io behavior
                        },
                        out var validatedToken
                    );

                    jwt = (JwtSecurityToken)validatedToken;
                }
                else
                {
                    jwt = handler.ReadJwtToken(token);
                }

                // -------------------------------------------------------------
                // RESPONSE (HEADER + PAYLOAD + CLAIMS)
                // -------------------------------------------------------------
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
#endregion