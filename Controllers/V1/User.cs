// ==========================================================================
// USER MODULE — User Profile Management
// Single file: Repository + Service + Controller
// ==========================================================================

using System;
using System.Threading.Tasks;
using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

#region Repository
namespace KeiroGenesis.API.Repositories
{
    public class UserRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<UserRepository> _logger;

        public UserRepository(IDbConnectionFactory db, ILogger<UserRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<dynamic?> GetUserAsync(Guid userId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM core.users WHERE user_id = @user_id",
                new { user_id = userId }
            );
        }
    }
}
#endregion

#region Service
namespace KeiroGenesis.API.Services
{
    public class UserService
    {
        private readonly UserRepository _repo;
        private readonly ILogger<UserService> _logger;

        public UserService(UserRepository repo, ILogger<UserService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public Task<dynamic?> GetUserAsync(Guid userId) => _repo.GetUserAsync(userId);
    }
}
#endregion

#region Controller
namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
    [Route("api/v1/[controller]")]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly UserService _service;

        public UserController(UserService service)
        {
            _service = service;
        }

        [HttpGet("get-user")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetUser()
        {
            var userId = GetCurrentUserId();
            var user = await _service.GetUserAsync(userId);
            return user != null ? Ok(user) : NotFound();
        }

        private Guid GetCurrentUserId()
        {
            var claim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                     ?? User.FindFirst("sub")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var userId))
                throw new UnauthorizedAccessException("Invalid user claim");
            return userId;
        }
    }
}
#endregion
