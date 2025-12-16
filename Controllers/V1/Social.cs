// ==========================================================================
// SOCIAL MODULE — Posts, Follows, Reactions, Comments
// Single file: Repository + Service + Controller
// ==========================================================================

using System;
using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

// ==========================================================================
#region Repository
// ==========================================================================
namespace KeiroGenesis.API.Repositories
{
    public class SocialRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<SocialRepository> _logger;

        public SocialRepository(IDbConnectionFactory db, ILogger<SocialRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        // -------------------- POSTS --------------------

        public async Task<dynamic> CreatePostAsync(
            Guid tenantId, Guid actorId, string content, string? mediaUrl, string visibility, Guid? replyToPostId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                @"SELECT * FROM social.fn_create_post(
                    @p_tenant_id, @p_actor_id, @p_content, @p_media_url, @p_visibility, @p_reply_to_post_id
                )",
                new
                {
                    p_tenant_id = tenantId,
                    p_actor_id = actorId,
                    p_content = content,
                    p_media_url = mediaUrl ?? (object)DBNull.Value,
                    p_visibility = visibility,
                    p_reply_to_post_id = replyToPostId ?? (object)DBNull.Value
                }
            );
        }

        public async Task<dynamic?> GetPostAsync(Guid tenantId, Guid postId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM social.fn_get_post(@p_tenant_id, @p_post_id)",
                new { p_tenant_id = tenantId, p_post_id = postId }
            );
        }

        public async Task<List<dynamic>> GetFeedAsync(Guid tenantId, Guid actorId, int limit, int offset)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM social.fn_get_feed(@p_tenant_id, @p_actor_id, @p_limit, @p_offset)",
                new { p_tenant_id = tenantId, p_actor_id = actorId, p_limit = limit, p_offset = offset }
            );
            return rows.AsList();
        }

        public async Task<List<dynamic>> GetPostsByActorAsync(Guid tenantId, Guid actorId, int limit, int offset)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM social.fn_get_posts_by_actor(@p_tenant_id, @p_actor_id, @p_limit, @p_offset)",
                new { p_tenant_id = tenantId, p_actor_id = actorId, p_limit = limit, p_offset = offset }
            );
            return rows.AsList();
        }

        public async Task<List<dynamic>> GetRepliesAsync(Guid tenantId, Guid postId, int limit, int offset)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM social.fn_get_replies(@p_tenant_id, @p_post_id, @p_limit, @p_offset)",
                new { p_tenant_id = tenantId, p_post_id = postId, p_limit = limit, p_offset = offset }
            );
            return rows.AsList();
        }

        public async Task DeletePostAsync(Guid tenantId, Guid postId, Guid actorId)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "CALL social.sp_delete_post(@p_tenant_id, @p_post_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_post_id = postId, p_actor_id = actorId }
            );
        }

        // -------------------- FOLLOWS --------------------

        public async Task FollowAsync(Guid tenantId, Guid followerActorId, Guid followedActorId)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "CALL social.sp_follow(@p_tenant_id, @p_follower_actor_id, @p_followed_actor_id)",
                new { p_tenant_id = tenantId, p_follower_actor_id = followerActorId, p_followed_actor_id = followedActorId }
            );
        }

        public async Task UnfollowAsync(Guid tenantId, Guid followerActorId, Guid followedActorId)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "CALL social.sp_unfollow(@p_tenant_id, @p_follower_actor_id, @p_followed_actor_id)",
                new { p_tenant_id = tenantId, p_follower_actor_id = followerActorId, p_followed_actor_id = followedActorId }
            );
        }

        public async Task<List<dynamic>> GetFollowersAsync(Guid tenantId, Guid actorId, int limit, int offset)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM social.fn_get_followers(@p_tenant_id, @p_actor_id, @p_limit, @p_offset)",
                new { p_tenant_id = tenantId, p_actor_id = actorId, p_limit = limit, p_offset = offset }
            );
            return rows.AsList();
        }

        public async Task<List<dynamic>> GetFollowingAsync(Guid tenantId, Guid actorId, int limit, int offset)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM social.fn_get_following(@p_tenant_id, @p_actor_id, @p_limit, @p_offset)",
                new { p_tenant_id = tenantId, p_actor_id = actorId, p_limit = limit, p_offset = offset }
            );
            return rows.AsList();
        }

        public async Task<bool> IsFollowingAsync(Guid tenantId, Guid followerActorId, Guid followedActorId)
        {
            using var conn = _db.CreateConnection();
            return await conn.ExecuteScalarAsync<bool>(
                "SELECT social.fn_is_following(@p_tenant_id, @p_follower_actor_id, @p_followed_actor_id)",
                new { p_tenant_id = tenantId, p_follower_actor_id = followerActorId, p_followed_actor_id = followedActorId }
            );
        }

        // -------------------- REACTIONS --------------------

        public async Task ReactToPostAsync(Guid tenantId, Guid postId, Guid actorId, string reactionType)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "CALL social.sp_react_to_post(@p_tenant_id, @p_post_id, @p_actor_id, @p_reaction_type)",
                new { p_tenant_id = tenantId, p_post_id = postId, p_actor_id = actorId, p_reaction_type = reactionType }
            );
        }

        public async Task RemoveReactionAsync(Guid tenantId, Guid postId, Guid actorId)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "CALL social.sp_remove_reaction(@p_tenant_id, @p_post_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_post_id = postId, p_actor_id = actorId }
            );
        }

        public async Task<List<dynamic>> GetReactionsAsync(Guid tenantId, Guid postId)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM social.fn_get_reactions(@p_tenant_id, @p_post_id)",
                new { p_tenant_id = tenantId, p_post_id = postId }
            );
            return rows.AsList();
        }

        // -------------------- COMMENTS --------------------

        public async Task<dynamic> AddCommentAsync(Guid tenantId, Guid postId, Guid actorId, string content)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM social.fn_add_comment(@p_tenant_id, @p_post_id, @p_actor_id, @p_content)",
                new { p_tenant_id = tenantId, p_post_id = postId, p_actor_id = actorId, p_content = content }
            );
        }

        public async Task<List<dynamic>> GetCommentsAsync(Guid tenantId, Guid postId, int limit, int offset)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM social.fn_get_comments(@p_tenant_id, @p_post_id, @p_limit, @p_offset)",
                new { p_tenant_id = tenantId, p_post_id = postId, p_limit = limit, p_offset = offset }
            );
            return rows.AsList();
        }

        public async Task DeleteCommentAsync(Guid tenantId, Guid commentId, Guid actorId)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "CALL social.sp_delete_comment(@p_tenant_id, @p_comment_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_comment_id = commentId, p_actor_id = actorId }
            );
        }
    }
}
#endregion

// ==========================================================================
#region Service
// ==========================================================================
namespace KeiroGenesis.API.Services
{
    public class SocialService
    {
        private readonly SocialRepository _repo;
        private readonly ILogger<SocialService> _logger;

        public SocialService(SocialRepository repo, ILogger<SocialService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<dynamic> CreatePostAsync(
            Guid tenantId, Guid actorId, string content, string? mediaUrl, string visibility = "public", Guid? replyToPostId = null)
        {
            var post = await _repo.CreatePostAsync(tenantId, actorId, content, mediaUrl, visibility, replyToPostId);
            _logger.LogInformation("Actor {ActorId} created post", actorId);
            return post;
        }

        public Task<dynamic?> GetPostAsync(Guid tenantId, Guid postId)
            => _repo.GetPostAsync(tenantId, postId);

        public Task<List<dynamic>> GetFeedAsync(Guid tenantId, Guid actorId, int limit = 20, int offset = 0)
            => _repo.GetFeedAsync(tenantId, actorId, limit, offset);

        public Task<List<dynamic>> GetPostsByActorAsync(Guid tenantId, Guid actorId, int limit = 20, int offset = 0)
            => _repo.GetPostsByActorAsync(tenantId, actorId, limit, offset);

        public Task<List<dynamic>> GetRepliesAsync(Guid tenantId, Guid postId, int limit = 20, int offset = 0)
            => _repo.GetRepliesAsync(tenantId, postId, limit, offset);

        public async Task DeletePostAsync(Guid tenantId, Guid postId, Guid actorId)
        {
            await _repo.DeletePostAsync(tenantId, postId, actorId);
            _logger.LogInformation("Deleted post {PostId}", postId);
        }

        public async Task FollowAsync(Guid tenantId, Guid followerActorId, Guid followedActorId)
        {
            await _repo.FollowAsync(tenantId, followerActorId, followedActorId);
            _logger.LogInformation("Actor {FollowerId} followed {FollowedId}", followerActorId, followedActorId);
        }

        public async Task UnfollowAsync(Guid tenantId, Guid followerActorId, Guid followedActorId)
        {
            await _repo.UnfollowAsync(tenantId, followerActorId, followedActorId);
            _logger.LogInformation("Actor {FollowerId} unfollowed {FollowedId}", followerActorId, followedActorId);
        }

        public Task<List<dynamic>> GetFollowersAsync(Guid tenantId, Guid actorId, int limit = 20, int offset = 0)
            => _repo.GetFollowersAsync(tenantId, actorId, limit, offset);

        public Task<List<dynamic>> GetFollowingAsync(Guid tenantId, Guid actorId, int limit = 20, int offset = 0)
            => _repo.GetFollowingAsync(tenantId, actorId, limit, offset);

        public Task<bool> IsFollowingAsync(Guid tenantId, Guid followerActorId, Guid followedActorId)
            => _repo.IsFollowingAsync(tenantId, followerActorId, followedActorId);

        public async Task ReactToPostAsync(Guid tenantId, Guid postId, Guid actorId, string reactionType)
        {
            await _repo.ReactToPostAsync(tenantId, postId, actorId, reactionType);
            _logger.LogInformation("Actor {ActorId} reacted to post {PostId}", actorId, postId);
        }

        public async Task RemoveReactionAsync(Guid tenantId, Guid postId, Guid actorId)
        {
            await _repo.RemoveReactionAsync(tenantId, postId, actorId);
            _logger.LogInformation("Actor {ActorId} removed reaction from post {PostId}", actorId, postId);
        }

        public Task<List<dynamic>> GetReactionsAsync(Guid tenantId, Guid postId)
            => _repo.GetReactionsAsync(tenantId, postId);

        public async Task<dynamic> AddCommentAsync(Guid tenantId, Guid postId, Guid actorId, string content)
        {
            var comment = await _repo.AddCommentAsync(tenantId, postId, actorId, content);
            _logger.LogInformation("Actor {ActorId} commented on post {PostId}", actorId, postId);
            return comment;
        }

        public Task<List<dynamic>> GetCommentsAsync(Guid tenantId, Guid postId, int limit = 20, int offset = 0)
            => _repo.GetCommentsAsync(tenantId, postId, limit, offset);

        public async Task DeleteCommentAsync(Guid tenantId, Guid commentId, Guid actorId)
        {
            await _repo.DeleteCommentAsync(tenantId, commentId, actorId);
            _logger.LogInformation("Deleted comment {CommentId}", commentId);
        }
    }
}
#endregion

// ==========================================================================
#region Controller
// ==========================================================================
namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
    [Route("api/v1/[controller]")]
    [Authorize]
    public class SocialController : ControllerBase
    {
        private readonly SocialService _service;

        public SocialController(SocialService service)
        {
            _service = service;
        }

        // -------------------- POSTS --------------------

        [HttpPost("create-post")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> CreatePost([FromBody] CreatePostRequest request)
        {
            var tenantId = GetTenantId();
            var post = await _service.CreatePostAsync(
                tenantId, request.ActorId, request.Content, request.MediaUrl, request.Visibility ?? "public", request.ReplyToPostId
            );
            return Ok(post);
        }

        [HttpGet("get-post")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetPost(Guid postId)
        {
            var tenantId = GetTenantId();
            var post = await _service.GetPostAsync(tenantId, postId);
            return post != null ? Ok(post) : NotFound();
        }

        [HttpGet("feed")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetFeed(
            Guid actorId,
            [FromQuery] int limit = 20,
            [FromQuery] int offset = 0)
        {
            var tenantId = GetTenantId();
            var posts = await _service.GetFeedAsync(tenantId, actorId, limit, offset);
            return Ok(posts);
        }

        [HttpGet("posts-by-actor")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetPostsByActor(
            Guid actorId,
            [FromQuery] int limit = 20,
            [FromQuery] int offset = 0)
        {
            var tenantId = GetTenantId();
            var posts = await _service.GetPostsByActorAsync(tenantId, actorId, limit, offset);
            return Ok(posts);
        }

        [HttpGet("replies")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetReplies(
            Guid postId,
            [FromQuery] int limit = 20,
            [FromQuery] int offset = 0)
        {
            var tenantId = GetTenantId();
            var replies = await _service.GetRepliesAsync(tenantId, postId, limit, offset);
            return Ok(replies);
        }

        [HttpDelete("delete-post")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> DeletePost(Guid postId, Guid actorId)
        {
            var tenantId = GetTenantId();
            await _service.DeletePostAsync(tenantId, postId, actorId);
            return Ok(new { success = true });
        }

        // -------------------- FOLLOWS --------------------

        [HttpPost("follow")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> Follow([FromBody] FollowRequest request)
        {
            var tenantId = GetTenantId();
            await _service.FollowAsync(tenantId, request.FollowerActorId, request.FollowedActorId);
            return Ok(new { success = true });
        }

        [HttpPost("unfollow")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> Unfollow([FromBody] FollowRequest request)
        {
            var tenantId = GetTenantId();
            await _service.UnfollowAsync(tenantId, request.FollowerActorId, request.FollowedActorId);
            return Ok(new { success = true });
        }

        [HttpGet("followers")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetFollowers(
            Guid actorId,
            [FromQuery] int limit = 20,
            [FromQuery] int offset = 0)
        {
            var tenantId = GetTenantId();
            var followers = await _service.GetFollowersAsync(tenantId, actorId, limit, offset);
            return Ok(followers);
        }

        [HttpGet("following")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetFollowing(
            Guid actorId,
            [FromQuery] int limit = 20,
            [FromQuery] int offset = 0)
        {
            var tenantId = GetTenantId();
            var following = await _service.GetFollowingAsync(tenantId, actorId, limit, offset);
            return Ok(following);
        }

        [HttpGet("is-following")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> IsFollowing(Guid followerActorId, Guid followedActorId)
        {
            var tenantId = GetTenantId();
            var isFollowing = await _service.IsFollowingAsync(tenantId, followerActorId, followedActorId);
            return Ok(new { is_following = isFollowing });
        }

        // -------------------- REACTIONS --------------------

        [HttpPost("react")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> ReactToPost([FromBody] ReactRequest request)
        {
            var tenantId = GetTenantId();
            await _service.ReactToPostAsync(tenantId, request.PostId, request.ActorId, request.ReactionType);
            return Ok(new { success = true });
        }

        [HttpDelete("remove-reaction")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> RemoveReaction(Guid postId, Guid actorId)
        {
            var tenantId = GetTenantId();
            await _service.RemoveReactionAsync(tenantId, postId, actorId);
            return Ok(new { success = true });
        }

        [HttpGet("reactions")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetReactions(Guid postId)
        {
            var tenantId = GetTenantId();
            var reactions = await _service.GetReactionsAsync(tenantId, postId);
            return Ok(reactions);
        }

        // -------------------- COMMENTS --------------------

        [HttpPost("add-comment")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> AddComment([FromBody] AddCommentRequest request)
        {
            var tenantId = GetTenantId();
            var comment = await _service.AddCommentAsync(tenantId, request.PostId, request.ActorId, request.Content);
            return Ok(comment);
        }

        [HttpGet("comments")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetComments(
            Guid postId,
            [FromQuery] int limit = 20,
            [FromQuery] int offset = 0)
        {
            var tenantId = GetTenantId();
            var comments = await _service.GetCommentsAsync(tenantId, postId, limit, offset);
            return Ok(comments);
        }

        [HttpDelete("delete-comment")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> DeleteComment(Guid commentId, Guid actorId)
        {
            var tenantId = GetTenantId();
            await _service.DeleteCommentAsync(tenantId, commentId, actorId);
            return Ok(new { success = true });
        }

        private Guid GetTenantId()
        {
            var claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var tenantId))
                throw new UnauthorizedAccessException("Invalid tenant claim");
            return tenantId;
        }
    }

    public class CreatePostRequest
    {
        public Guid ActorId { get; set; }
        public string Content { get; set; } = string.Empty;
        public string? MediaUrl { get; set; }
        public string? Visibility { get; set; }
        public Guid? ReplyToPostId { get; set; }
    }

    public class FollowRequest
    {
        public Guid FollowerActorId { get; set; }
        public Guid FollowedActorId { get; set; }
    }

    public class ReactRequest
    {
        public Guid PostId { get; set; }
        public Guid ActorId { get; set; }
        public string ReactionType { get; set; } = string.Empty;
    }

    public class AddCommentRequest
    {
        public Guid PostId { get; set; }
        public Guid ActorId { get; set; }
        public string Content { get; set; } = string.Empty;
    }
}
#endregion
