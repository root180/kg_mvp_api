// ==========================================================================
// MESSAGING MODULE — Conversations and Messages
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

#region Repository
namespace KeiroGenesis.API.Repositories
{
    public class MessagingRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<MessagingRepository> _logger;

        public MessagingRepository(IDbConnectionFactory db, ILogger<MessagingRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<dynamic> StartConversationAsync(Guid tenantId, Guid actor1Id, Guid actor2Id)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM social.fn_start_conversation(@p_tenant_id, @p_actor1_id, @p_actor2_id)",
                new { p_tenant_id = tenantId, p_actor1_id = actor1Id, p_actor2_id = actor2Id }
            );
        }

        public async Task<dynamic?> GetConversationAsync(Guid tenantId, Guid conversationId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM social.fn_get_conversation(@p_tenant_id, @p_conversation_id)",
                new { p_tenant_id = tenantId, p_conversation_id = conversationId }
            );
        }

        public async Task<List<dynamic>> GetConversationsAsync(Guid tenantId, Guid actorId)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM social.fn_get_conversations(@p_tenant_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_actor_id = actorId }
            );
            return rows.AsList();
        }

        public async Task<dynamic> SendMessageAsync(Guid tenantId, Guid conversationId, Guid senderActorId, string content)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM social.fn_send_message(@p_tenant_id, @p_conversation_id, @p_sender_actor_id, @p_content)",
                new { p_tenant_id = tenantId, p_conversation_id = conversationId, p_sender_actor_id = senderActorId, p_content = content }
            );
        }

        public async Task<List<dynamic>> GetMessagesAsync(Guid tenantId, Guid conversationId, int limit, int offset)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM social.fn_get_messages(@p_tenant_id, @p_conversation_id, @p_limit, @p_offset)",
                new { p_tenant_id = tenantId, p_conversation_id = conversationId, p_limit = limit, p_offset = offset }
            );
            return rows.AsList();
        }

        public async Task RateMessageAsync(Guid tenantId, Guid messageId, Guid actorId, int rating)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "SELECT social.fn_rate_message(@p_tenant_id, @p_message_id, @p_actor_id, @p_rating)",
                new { p_tenant_id = tenantId, p_message_id = messageId, p_actor_id = actorId, p_rating = rating }
            );
        }
    }
}
#endregion

#region Service
namespace KeiroGenesis.API.Services
{
    public class MessagingService
    {
        private readonly MessagingRepository _repo;
        private readonly ILogger<MessagingService> _logger;

        public MessagingService(MessagingRepository repo, ILogger<MessagingService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<dynamic> StartConversationAsync(Guid tenantId, Guid actor1Id, Guid actor2Id)
        {
            var conversation = await _repo.StartConversationAsync(tenantId, actor1Id, actor2Id);
            _logger.LogInformation("Started conversation between {Actor1} and {Actor2}", actor1Id, actor2Id);
            return conversation;
        }

        public Task<dynamic?> GetConversationAsync(Guid tenantId, Guid conversationId)
            => _repo.GetConversationAsync(tenantId, conversationId);

        public Task<List<dynamic>> GetConversationsAsync(Guid tenantId, Guid actorId)
            => _repo.GetConversationsAsync(tenantId, actorId);

        public async Task<dynamic> SendMessageAsync(Guid tenantId, Guid conversationId, Guid senderActorId, string content)
        {
            var message = await _repo.SendMessageAsync(tenantId, conversationId, senderActorId, content);
            _logger.LogInformation("Actor {ActorId} sent message in conversation {ConversationId}", senderActorId, conversationId);
            return message;
        }

        public Task<List<dynamic>> GetMessagesAsync(Guid tenantId, Guid conversationId, int limit = 50, int offset = 0)
            => _repo.GetMessagesAsync(tenantId, conversationId, limit, offset);

        public async Task RateMessageAsync(Guid tenantId, Guid messageId, Guid actorId, int rating)
        {
            await _repo.RateMessageAsync(tenantId, messageId, actorId, rating);
            _logger.LogInformation("Actor {ActorId} rated message {MessageId}", actorId, messageId);
        }
    }
}
#endregion

#region Controller
namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
    [Route("api/v1/[controller]")]
    [Authorize]
    public class MessagingController : ControllerBase
    {
        private readonly MessagingService _service;

        public MessagingController(MessagingService service)
        {
            _service = service;
        }

        [HttpPost("start-conversation")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> StartConversation([FromBody] StartConversationRequest request)
        {
            var tenantId = GetTenantId();
            var conversation = await _service.StartConversationAsync(tenantId, request.Actor1Id, request.Actor2Id);
            return Ok(conversation);
        }

        [HttpGet("get-conversation")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetConversation(Guid conversationId)
        {
            var tenantId = GetTenantId();
            var conversation = await _service.GetConversationAsync(tenantId, conversationId);
            return conversation != null ? Ok(conversation) : NotFound();
        }

        [HttpGet("conversations")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetConversations(Guid actorId)
        {
            var tenantId = GetTenantId();
            var conversations = await _service.GetConversationsAsync(tenantId, actorId);
            return Ok(conversations);
        }

        [HttpPost("send-message")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> SendMessage([FromBody] SendMessageRequest request)
        {
            var tenantId = GetTenantId();
            var message = await _service.SendMessageAsync(tenantId, request.ConversationId, request.SenderActorId, request.Content);
            return Ok(message);
        }

        [HttpGet("messages")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetMessages(
            Guid conversationId,
            [FromQuery] int limit = 50,
            [FromQuery] int offset = 0)
        {
            var tenantId = GetTenantId();
            var messages = await _service.GetMessagesAsync(tenantId, conversationId, limit, offset);
            return Ok(messages);
        }

        [HttpPost("rate-message")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> RateMessage([FromBody] RateMessageRequest request)
        {
            var tenantId = GetTenantId();
            await _service.RateMessageAsync(tenantId, request.MessageId, request.ActorId, request.Rating);
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

    public class StartConversationRequest
    {
        public Guid Actor1Id { get; set; }
        public Guid Actor2Id { get; set; }
    }

    public class SendMessageRequest
    {
        public Guid ConversationId { get; set; }
        public Guid SenderActorId { get; set; }
        public string Content { get; set; } = string.Empty;
    }

    public class RateMessageRequest
    {
        public Guid MessageId { get; set; }
        public Guid ActorId { get; set; }
        public int Rating { get; set; }
    }
}
#endregion
