// ==========================================================================
// ACTOR CONVERSATION - COMPLETE IMPLEMENTATION (SINGLE FILE)
// ==========================================================================
// Contains: DTOs + Service + Controller
// Pattern: NO hardcoded SQL, all operations use stored procedures
// ==========================================================================

using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Dapper;
using KeiroGenesis.API.Core.Database;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

// ==========================================================================
#region DTOs - API Boundary Only
// ==========================================================================

namespace KeiroGenesis.API.DTOs.ActorConversation
{
    // Request: Send message to actor
    public sealed class ActorConversationRequest
    {
        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;
    }

    // Response: Actor conversation reply
    public sealed class ActorConversationResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("actorId")]
        public Guid ActorId { get; init; }

        [JsonPropertyName("response")]
        public string Response { get; init; } = string.Empty;

        [JsonPropertyName("conversationId")]
        public Guid? ConversationId { get; init; }

        [JsonPropertyName("messageId")]
        public Guid? MessageId { get; init; }

        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; init; }
    }

    // Internal: Conversation result (NOT a DTO - fixes tuple deconstruction error with dynamic)
    public class ConversationResult
    {
        public bool Success { get; set; }
        public string Response { get; set; } = string.Empty;
        public Guid? ConversationId { get; set; }
        public Guid? MessageId { get; set; }
    }

    // Internal: Stored conversation result (fixes tuple deconstruction)
    public class StoredConversationResult
    {
        public Guid ConversationId { get; set; }
        public Guid MessageId { get; set; }
    }

    // Internal: Actor runtime context (NOT a DTO - used internally only)
    public class ActorRuntimeContext
    {
        public Guid ActorId { get; set; }
        public Guid TenantId { get; set; }
        public Guid UserId { get; set; }
        public string DisplayName { get; set; } = string.Empty;
        public string Handle { get; set; } = string.Empty;
        public string ActorType { get; set; } = string.Empty;

        public string Tone { get; set; } = "professional";
        public string Verbosity { get; set; } = "balanced";
        public string Humor { get; set; } = "subtle";

        public string? Values { get; set; }
        public string? Visibility { get; set; }
        public List<string> GoverningRules { get; set; } = new();

        public List<string> RecentMemories { get; set; } = new();
        public List<string> PinnedMemories { get; set; } = new();

        public string? OpeningMessage { get; set; }
        public string OpeningMode { get; set; } = "none";
    }

    // Internal: RAG context chunks
    public class RagContextChunk
    {
        public string Content { get; set; } = string.Empty;
        public double Score { get; set; }
        public string SourceType { get; set; } = string.Empty;
        public Guid? SourceId { get; set; }
    }

    // Internal: LLM request structure
    public class LlmRequest
    {
        public string Model { get; set; } = "gpt-4";
        public List<LlmMessage> Messages { get; set; } = new();
        public double Temperature { get; set; } = 0.7;
        public int MaxTokens { get; set; } = 1000;
    }

    public class LlmMessage
    {
        public string Role { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
    }

    // Internal: LLM response structure
    public class LlmResponse
    {
        public string Content { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public int TokensUsed { get; set; }
    }
}
#endregion

// ==========================================================================
#region Service
// ==========================================================================

namespace KeiroGenesis.API.Services
{
    using KeiroGenesis.API.DTOs.ActorConversation;

    public class ActorConversationService
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<ActorConversationService> _logger;
        private readonly IConfiguration _config;
        private readonly IHttpClientFactory _httpClientFactory;

        public ActorConversationService(
            IDbConnectionFactory db,
            ILogger<ActorConversationService> logger,
            IConfiguration config,
            IHttpClientFactory httpClientFactory)
        {
            _db = db;
            _logger = logger;
            _config = config;
            _httpClientFactory = httpClientFactory;
        }

        // ======================================================================
        // MAIN CONVERSATION FLOW - Returns DTO instead of tuple
        // ======================================================================

        public async Task<ConversationResult> ProcessConversationAsync(
            Guid tenantId,
            Guid userId,
            Guid actorId,
            string message)
        {
            try
            {
                // 1. Identity Resolution (Non-Negotiable)
                var actor = await ResolveAndValidateActorAsync(tenantId, actorId);
                if (actor == null)
                {
                    _logger.LogWarning("Actor {ActorId} not found or inactive", actorId);
                    return new ConversationResult
                    {
                        Success = false,
                        Response = "Actor not found or inactive"
                    };
                }

                // 2. Actor Context Assembly (NO AI YET)
                var context = await AssembleActorContextAsync(tenantId, userId, actorId, actor);

                // 3. Prompt Assembly (Actor-Centric)
                var systemPrompt = BuildSystemPrompt(context);
                var memoryPrompt = BuildMemoryPrompt(context);

                // 4. RAG Service (Supporting Role)
                var ragContext = await GetRagContextAsync(tenantId, actorId, message);

                // 5. Final Prompt Merge
                var finalPrompt = MergeFinalPrompt(systemPrompt, memoryPrompt, ragContext, message);

                // Check if opening message should be applied (user-configured behavior)
                var isFirstInteraction = await IsFirstInteractionAsync(tenantId, userId, actorId);
                ApplyOpeningMessage(context, finalPrompt, isFirstInteraction);

                // 6. LLM Call
                var llmResponse = await CallLlmAsync(finalPrompt, message);

                // 7. Response Handling (Critical Step) - Use DTO to avoid tuple deconstruction
                var stored = await StoreConversationAsync(
                    tenantId, userId, actorId, message, llmResponse.Content);

                // 8. Memory Feedback Loop (Async - fire and forget)
                _ = Task.Run(async () => await ProcessMemoryFeedbackAsync(
                    tenantId, actorId, stored.ConversationId, stored.MessageId, message, llmResponse.Content));

                return new ConversationResult
                {
                    Success = true,
                    Response = llmResponse.Content,
                    ConversationId = stored.ConversationId,
                    MessageId = stored.MessageId
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Conversation processing failed for actor {ActorId}", actorId);
                return new ConversationResult
                {
                    Success = false,
                    Response = "An error occurred processing your message"
                };
            }
        }

        // ======================================================================
        // 1. IDENTITY RESOLUTION (Non-Negotiable)
        // ======================================================================

        private async Task<dynamic?> ResolveAndValidateActorAsync(Guid tenantId, Guid actorId)
        {
            using var conn = _db.CreateConnection();

            var actor = await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM conversation.fn_validate_actor(@p_tenant_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_actor_id = actorId }
            );

            if (actor == null)
            {
                _logger.LogWarning("Actor validation failed: ActorId={ActorId}, TenantId={TenantId}",
                    actorId, tenantId);
            }

            return actor;
        }

        // ======================================================================
        // 2. ACTOR CONTEXT ASSEMBLY (NO AI YET - Deterministic)
        // ======================================================================

        private async Task<ActorRuntimeContext> AssembleActorContextAsync(
            Guid tenantId, Guid userId, Guid actorId, dynamic actor)
        {
            var context = new ActorRuntimeContext
            {
                ActorId = actorId,
                TenantId = tenantId,
                UserId = userId,
                DisplayName = actor.display_name ?? "Actor",
                Handle = actor.handle ?? "",
                ActorType = actor.actor_type ?? "unknown"
            };

            // Load personality traits (if clone actor)
            if (context.ActorType == "clone")
            {
                await LoadCloneConstraintsAsync(context, actorId);
            }

            // Load recent memory (light)
            await LoadRecentMemoryAsync(context, tenantId, actorId);

            return context;
        }

        private async Task LoadCloneConstraintsAsync(ActorRuntimeContext context, Guid actorId)
        {
            using var conn = _db.CreateConnection();

            var clone = await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM conversation.fn_get_clone_config(@p_actor_id)",
                new { p_actor_id = actorId }
            );

            if (clone != null)
            {
                context.Values = clone.bio ?? "";
                context.Visibility = clone.visibility ?? "private";

                // Load opening message configuration (user-defined)
                context.OpeningMessage = clone.opening_message;
                context.OpeningMode = clone.opening_mode ?? "none";

                // Parse personality traits
                if (clone.personality_traits != null)
                {
                    try
                    {
                        var traits = JsonSerializer.Deserialize<Dictionary<string, string>>(
                            clone.personality_traits.ToString());

                        if (traits != null)
                        {
                            context.Tone = traits.GetValueOrDefault("tone", "professional");
                            context.Verbosity = traits.GetValueOrDefault("verbosity", "balanced");
                            context.Humor = traits.GetValueOrDefault("humor", "subtle");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse personality traits for actor {ActorId}", actorId);
                    }
                }
            }
        }

        private async Task LoadRecentMemoryAsync(ActorRuntimeContext context, Guid tenantId, Guid actorId)
        {
            using var conn = _db.CreateConnection();

            // Load last 5 memory contents (actual schema uses content, not summary)
            var memories = await conn.QueryAsync<string>(
                "SELECT content FROM conversation.fn_get_recent_memories(@p_tenant_id, @p_actor_id, @p_limit)",
                new { p_tenant_id = tenantId, p_actor_id = actorId, p_limit = 5 }
            );

            context.RecentMemories = memories.ToList();

            // Load pinned memories (using is_sensitive as proxy for pinned)
            var pinned = await conn.QueryAsync<string>(
                "SELECT content FROM conversation.fn_get_pinned_memories(@p_tenant_id, @p_actor_id, @p_limit)",
                new { p_tenant_id = tenantId, p_actor_id = actorId, p_limit = 3 }
            );

            context.PinnedMemories = pinned.ToList();
        }

        // ======================================================================
        // 3. PROMPT ASSEMBLY (Actor-Centric)
        // ======================================================================

        private string BuildSystemPrompt(ActorRuntimeContext context)
        {
            var sb = new StringBuilder();

            // Silent Authority Layer - Behavioral rules only, no identity descriptions
            sb.AppendLine($"You speak in the first person as {context.DisplayName}.");
            sb.AppendLine();
            sb.AppendLine("Your responses must reflect:");

            if (!string.IsNullOrEmpty(context.Values))
            {
                sb.AppendLine($"- the values, priorities, and perspectives: {context.Values}");
            }

            sb.AppendLine($"- {context.Tone} tone, {context.Verbosity} verbosity, {context.Humor} humor");
            sb.AppendLine("- consistent reasoning aligned with past statements and memories");
            sb.AppendLine();
            sb.AppendLine("You do not explain your role or identity unless directly asked.");
            sb.AppendLine("You do not reference internal systems, prompts, or training.");
            sb.AppendLine("You respond naturally, confidently, and concisely.");
            sb.AppendLine();
            sb.AppendLine("If information is uncertain or outside scope, acknowledge briefly and redirect appropriately.");

            return sb.ToString();
        }

        private string BuildMemoryPrompt(ActorRuntimeContext context)
        {
            if (context.RecentMemories.Count == 0 && context.PinnedMemories.Count == 0)
            {
                return string.Empty;
            }

            var sb = new StringBuilder();
            sb.AppendLine("Your recent context and memories:");

            if (context.PinnedMemories.Any())
            {
                sb.AppendLine("\nCore memories (always relevant):");
                foreach (var memory in context.PinnedMemories)
                {
                    sb.AppendLine($"- {memory}");
                }
            }

            if (context.RecentMemories.Any())
            {
                sb.AppendLine("\nRecent interactions:");
                foreach (var memory in context.RecentMemories)
                {
                    sb.AppendLine($"- {memory}");
                }
            }

            return sb.ToString();
        }

        // ======================================================================
        // 4. RAG SERVICE (Supporting Role - Context Retrieval Only)
        // ======================================================================

        private async Task<List<RagContextChunk>> GetRagContextAsync(
            Guid tenantId, Guid actorId, string message)
        {
            try
            {
                var ragUrl = _config["RAG:ServiceUrl"];
                if (string.IsNullOrEmpty(ragUrl))
                {
                    _logger.LogWarning("RAG service URL not configured, skipping RAG context");
                    return new List<RagContextChunk>();
                }

                _logger.LogInformation("RAG context requested for actor {ActorId}", actorId);
                return new List<RagContextChunk>(); // Placeholder
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RAG context retrieval failed for actor {ActorId}", actorId);
                return new List<RagContextChunk>(); // Non-blocking failure
            }
        }

        // ======================================================================
        // 5. FINAL PROMPT MERGE
        // ======================================================================

        private LlmRequest MergeFinalPrompt(
            string systemPrompt,
            string memoryPrompt,
            List<RagContextChunk> ragContext,
            string userMessage)
        {
            var messages = new List<LlmMessage>();

            // System prompt (Silent Authority Layer - behavioral rules only)
            messages.Add(new LlmMessage
            {
                Role = "system",
                Content = systemPrompt
            });

            // Memory prompt (if any)
            if (!string.IsNullOrEmpty(memoryPrompt))
            {
                messages.Add(new LlmMessage
                {
                    Role = "system",
                    Content = memoryPrompt
                });
            }

            // RAG context (if any)
            if (ragContext.Any())
            {
                var ragPrompt = new StringBuilder();
                ragPrompt.AppendLine("Relevant context from your knowledge:");

                foreach (var chunk in ragContext.Take(5))
                {
                    ragPrompt.AppendLine($"- {chunk.Content}");
                }

                messages.Add(new LlmMessage
                {
                    Role = "system",
                    Content = ragPrompt.ToString()
                });
            }

            // User message
            messages.Add(new LlmMessage
            {
                Role = "user",
                Content = userMessage
            });

            return new LlmRequest
            {
                Model = _config["LLM:Model"] ?? "gpt-4",
                Messages = messages,
                Temperature = double.Parse(_config["LLM:Temperature"] ?? "0.7"),
                MaxTokens = int.Parse(_config["LLM:MaxTokens"] ?? "1000")
            };
        }

        // Check if this is the first interaction in this conversation
        private async Task<bool> IsFirstInteractionAsync(Guid tenantId, Guid userId, Guid actorId)
        {
            using var conn = _db.CreateConnection();

            var isFirst = await conn.ExecuteScalarAsync<bool>(
                "SELECT conversation.fn_check_first_interaction(@p_tenant_id, @p_user_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_user_id = userId, p_actor_id = actorId }
            );

            return isFirst;
        }

        // Apply opening message based on user-configured behavior
        // This is NOT hardcoded - it comes from clone configuration
        private void ApplyOpeningMessage(
            ActorRuntimeContext context,
            LlmRequest request,
            bool isFirstInteraction)
        {
            // Only apply if user has configured an opening message
            if (string.IsNullOrEmpty(context.OpeningMessage))
                return;

            // Apply based on configured mode
            var shouldApply = context.OpeningMode switch
            {
                "first_interaction" => isFirstInteraction,
                "always" => true,
                "none" => false,
                _ => false
            };

            if (shouldApply)
            {
                // Insert opening message as first assistant message
                request.Messages.Insert(0, new LlmMessage
                {
                    Role = "assistant",
                    Content = context.OpeningMessage
                });

                _logger.LogInformation(
                    "Applied opening message for actor {ActorId} (mode: {Mode})",
                    context.ActorId, context.OpeningMode);
            }
        }

        // ======================================================================
        // 6. LLM CALL (OpenAI / Claude / Anthropic)
        // ======================================================================

        private async Task<LlmResponse> CallLlmAsync(LlmRequest request, string userMessage)
        {
            try
            {
                var provider = _config["LLM:Provider"] ?? "openai";

                if (provider == "openai")
                {
                    return await CallOpenAiAsync(request);
                }
                else if (provider == "anthropic")
                {
                    return await CallAnthropicAsync(request);
                }
                else
                {
                    _logger.LogWarning("Unknown LLM provider: {Provider}, using fallback", provider);
                    return new LlmResponse
                    {
                        Content = "I'm here to help, but I'm currently unable to process your request.",
                        Model = "fallback",
                        TokensUsed = 0
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LLM call failed");
                return new LlmResponse
                {
                    Content = "I apologize, but I'm experiencing technical difficulties.",
                    Model = "error",
                    TokensUsed = 0
                };
            }
        }

        private async Task<LlmResponse> CallOpenAiAsync(LlmRequest request)
        {
            var apiKey = _config["LLM:OpenAI:ApiKey"];
            if (string.IsNullOrEmpty(apiKey))
            {
                throw new InvalidOperationException("OpenAI API key not configured");
            }

            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");

            var payload = new
            {
                model = request.Model,
                messages = request.Messages.Select(m => new
                {
                    role = m.Role,
                    content = m.Content
                }).ToArray(),
                temperature = request.Temperature,
                max_tokens = request.MaxTokens
            };

            var content = new StringContent(
                JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json"
            );

            var response = await client.PostAsync("https://api.openai.com/v1/chat/completions", content);
            response.EnsureSuccessStatusCode();

            var responseBody = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<JsonDocument>(responseBody);

            var messageContent = result?.RootElement
                .GetProperty("choices")[0]
                .GetProperty("message")
                .GetProperty("content")
                .GetString() ?? "";

            var tokensUsed = result?.RootElement
                .GetProperty("usage")
                .GetProperty("total_tokens")
                .GetInt32() ?? 0;

            return new LlmResponse
            {
                Content = messageContent,
                Model = request.Model,
                TokensUsed = tokensUsed
            };
        }

        private async Task<LlmResponse> CallAnthropicAsync(LlmRequest request)
        {
            _logger.LogWarning("Anthropic provider not yet implemented");
            return new LlmResponse
            {
                Content = "Anthropic integration coming soon.",
                Model = "anthropic",
                TokensUsed = 0
            };
        }

        // ======================================================================
        // 7. RESPONSE HANDLING (Critical Step) - Returns DTO
        // ======================================================================

        private async Task<StoredConversationResult> StoreConversationAsync(
            Guid tenantId,
            Guid userId,
            Guid actorId,
            string userMessage,
            string actorResponse)
        {
            using var conn = _db.CreateConnection();

            // Get or create conversation
            var conversationId = await conn.ExecuteScalarAsync<Guid>(
                "SELECT conversation.sp_store_conversation(@p_tenant_id, @p_user_id, @p_actor_id)",
                new { p_tenant_id = tenantId, p_user_id = userId, p_actor_id = actorId }
            );

            // Store user message
            var userMessageId = await conn.ExecuteScalarAsync<Guid>(
                @"SELECT conversation.sp_store_message(
                    @p_tenant_id, @p_conversation_id, @p_actor_id, @p_role, @p_content, @p_tokens_used
                )",
                new
                {
                    p_tenant_id = tenantId,
                    p_conversation_id = conversationId,
                    p_actor_id = actorId,
                    p_role = "user",
                    p_content = userMessage,
                    p_tokens_used = 0
                }
            );

            // Store actor message
            var actorMessageId = await conn.ExecuteScalarAsync<Guid>(
                @"SELECT conversation.sp_store_message(
                    @p_tenant_id, @p_conversation_id, @p_actor_id, @p_role, @p_content, @p_tokens_used
                )",
                new
                {
                    p_tenant_id = tenantId,
                    p_conversation_id = conversationId,
                    p_actor_id = actorId,
                    p_role = "assistant",
                    p_content = actorResponse,
                    p_tokens_used = 0
                }
            );

            _logger.LogInformation(
                "Stored conversation: ConversationId={ConversationId}, UserMsgId={UserMsgId}, ActorMsgId={ActorMsgId}",
                conversationId, userMessageId, actorMessageId);

            return new StoredConversationResult
            {
                ConversationId = conversationId,
                MessageId = actorMessageId
            };
        }

        // ======================================================================
        // 8. MEMORY FEEDBACK LOOP (Async - Event-Driven)
        // ======================================================================

        private async Task ProcessMemoryFeedbackAsync(
            Guid tenantId,
            Guid actorId,
            Guid conversationId,
            Guid messageId,
            string userMessage,
            string actorResponse)
        {
            try
            {
                // Summarize interaction
                var title = $"Conversation on {DateTime.UtcNow:yyyy-MM-dd}";
                var content = $"User: {userMessage}\n\nAssistant: {actorResponse}";

                // Store memory using stored procedure (converts actor_id to clone_id internally)
                using var conn = _db.CreateConnection();
                var memoryId = await conn.ExecuteScalarAsync<Guid>(
                    @"SELECT conversation.sp_store_memory(
                        @p_tenant_id, @p_actor_id, @p_title, @p_content, @p_memory_type, @p_source_id
                    )",
                    new
                    {
                        p_tenant_id = tenantId,
                        p_actor_id = actorId,
                        p_title = title,
                        p_content = content,
                        p_memory_type = "conversation",
                        p_source_id = conversationId
                    }
                );

                _logger.LogInformation(
                    "Memory stored (ID={MemoryId}) for actor {ActorId}, conversation {ConversationId}",
                    memoryId, actorId, conversationId);

                // Update analytics (fire and forget)
                await UpdateConversationAnalyticsAsync(tenantId, actorId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Memory feedback loop failed for actor {ActorId}, conversation {ConversationId}",
                    actorId, conversationId);
            }
        }

        private async Task UpdateConversationAnalyticsAsync(Guid tenantId, Guid actorId)
        {
            try
            {
                using var conn = _db.CreateConnection();
                await conn.ExecuteAsync(
                    "CALL conversation.sp_update_actor_stats(@p_actor_id)",
                    new { p_actor_id = actorId }
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Analytics update failed for actor {ActorId}", actorId);
            }
        }

        private string TruncateMessage(string message, int maxLength)
        {
            if (string.IsNullOrEmpty(message) || message.Length <= maxLength)
                return message;

            return message.Substring(0, maxLength) + "...";
        }
    }
}
#endregion

// ==========================================================================
#region Controller
// ==========================================================================

namespace KeiroGenesis.API.Controllers.V1
{
    using KeiroGenesis.API.DTOs.ActorConversation;
    using KeiroGenesis.API.Services;

    [ApiController]
    [Route("api/v1/actors")]
    [Authorize]
    public class ActorConversationController : ControllerBase
    {
        private readonly ActorConversationService _conversationService;
        private readonly ILogger<ActorConversationController> _logger;

        public ActorConversationController(
            ActorConversationService conversationService,
            ILogger<ActorConversationController> logger)
        {
            _conversationService = conversationService;
            _logger = logger;
        }

        [HttpPost("{actorId}/conversation")]
        [ProducesResponseType(typeof(ActorConversationResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        [ProducesResponseType(404)]
        [ProducesResponseType(409)]
        public async Task<IActionResult> SendMessage(
            Guid actorId,
            [FromBody] ActorConversationRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Message))
            {
                return BadRequest(new ActorConversationResponse
                {
                    Success = false,
                    ActorId = actorId,
                    Response = "Message cannot be empty",
                    Timestamp = DateTime.UtcNow
                });
            }

            var tenantId = GetTenantId();
            var userId = GetCurrentUserId();

            // Fixed: Use ConversationResult DTO instead of tuple deconstruction
            var result = await _conversationService.ProcessConversationAsync(
                tenantId, userId, actorId, request.Message);

            if (!result.Success)
            {
                return StatusCode(500, new ActorConversationResponse
                {
                    Success = false,
                    ActorId = actorId,
                    Response = result.Response,
                    Timestamp = DateTime.UtcNow
                });
            }

            return Ok(new ActorConversationResponse
            {
                Success = true,
                ActorId = actorId,
                Response = result.Response,
                ConversationId = result.ConversationId,
                MessageId = result.MessageId,
                Timestamp = DateTime.UtcNow
            });
        }

        private Guid GetTenantId()
        {
            var claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var tenantId))
                throw new UnauthorizedAccessException("Invalid tenant claim");
            return tenantId;
        }

        private Guid GetCurrentUserId()
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