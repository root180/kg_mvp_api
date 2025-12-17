// ==========================================================================
// RAG MODULE — Documents, Embeddings, Vector Search
// Single file: Repository + Service + Controller
// Uses Pgvector for similarity search
// ==========================================================================

using System;
using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using Pgvector;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using KeiroGenesis.API.Services;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Core.Database;

#region Repository
namespace KeiroGenesis.API.Repositories
{
    public class RagRepository
    {
        private readonly IDbConnectionFactory _db;
        private readonly ILogger<RagRepository> _logger;

        public RagRepository(IDbConnectionFactory db, ILogger<RagRepository> logger)
        {
            _db = db;
            _logger = logger;
        }

        public async Task<dynamic> AddDocumentAsync(Guid tenantId, Guid cloneId, string filename, string contentType, long size, string url)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM rag.fn_add_document(@p_tenant_id, @p_clone_id, @p_filename, @p_content_type, @p_size, @p_url)",
                new { p_tenant_id = tenantId, p_clone_id = cloneId, p_filename = filename, p_content_type = contentType, p_size = size, p_url = url }
            );
        }

        public async Task<List<dynamic>> GetDocumentsAsync(Guid tenantId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM rag.fn_get_documents(@p_tenant_id, @p_clone_id)",
                new { p_tenant_id = tenantId, p_clone_id = cloneId }
            );
            return rows.AsList();
        }

        public async Task<dynamic?> GetDocumentAsync(Guid tenantId, Guid documentId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM rag.fn_get_document(@p_tenant_id, @p_document_id)",
                new { p_tenant_id = tenantId, p_document_id = documentId }
            );
        }

        public async Task DeleteDocumentAsync(Guid tenantId, Guid documentId)
        {
            using var conn = _db.CreateConnection();
            await conn.ExecuteAsync(
                "SELECT rag.fn_delete_document(@p_tenant_id, @p_document_id)",
                new { p_tenant_id = tenantId, p_document_id = documentId }
            );
        }

        public async Task AddChunksAsync(Guid tenantId, Guid documentId, List<(string content, Vector embedding)> chunks)
        {
            using var conn = _db.CreateConnection();
            foreach (var (content, embedding) in chunks)
            {
                await conn.ExecuteAsync(
                    "SELECT rag.fn_add_chunks(@p_tenant_id, @p_document_id, @p_content, @p_embedding)",
                    new { p_tenant_id = tenantId, p_document_id = documentId, p_content = content, p_embedding = embedding }
                );
            }
        }

        public async Task<List<dynamic>> SearchSimilarAsync(Guid tenantId, Guid cloneId, Vector queryEmbedding, int limit)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM rag.fn_search_similar(@p_tenant_id, @p_clone_id, @p_query_embedding, @p_limit)",
                new { p_tenant_id = tenantId, p_clone_id = cloneId, p_query_embedding = queryEmbedding, p_limit = limit }
            );
            return rows.AsList();
        }

        public async Task<List<dynamic>> GetChatContextAsync(Guid tenantId, Guid cloneId, Vector queryEmbedding, int limit)
        {
            using var conn = _db.CreateConnection();
            var rows = await conn.QueryAsync(
                "SELECT * FROM rag.fn_get_chat_context(@p_tenant_id, @p_clone_id, @p_query_embedding, @p_limit)",
                new { p_tenant_id = tenantId, p_clone_id = cloneId, p_query_embedding = queryEmbedding, p_limit = limit }
            );
            return rows.AsList();
        }

        public async Task<dynamic?> GetPersonalityAsync(Guid tenantId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM rag.fn_get_personality(@p_tenant_id, @p_clone_id)",
                new { p_tenant_id = tenantId, p_clone_id = cloneId }
            );
        }

        public async Task<dynamic?> GetExpertiseAsync(Guid tenantId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM rag.fn_get_expertise(@p_tenant_id, @p_clone_id)",
                new { p_tenant_id = tenantId, p_clone_id = cloneId }
            );
        }

        public async Task<dynamic?> BuildSystemPromptAsync(Guid tenantId, Guid cloneId)
        {
            using var conn = _db.CreateConnection();
            return await conn.QueryFirstOrDefaultAsync(
                "SELECT * FROM rag.fn_build_system_prompt(@p_tenant_id, @p_clone_id)",
                new { p_tenant_id = tenantId, p_clone_id = cloneId }
            );
        }
    }
}
#endregion

#region Service
namespace KeiroGenesis.API.Services
{
    public class RagService
    {
        private readonly RagRepository _repo;
        private readonly ILogger<RagService> _logger;

        public RagService(RagRepository repo, ILogger<RagService> logger)
        {
            _repo = repo;
            _logger = logger;
        }

        public async Task<dynamic> AddDocumentAsync(Guid tenantId, Guid cloneId, string filename, string contentType, long size, string url)
        {
            var document = await _repo.AddDocumentAsync(tenantId, cloneId, filename, contentType, size, url);
            _logger.LogInformation("Added document {Filename} for clone {CloneId}", filename, cloneId);
            return document;
        }

        public Task<List<dynamic>> GetDocumentsAsync(Guid tenantId, Guid cloneId)
            => _repo.GetDocumentsAsync(tenantId, cloneId);

        public Task<dynamic?> GetDocumentAsync(Guid tenantId, Guid documentId)
            => _repo.GetDocumentAsync(tenantId, documentId);

        public async Task DeleteDocumentAsync(Guid tenantId, Guid documentId)
        {
            await _repo.DeleteDocumentAsync(tenantId, documentId);
            _logger.LogInformation("Deleted document {DocumentId}", documentId);
        }

        public async Task AddChunksAsync(Guid tenantId, Guid documentId, List<(string content, Vector embedding)> chunks)
        {
            await _repo.AddChunksAsync(tenantId, documentId, chunks);
            _logger.LogInformation("Added {Count} chunks to document {DocumentId}", chunks.Count, documentId);
        }

        public Task<List<dynamic>> SearchSimilarAsync(Guid tenantId, Guid cloneId, Vector queryEmbedding, int limit = 5)
            => _repo.SearchSimilarAsync(tenantId, cloneId, queryEmbedding, limit);

        public Task<List<dynamic>> GetChatContextAsync(Guid tenantId, Guid cloneId, Vector queryEmbedding, int limit = 5)
            => _repo.GetChatContextAsync(tenantId, cloneId, queryEmbedding, limit);

        public Task<dynamic?> GetPersonalityAsync(Guid tenantId, Guid cloneId)
            => _repo.GetPersonalityAsync(tenantId, cloneId);

        public Task<dynamic?> GetExpertiseAsync(Guid tenantId, Guid cloneId)
            => _repo.GetExpertiseAsync(tenantId, cloneId);

        public Task<dynamic?> BuildSystemPromptAsync(Guid tenantId, Guid cloneId)
            => _repo.BuildSystemPromptAsync(tenantId, cloneId);
    }
}
#endregion

#region Controller
namespace KeiroGenesis.API.Controllers.V1
{
    [ApiController]
    [Route("api/v1/[controller]")]
    [Authorize]
    public class RagController : ControllerBase
    {
        private readonly RagService _service;

        public RagController(RagService service)
        {
            _service = service;
        }

        [HttpPost("add-document")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> AddDocument([FromBody] AddDocumentRequest request)
        {
            var tenantId = GetTenantId();
            var document = await _service.AddDocumentAsync(tenantId, request.CloneId, request.Filename, request.ContentType, request.Size, request.Url);
            return Ok(document);
        }

        [HttpGet("get-documents")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetDocuments(Guid cloneId)
        {
            var tenantId = GetTenantId();
            var documents = await _service.GetDocumentsAsync(tenantId, cloneId);
            return Ok(documents);
        }

        [HttpGet("get-document")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetDocument(Guid documentId)
        {
            var tenantId = GetTenantId();
            var document = await _service.GetDocumentAsync(tenantId, documentId);
            return document != null ? Ok(document) : NotFound();
        }

        [HttpDelete("delete-document")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> DeleteDocument(Guid documentId)
        {
            var tenantId = GetTenantId();
            await _service.DeleteDocumentAsync(tenantId, documentId);
            return Ok(new { success = true });
        }

        [HttpPost("search-similar")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> SearchSimilar([FromBody] SearchSimilarRequest request)
        {
            var tenantId = GetTenantId();
            var embedding = new Vector(request.QueryEmbedding);
            var results = await _service.SearchSimilarAsync(tenantId, request.CloneId, embedding, request.Limit);
            return Ok(results);
        }

        [HttpPost("get-chat-context")]
        [ProducesResponseType(200)]
        public async Task<IActionResult> GetChatContext([FromBody] GetChatContextRequest request)
        {
            var tenantId = GetTenantId();
            var embedding = new Vector(request.QueryEmbedding);
            var results = await _service.GetChatContextAsync(tenantId, request.CloneId, embedding, request.Limit);
            return Ok(results);
        }

        [HttpGet("get-personality")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetPersonality(Guid cloneId)
        {
            var tenantId = GetTenantId();
            var personality = await _service.GetPersonalityAsync(tenantId, cloneId);
            return personality != null ? Ok(personality) : NotFound();
        }

        [HttpGet("get-expertise")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetExpertise(Guid cloneId)
        {
            var tenantId = GetTenantId();
            var expertise = await _service.GetExpertiseAsync(tenantId, cloneId);
            return expertise != null ? Ok(expertise) : NotFound();
        }

        [HttpGet("build-system-prompt")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> BuildSystemPrompt(Guid cloneId)
        {
            var tenantId = GetTenantId();
            var prompt = await _service.BuildSystemPromptAsync(tenantId, cloneId);
            return prompt != null ? Ok(prompt) : NotFound();
        }

        private Guid GetTenantId()
        {
            var claim = User.FindFirst("tenant_id")?.Value;
            if (claim == null || !Guid.TryParse(claim, out var tenantId))
                throw new UnauthorizedAccessException("Invalid tenant claim");
            return tenantId;
        }
    }

    public class AddDocumentRequest
    {
        public Guid CloneId { get; set; }
        public string Filename { get; set; } = string.Empty;
        public string ContentType { get; set; } = string.Empty;
        public long Size { get; set; }
        public string Url { get; set; } = string.Empty;
    }

    public class SearchSimilarRequest
    {
        public Guid CloneId { get; set; }
        public float[] QueryEmbedding { get; set; } = Array.Empty<float>();
        public int Limit { get; set; } = 5;
    }

    public class GetChatContextRequest
    {
        public Guid CloneId { get; set; }
        public float[] QueryEmbedding { get; set; } = Array.Empty<float>();
        public int Limit { get; set; } = 5;
    }
}
#endregion
