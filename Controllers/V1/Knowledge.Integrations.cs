// ============================================================================
// KNOWLEDGE UPLOAD - GOOGLE DRIVE & GITHUB INTEGRATIONS
// ============================================================================
// ✅ Google Drive file import with OAuth
// ✅ GitHub repository ingestion
// ✅ Same compliance pipeline as other sources
// ============================================================================

using KeiroGenesis.API.DTOs.Knowledge;
using KeiroGenesis.API.Exceptions;
using KeiroGenesis.API.Repositories;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace KeiroGenesis.API.Services
{
    public partial class KnowledgeService
    {
        /// <summary>
        /// Upload from Google Drive
        /// Requires: knowledge.google.import capability
        /// </summary>
        public async Task<KnowledgeUploadResponse> UploadGoogleDriveAsync(
            Guid tenantId,
            Guid userId,
            Guid cloneId,
            UploadGoogleDriveRequest request)
        {
            try
            {
                // ✅ Compliance pipeline
                await ValidateCloneOwnershipAsync(tenantId, userId, cloneId);
                await RequireCapabilityAsync(tenantId, userId, "knowledge.google.import");
                await CheckRateLimitAsync(tenantId, userId, cloneId);

                // ✅ Step 1: Download file from Google Drive
                (string fileName, byte[] fileContent, string mimeType) = await DownloadGoogleDriveFileAsync(
                     request.FileId,
                    request.AccessToken);

                // ✅ Step 2: Create document record
                var sourceUri = $"gdrive://{request.FileId}";
                var documentId = await _repo.CreateDocumentAsync(
                    tenantId,
                    cloneId,
                    "google-drive",
                    sourceUri,
                    fileName);

                // ✅ Step 3: Send to RAG service
                var ragPayload = new
                {
                    document_id = documentId,
                    clone_id = cloneId,
                    tenant_id = tenantId,
                    file_name = fileName,
                    file_content = Convert.ToBase64String(fileContent),
                    mime_type = mimeType,
                    source_type = "google-drive",
                    metadata = new
                    {
                        google_drive_file_id = request.FileId,
                        original_name = fileName
                    }
                };

                var response = await SendToRAGServiceAsync(
                    "/ingest/google-drive",
                    ragPayload,
                    documentId);

                return new KnowledgeUploadResponse
                {
                    Success = true,
                    Message = "Google Drive file submitted for processing",
                    DocumentId = documentId,
                    Status = "processing"
                };
            }
            catch (CloneOwnershipException ex)
            {
                return new KnowledgeUploadResponse { Success = false, Message = ex.Message, ErrorCode = "OWNERSHIP_DENIED" };
            }
            catch (CapabilityDeniedException ex)
            {
                return new KnowledgeUploadResponse { Success = false, Message = ex.Message, ErrorCode = "CAPABILITY_DENIED" };
            }
            catch (RateLimitExceededException ex)
            {
                return new KnowledgeUploadResponse { Success = false, Message = ex.Message, ErrorCode = "RATE_LIMIT_EXCEEDED" };
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Failed to download from Google Drive");
                return new KnowledgeUploadResponse
                {
                    Success = false,
                    Message = "Failed to access Google Drive file. Check access token and permissions.",
                    ErrorCode = "GOOGLE_DRIVE_ERROR"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to upload from Google Drive");
                return new KnowledgeUploadResponse { Success = false, Message = "Internal error occurred", ErrorCode = "INTERNAL_ERROR" };
            }
        }

        /// <summary>
        /// Upload from GitHub repository
        /// Requires: knowledge.github.import capability
        /// </summary>
        public async Task<KnowledgeUploadResponse> UploadGitHubAsync(
            Guid tenantId,
            Guid userId,
            Guid cloneId,
            UploadGitHubRequest request)
        {
            try
            {
                // ✅ Compliance pipeline
                await ValidateCloneOwnershipAsync(tenantId, userId, cloneId);
                await RequireCapabilityAsync(tenantId, userId, "knowledge.github.import");
                await CheckRateLimitAsync(tenantId, userId, cloneId);

                // ✅ Validate GitHub URL
                if (!IsValidGitHubUrl(request.RepoUrl))
                {
                    return new KnowledgeUploadResponse
                    {
                        Success = false,
                        Message = "Invalid GitHub repository URL",
                        ErrorCode = "VALIDATION_ERROR"
                    };
                }

                // ✅ Create document record
                var sourceUri = $"{request.RepoUrl}@{request.Branch}";
                if (!string.IsNullOrEmpty(request.Path))
                {
                    sourceUri += $":{request.Path}";
                }

                var documentId = await _repo.CreateDocumentAsync(
                    tenantId,
                    cloneId,
                    "github",
                    sourceUri,
                    ExtractRepoName(request.RepoUrl));

                // ✅ Send to RAG service (async processing)
                var ragPayload = new
                {
                    document_id = documentId,
                    clone_id = cloneId,
                    tenant_id = tenantId,
                    repo_url = request.RepoUrl,
                    branch = request.Branch,
                    path = request.Path,
                    source_type = "github",
                    metadata = new
                    {
                        repo_name = ExtractRepoName(request.RepoUrl),
                        branch = request.Branch,
                        path = request.Path ?? "/"
                    }
                };

                var response = await SendToRAGServiceAsync(
                    "/ingest/github",
                    ragPayload,
                    documentId);

                return new KnowledgeUploadResponse
                {
                    Success = true,
                    Message = "GitHub repository submitted for processing",
                    DocumentId = documentId,
                    Status = "processing"
                };
            }
            catch (CloneOwnershipException ex)
            {
                return new KnowledgeUploadResponse { Success = false, Message = ex.Message, ErrorCode = "OWNERSHIP_DENIED" };
            }
            catch (CapabilityDeniedException ex)
            {
                return new KnowledgeUploadResponse { Success = false, Message = ex.Message, ErrorCode = "CAPABILITY_DENIED" };
            }
            catch (RateLimitExceededException ex)
            {
                return new KnowledgeUploadResponse { Success = false, Message = ex.Message, ErrorCode = "RATE_LIMIT_EXCEEDED" };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to upload from GitHub");
                return new KnowledgeUploadResponse { Success = false, Message = "Internal error occurred", ErrorCode = "INTERNAL_ERROR" };
            }
        }

        // ============================================================================
        // PRIVATE HELPERS
        // ============================================================================

        /// <summary>
        /// Download file from Google Drive using OAuth token
        /// </summary>
        private async Task<(string fileName, byte[] content, string mimeType)> DownloadGoogleDriveFileAsync(
            string fileId,
            string accessToken)
        {
            using var client = new HttpClient();

            // ✅ Get file metadata
            var metadataUrl = $"https://www.googleapis.com/drive/v3/files/{fileId}?fields=name,mimeType";
            var metadataRequest = new HttpRequestMessage(HttpMethod.Get, metadataUrl);
            metadataRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var metadataResponse = await client.SendAsync(metadataRequest);

            if (!metadataResponse.IsSuccessStatusCode)
            {
                var error = await metadataResponse.Content.ReadAsStringAsync();
                _logger.LogError("Google Drive metadata fetch failed: {Error}", error);
                throw new HttpRequestException($"Failed to fetch file metadata: {metadataResponse.StatusCode}");
            }

            var metadataJson = await metadataResponse.Content.ReadAsStringAsync();
            var metadata = JsonSerializer.Deserialize<JsonElement>(metadataJson);
            var fileName = metadata.GetProperty("name").GetString() ?? "unknown";
            var mimeType = metadata.GetProperty("mimeType").GetString() ?? "application/octet-stream";

            // ✅ Download file content
            var downloadUrl = $"https://www.googleapis.com/drive/v3/files/{fileId}?alt=media";
            var downloadRequest = new HttpRequestMessage(HttpMethod.Get, downloadUrl);
            downloadRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var downloadResponse = await client.SendAsync(downloadRequest);

            if (!downloadResponse.IsSuccessStatusCode)
            {
                var error = await downloadResponse.Content.ReadAsStringAsync();
                _logger.LogError("Google Drive download failed: {Error}", error);
                throw new HttpRequestException($"Failed to download file: {downloadResponse.StatusCode}");
            }

            var content = await downloadResponse.Content.ReadAsByteArrayAsync();

            return (fileName, content, mimeType);
        }

        /// <summary>
        /// Validate GitHub repository URL format
        /// </summary>
        private bool IsValidGitHubUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;

            // Accept both HTTPS and SSH formats
            var validPatterns = new[]
            {
                @"^https://github\.com/[\w-]+/[\w.-]+/?$",
                @"^git@github\.com:[\w-]+/[\w.-]+\.git$"
            };

            return validPatterns.Any(pattern =>
                System.Text.RegularExpressions.Regex.IsMatch(url, pattern));
        }

        /// <summary>
        /// Extract repository name from GitHub URL
        /// </summary>
        private string ExtractRepoName(string url)
        {
            // https://github.com/owner/repo → repo
            // git@github.com:owner/repo.git → repo

            var parts = url.TrimEnd('/').Split('/');
            var name = parts[^1].Replace(".git", "");

            return name;
        }
    }
}

// ============================================================================
// CONTROLLER UPDATES (Add these methods to KnowledgeController)
// ============================================================================

namespace KeiroGenesis.API.Controllers.V1
{
    public partial class KnowledgeController
    {
        /// <summary>
        /// Upload Google Drive file
        /// POST /api/v1/clonewizard/{cloneId}/knowledge/google-drive
        /// </summary>
        [HttpPost("google-drive")]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 202)]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 400)]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 402)]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 403)]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 429)]
        public async Task<IActionResult> UploadGoogleDrive(
            [FromRoute] Guid cloneId,
            [FromBody] UploadGoogleDriveRequest request)
        {
            var result = await _service.UploadGoogleDriveAsync(
                GetTenantId(),
                GetUserId(),
                cloneId,
                request);

            return MapResponseToStatus(result);
        }

        /// <summary>
        /// Upload GitHub repository
        /// POST /api/v1/clonewizard/{cloneId}/knowledge/github
        /// </summary>
        [HttpPost("github")]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 202)]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 400)]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 402)]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 403)]
        [ProducesResponseType(typeof(KnowledgeUploadResponse), 429)]
        public async Task<IActionResult> UploadGitHub(
            [FromRoute] Guid cloneId,
            [FromBody] UploadGitHubRequest request)
        {
            var result = await _service.UploadGitHubAsync(
                GetTenantId(),
                GetUserId(),
                cloneId,
                request);

            return MapResponseToStatus(result);
        }
    }
}

// ============================================================================
// FRONTEND INTEGRATION EXAMPLES
// ============================================================================

/*
// ============================================================================
// 1. GOOGLE DRIVE UPLOAD (Frontend)
// ============================================================================

// Step 1: Get OAuth token from Google
// User clicks "Add from Google Drive" → redirect to Google OAuth

const GOOGLE_CLIENT_ID = 'your-client-id';
const GOOGLE_REDIRECT_URI = 'http://localhost:3000/google-callback';
const GOOGLE_SCOPES = 'https://www.googleapis.com/auth/drive.readonly';

const initiateGoogleDriveAuth = () => {
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${GOOGLE_CLIENT_ID}&` +
    `redirect_uri=${GOOGLE_REDIRECT_URI}&` +
    `response_type=token&` +
    `scope=${GOOGLE_SCOPES}`;
  
  window.location.href = authUrl;
};

// Step 2: Handle callback and get access token
// On /google-callback page:
const handleGoogleCallback = () => {
  const hash = window.location.hash.substring(1);
  const params = new URLSearchParams(hash);
  const accessToken = params.get('access_token');
  
  // Store token temporarily
  sessionStorage.setItem('google_access_token', accessToken);
  
  // Open file picker
  showGoogleFilePicker(accessToken);
};

// Step 3: Use Google Picker to select file
const showGoogleFilePicker = (accessToken) => {
  // Load Google Picker API
  gapi.load('picker', () => {
    const picker = new google.picker.PickerBuilder()
      .addView(google.picker.ViewId.DOCS)
      .setOAuthToken(accessToken)
      .setCallback((data) => {
        if (data.action === google.picker.Action.PICKED) {
          const fileId = data.docs[0].id;
          uploadGoogleDriveFile(fileId, accessToken);
        }
      })
      .build();
    
    picker.setVisible(true);
  });
};

// Step 4: Upload to backend
const uploadGoogleDriveFile = async (fileId, accessToken) => {
  const response = await fetch(
    `${baseUrl}/api/v1/clonewizard/${cloneId}/knowledge/google-drive`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${yourApiToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        file_id: fileId,
        access_token: accessToken
      })
    }
  );

  const result = await response.json();
  console.log('Upload result:', result);
};

// ============================================================================
// 2. GITHUB UPLOAD (Frontend)
// ============================================================================

const uploadGitHubRepo = async (cloneId, repoUrl, branch = 'main', path = null) => {
  const response = await fetch(
    `${baseUrl}/api/v1/clonewizard/${cloneId}/knowledge/github`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        repo_url: repoUrl,
        branch: branch,
        path: path  // Optional: specific folder/file
      })
    }
  );

  return await response.json();
};

// Usage:
await uploadGitHubRepo(
  'clone-uuid-here',
  'https://github.com/octocat/Hello-World',
  'main',
  'docs'  // Optional: only ingest /docs folder
);

*/