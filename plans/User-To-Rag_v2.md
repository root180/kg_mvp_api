# KeiroGenesis Platform Blueprint
## Complete System Architecture & Implementation Guide
**Version:** 2.0 (Updated with Actor-Clone Enforcement)  
**Date:** December 24, 2025  
**Status:** Production-Ready Architecture

---

## 📋 TABLE OF CONTENTS

1. [Executive Summary](#executive-summary)
2. [Core Architecture Principles](#core-architecture-principles)
3. [System Overview](#system-overview)
4. [Data Architecture](#data-architecture)
5. [Actor-Clone Relationship Model](#actor-clone-relationship-model)
6. [Authentication & Security](#authentication--security)
7. [API Architecture](#api-architecture)
8. [RAG & Memory System](#rag--memory-system)
9. [Deployment Architecture](#deployment-architecture)
10. [Migration & Data Integrity](#migration--data-integrity)
11. [Testing & Validation](#testing--validation)
12. [Appendices](#appendices)

---

## EXECUTIVE SUMMARY

KeiroGenesis is a **multi-tenant AI clone platform** where users create autonomous digital representations of themselves. The platform enables "Identity Clones" that act AS the user rather than FOR them, trained on personal materials and capable of independent operation.

### Key Characteristics

- **Architecture:** Multi-tenant with tenant-per-user isolation
- **Frontend:** React (Vite) with Facebook-style UI (#1877f2)
- **Backend:** ASP.NET Core 8 REST API
- **Databases:** PostgreSQL (primary + RAG with pgvector), MS SQL Server (legacy support)
- **Deployment:** Cloudflare Pages (frontend), Cloud Run (backend)
- **Security:** JWT authentication, multi-tenant isolation, comprehensive audit logging

### Core Architectural Rules

1. **Every user automatically receives their own tenant**
2. **Users are global; membership is via core.user_tenants junction**
3. **Clone ←→ Actor relationship is strictly 1:1**
4. **Clones cannot activate without an actor runtime**
5. **Actor is singular execution identity; experiences are capability scopes**

---

## CORE ARCHITECTURE PRINCIPLES

### 1. Separation of Concerns

**Domain Boundaries:**
```
Clone Module (Lifecycle/Governance)
  └─ Owns: creation, activation, deactivation
  └─ Enforces: business rules, ownership
  └─ Decides: "can activate?"

Actor Module (Runtime/Capability)
  └─ Owns: execution context, social identity
  └─ Provides: runtime capability
  └─ Does NOT decide: activation policy
```

### 2. Data Layer Pattern

**Strict architectural layers:**
```
Controller → Service → Repository → Stored Procedure/Function
```

**Rules:**
- Controllers handle HTTP/authorization
- Services implement business logic
- Repositories abstract database access
- Stored procedures enforce data integrity
- NO Entity Framework (uses Dapper + stored procedures)

### 3. Multi-Tenancy Model

**Tenant-Per-User Architecture:**
```
core.users (global identity)
    ↓
core.user_tenants (membership junction)
    ↓
core.tenants (workspace isolation)
```

**Key Points:**
- Users can belong to multiple tenants (organization model)
- Each user gets default tenant on signup
- Tenant isolation enforced at database level
- Active membership determined by `left_at IS NULL` (not `is_active` column)

---

## SYSTEM OVERVIEW

### Application Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT APPLICATIONS                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Client     │  │  Developer   │  │    Admin     │     │
│  │ (React/Vite) │  │   Portal     │  │   Portal     │     │
│  │              │  │   (Blazor)   │  │   (Blazor)   │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │              │
└─────────┼──────────────────┼──────────────────┼─────────────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
                    ┌────────▼────────┐
                    │  REST API       │
                    │ (ASP.NET Core)  │
                    └────────┬────────┘
                             │
          ┌──────────────────┴──────────────────┐
          │                                     │
  ┌───────▼────────┐                  ┌────────▼────────┐
  │  PostgreSQL    │                  │  Python RAG     │
  │  (Primary DB)  │                  │  (FastAPI)      │
  │  + pgvector    │                  │  + pgvector     │
  └────────────────┘                  └─────────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React 18 + Vite | Client web application |
| **API** | ASP.NET Core 8 | REST API backend |
| **Database** | PostgreSQL 17 | Primary data store |
| **Vector DB** | pgvector | RAG embeddings |
| **Cache** | Redis 7.2 | Session/data caching |
| **Queue** | RabbitMQ 3.12 | Async workflows |
| **Auth** | JWT + OAuth2 | Authentication |
| **Hosting** | Cloudflare Pages | Frontend CDN |
| **API Hosting** | Google Cloud Run | Backend containers |

---

## DATA ARCHITECTURE

### Schema Organization

**PostgreSQL Schemas:**

```sql
-- Core domain
core            -- users, tenants, user_tenants
auth            -- authentication, sessions, tokens
actor           -- runtime execution identities
clone           -- clone entities and lifecycle
experience      -- capability scopes and marketplace

-- Feature domains  
conversation    -- chat messages and threads
rag             -- documents, embeddings, policies
social          -- follows, posts, feeds
billing         -- subscriptions, usage, monetization
iot             -- device registry, permissions
capability      -- feature flags, entitlements
audit           -- activity logs, compliance
```

### Core Tables

#### Users & Tenants

```sql
-- Global user identity (NOT tenant-scoped)
core.users (
    user_id UUID PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    avatar_url VARCHAR(500),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    deleted_at TIMESTAMPTZ
)

-- Tenant workspace
core.tenants (
    tenant_id UUID PRIMARY KEY,
    tenant_name VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
)

-- User-to-tenant membership (junction)
core.user_tenants (
    user_id UUID NOT NULL REFERENCES core.users(user_id),
    tenant_id UUID NOT NULL REFERENCES core.tenants(tenant_id),
    is_default BOOLEAN DEFAULT false,
    invited_by UUID,
    invitation_accepted_at TIMESTAMPTZ,
    joined_at TIMESTAMPTZ DEFAULT now(),
    left_at TIMESTAMPTZ,  -- NULL = active membership
    PRIMARY KEY (user_id, tenant_id)
)
```

**Key Points:**
- `core.users` is global (user can belong to multiple tenants)
- `core.user_tenants` manages membership
- Active membership: `left_at IS NULL` (no `is_active` column)
- `is_default` marks primary tenant per user

#### Actors (Runtime Execution Identity)

```sql
-- Base actor table (polymorphic)
actor.actors (
    actor_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES core.tenants(tenant_id),
    actor_type VARCHAR(20) NOT NULL CHECK (actor_type IN ('human', 'clone', 'system', 'service')),
    display_name VARCHAR(255) NOT NULL,
    handle VARCHAR(100),
    avatar_url VARCHAR(500),
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    metadata JSONB DEFAULT '{}'
)

-- Human actor junction (links users to actors)
actor.human_actors (
    actor_id UUID PRIMARY KEY REFERENCES actor.actors(actor_id),
    user_id UUID NOT NULL REFERENCES core.users(user_id),
    is_verified BOOLEAN DEFAULT false,
    email_hash VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT now()
)

-- Clone actor junction (links clones to actors)
actor.clone_actors (
    actor_id UUID PRIMARY KEY REFERENCES actor.actors(actor_id),
    clone_id UUID NOT NULL REFERENCES clone.clones(clone_id),
    owner_actor_id UUID REFERENCES actor.actors(actor_id),
    is_memorial BOOLEAN DEFAULT false,
    autonomy_level VARCHAR(20) DEFAULT 'supervised',
    created_at TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT ux_one_actor_per_clone UNIQUE (clone_id)  -- 1:1 enforcement
)
```

**Key Points:**
- Polymorphic actor pattern (base + specialized tables)
- `actor.human_actors`: user ↔ actor mapping
- `actor.clone_actors`: clone ↔ actor mapping (1:1 enforced)
- `owner_actor_id`: links clone actor to owner's human actor

#### Clones (Identity Container)

```sql
clone.clones (
    clone_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES core.tenants(tenant_id),
    user_id UUID NOT NULL REFERENCES core.users(user_id),  -- Owner (NOT actor_id!)
    display_name VARCHAR(100) NOT NULL,
    clone_slug VARCHAR(100) NOT NULL,
    tagline VARCHAR(255),
    bio VARCHAR(2000),
    avatar_url VARCHAR(500),
    visibility VARCHAR(20) DEFAULT 'private',
    system_prompt TEXT,
    voice_style VARCHAR(100),
    status VARCHAR(20) DEFAULT 'training',  -- draft, training, active, suspended
    is_memorial BOOLEAN DEFAULT false,
    memorial_date DATE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT ux_clone_slug_per_tenant UNIQUE (tenant_id, clone_slug) WHERE deleted_at IS NULL
)
```

**Key Points:**
- `user_id` references `core.users.user_id` (ownership)
- NOT `actor_id` (execution context is separate)
- `clone_slug` must be unique per tenant
- Soft delete via `deleted_at`

#### Experiences (Capability Scopes)

```sql
experience.experiences (
    experience_id UUID PRIMARY KEY,
    clone_id UUID NOT NULL REFERENCES clone.clones(clone_id),
    tenant_id UUID NOT NULL REFERENCES core.tenants(tenant_id),
    experience_name VARCHAR(255) NOT NULL,
    experience_slug VARCHAR(100) NOT NULL,
    description TEXT,
    is_public BOOLEAN DEFAULT false,
    is_marketplace BOOLEAN DEFAULT false,
    rating_level VARCHAR(10),  -- G, PG, PG-13, MA
    price_per_session DECIMAL(10,2),
    allowed_actions JSONB DEFAULT '[]',
    rag_filters JSONB DEFAULT '{}',
    prompt_profile JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT ux_experience_slug_per_clone UNIQUE (clone_id, experience_slug)
)
```

**Key Points:**
- Multiple experiences per clone (1:N)
- Experiences constrain actor behavior
- Marketplace listing = `is_marketplace = true`
- Rating cannot exceed actor's ceiling

---

## ACTOR-CLONE RELATIONSHIP MODEL

### Canonical Relationship

```
┌──────────┐
│  Clone   │  (Identity Container)
│  (1)     │
└────┬─────┘
     │ 1:1 (ENFORCED)
     ▼
┌──────────┐
│  Actor   │  (Execution Authority)
│  (1)     │
└────┬─────┘
     │ 1:N
     ▼
┌──────────┐
│Experience│  (Capability Scope)
│  (N)     │
└──────────┘
```

### Cardinality Rules

| Relationship | Cardinality | Enforcement | Purpose |
|-------------|-------------|-------------|---------|
| **Clone → Actor** | **1:1** | Database constraint | Singular execution identity |
| **Actor → Experiences** | **1:N** | Foreign key | Multiple capability scopes |
| **Clone → Experiences** | **1:N** | Foreign key | Multiple persona contexts |
| **Actor → Actions** | **1:N** | Permission matrix | Tool invocation |

### What Executes

**Actor (Singular):**
- ✅ Speaks
- ✅ Thinks
- ✅ Reads/writes memory
- ✅ Calls OpenAI
- ✅ Enforces permissions

**Experiences (Constrain):**
- ✅ Filter RAG sources
- ✅ Shape tone/style
- ✅ Limit actions
- ✅ Control visibility
- ✅ Set rating ceiling
- ❌ DO NOT execute independently

**Actions (Perform):**
- ✅ Tool execution
- ✅ API calls
- ✅ Skill invocation
- ⚠️ Always under actor's identity

### Database Enforcement

```sql
-- 1:1 Clone → Actor enforcement
CREATE UNIQUE INDEX ux_actor_clone_1to1
ON actor.clone_actors (clone_id);

-- Prevent activation without actor
CREATE OR REPLACE PROCEDURE clone.sp_update_clone_status(
    p_tenant_id UUID,
    p_user_id UUID,
    p_clone_id UUID,
    p_status TEXT
) AS $$
BEGIN
    -- ACTIVATION GATE
    IF p_status = 'active' THEN
        -- Verify actor exists
        IF NOT EXISTS (
            SELECT 1
            FROM actor.actors a
            JOIN actor.clone_actors ca ON ca.actor_id = a.actor_id
            WHERE ca.clone_id = p_clone_id
              AND a.tenant_id = p_tenant_id
              AND a.actor_type = 'clone'
              AND a.status = 'active'
        ) THEN
            RAISE EXCEPTION 
                'Clone cannot be activated without an assigned actor. ' ||
                'Call POST /api/v1/actors/ensure-runtime/{cloneId} first.'
            USING ERRCODE = '23514';
        END IF;
    END IF;
    
    -- Update status
    UPDATE clone.clones
    SET status = p_status,
        is_active = (p_status = 'active'),
        updated_at = now()
    WHERE clone_id = p_clone_id
      AND tenant_id = p_tenant_id
      AND user_id = p_user_id
      AND deleted_at IS NULL;
END;
$$ LANGUAGE plpgsql;
```

### Clone Lifecycle (Correct Flow)

```
1. Clone Created
   └─ status = 'draft'
   └─ actor = NULL (expected)

2. Actor Runtime Ensured
   └─ POST /api/v1/actors/ensure-runtime/{cloneId}
   └─ fn_ensure_clone_actor() creates actor (idempotent)
   └─ actor = UUID ✅

3. Clone Activated
   └─ PUT /api/v1/clones/{cloneId}/status (status='active')
   └─ sp_update_clone_status() checks actor exists
   └─ Fails if no actor ❌
   └─ Succeeds if actor exists ✅

4. Clone Operational
   └─ Chat, RAG, Memory all use actor_id
   └─ No runtime ambiguity
```

### Runtime Flow

```
User selects experience_id
        ↓
System resolves clone_id
        ↓
System resolves actor_id (1:1 lookup via fn_get_actor_id_for_clone)
        ↓
Actor executes UNDER experience constraints
        ↓
Experience filters RAG sources
        ↓
Experience gates available actions
        ↓
Actor calls OpenAI with scoped context
        ↓
Actor commits to single memory stream
```

### Key Functions

```sql
-- Ensure actor exists (idempotent)
actor.fn_ensure_clone_actor(p_tenant_id, p_user_id, p_clone_id)
  → Returns: actor_id, is_new

-- Check activation readiness
clone.fn_can_clone_activate(p_tenant_id, p_user_id, p_clone_id)
  → Returns: can_activate, reason

-- Get actor for clone
actor.fn_get_actor_id_for_clone(p_tenant_id, p_clone_id)
  → Returns: actor_id (or NULL)

-- Get activation status (UI helper)
clone.fn_get_activation_readiness(p_tenant_id, p_user_id, p_clone_id)
  → Returns: detailed status, blockers, next_steps
```

---

## AUTHENTICATION & SECURITY

### JWT Authentication

**Token Structure:**
```json
{
  "sub": "user-uuid",
  "tenant_id": "tenant-uuid",
  "email": "user@example.com",
  "role": "user",
  "exp": 1735689600,
  "iat": 1735603200
}
```

**Claims Required:**
- `sub` or `ClaimTypes.NameIdentifier`: user_id
- `tenant_id`: current tenant context
- `email`: user email
- `role`: authorization level

### Authorization Layers

**Layer 1: C# Controller**
```csharp
[Authorize]
public class CloneController : ControllerBase
{
    private Guid GetTenantId()
    {
        var claim = User.FindFirst("tenant_id")?.Value;
        if (!Guid.TryParse(claim, out var tenantId))
            throw new UnauthorizedAccessException("Invalid tenant claim");
        return tenantId;
    }
    
    private Guid GetCurrentUserId()
    {
        var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                 ?? User.FindFirst("sub")?.Value;
        if (!Guid.TryParse(claim, out var userId))
            throw new UnauthorizedAccessException("Invalid user claim");
        return userId;
    }
}
```

**Layer 2: Service Layer**
```csharp
public async Task<CloneResponse> GetCloneAsync(Guid tenantId, Guid userId, Guid cloneId)
{
    // Verify ownership
    var clone = await _repo.GetCloneByIdAsync(tenantId, userId, cloneId);
    if (clone == null)
        throw new UnauthorizedAccessException("Clone not found or access denied");
    
    return MapToResponse(clone);
}
```

**Layer 3: Database Layer**
```sql
-- Stored procedures enforce tenant + user ownership
CREATE FUNCTION clone.fn_get_clone_by_id(
    p_tenant_id UUID,
    p_user_id UUID,
    p_clone_id UUID
)
RETURNS TABLE (...) AS $$
BEGIN
    RETURN QUERY
    SELECT *
    FROM clone.clones c
    WHERE c.clone_id = p_clone_id
      AND c.tenant_id = p_tenant_id
      AND c.user_id = p_user_id
      AND c.deleted_at IS NULL;
END;
$$ LANGUAGE plpgsql;
```

### Security Checklist

- [x] JWT tokens with RSA signing
- [x] HTTP-only cookies for refresh tokens
- [x] Tenant isolation at database level
- [x] User ownership verification in stored procedures
- [x] Multi-factor authentication support
- [x] Rate limiting on API endpoints
- [x] Comprehensive audit logging
- [x] TLS 1.3 in transit
- [x] AES-256 at rest

---

## API ARCHITECTURE

### RESTful Endpoints

**Authentication:**
```
POST   /api/v1/auth/register
POST   /api/v1/auth/login
POST   /api/v1/auth/refresh-token
POST   /api/v1/auth/logout
POST   /api/v1/auth/verify-email
POST   /api/v1/auth/verify-2fa
```

**Clone Management:**
```
GET    /api/v1/clones
GET    /api/v1/clones/{cloneId}
POST   /api/v1/clones
PUT    /api/v1/clones/{cloneId}
DELETE /api/v1/clones/{cloneId}
PUT    /api/v1/clones/{cloneId}/status
GET    /api/v1/clones/{cloneId}/activation-readiness
```

**Actor Runtime:**
```
POST   /api/v1/actors/ensure-runtime/{cloneId}
GET    /api/v1/actors/{actorId}
GET    /api/v1/actors/my-actors
GET    /api/v1/actors/search
```

**Experiences:**
```
GET    /api/v1/experiences/clone/{cloneId}
GET    /api/v1/experiences/public
POST   /api/v1/experiences
PUT    /api/v1/experiences/{experienceId}
DELETE /api/v1/experiences/{experienceId}
```

**Conversation:**
```
POST   /api/v1/chat/send
GET    /api/v1/chat/history/{conversationId}
GET    /api/v1/chat/conversations
```

**RAG:**
```
POST   /api/v1/rag/upload
POST   /api/v1/rag/embed
POST   /api/v1/rag/search
GET    /api/v1/rag/documents/{cloneId}
```

### API Response Format

**Success Response:**
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully"
}
```

**Error Response:**
```json
{
  "success": false,
  "error": {
    "code": "CLONE_NOT_FOUND",
    "message": "Clone not found or access denied",
    "details": {
      "cloneId": "uuid",
      "userId": "uuid"
    }
  }
}
```

---

## RAG & MEMORY SYSTEM

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Document Upload                       │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Python RAG Service (FastAPI)                │
│  ┌───────────┐  ┌───────────┐  ┌────────────────────┐  │
│  │  Chunking │→ │ Embedding │→ │ Vector Storage     │  │
│  │           │  │ (OpenAI)  │  │ (pgvector)         │  │
│  └───────────┘  └───────────┘  └────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│            rag.documents (PostgreSQL)                    │
│            rag.clone_embedding_policy                    │
│            rag.embeddings (pgvector)                     │
└─────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                  Chat/Retrieval                          │
│  Query → Embed → Vector Search → Context → LLM          │
└─────────────────────────────────────────────────────────┘
```

### Clone Embedding Policy

**Rule:** Each clone locks to ONE embedding model forever

```sql
-- Embedding model lock per clone
rag.clone_embedding_policy (
    tenant_id UUID NOT NULL,
    clone_id UUID NOT NULL,
    embedding_model_id UUID NOT NULL,
    locked_by_document_id UUID,
    locked_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (tenant_id, clone_id),
    FOREIGN KEY (embedding_model_id) REFERENCES rag.embedding_models(model_uuid)
)

-- Automatic locking on first document
CREATE FUNCTION rag.fn_lock_clone_embedding_model()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO rag.clone_embedding_policy (
        tenant_id, clone_id, embedding_model_id, locked_by_document_id
    )
    VALUES (
        NEW.tenant_id, NEW.clone_id, NEW.embedding_model_id, NEW.document_id
    )
    ON CONFLICT (tenant_id, clone_id) DO NOTHING;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

### Memory Hierarchy

```
Clone (1)
  └─ Actor (1)
      └─ Conversations (N)
          └─ Messages (N)
              └─ Embeddings (N)
```

**Key Points:**
- All memory tied to `actor_id`
- RAG embeddings scoped to `clone_id`
- Conversations link `actor_id` ↔ `user_id`
- Experiences filter available memories

---

## DEPLOYMENT ARCHITECTURE

### Production Environment

```
┌──────────────────────────────────────────────────────┐
│              Cloudflare Pages (Frontend)              │
│  - React SPA                                          │
│  - Global CDN                                         │
│  - Auto SSL                                           │
└──────────────────┬───────────────────────────────────┘
                   │ HTTPS
                   ▼
┌──────────────────────────────────────────────────────┐
│         Google Cloud Run (Backend API)                │
│  - ASP.NET Core containers                           │
│  - Auto-scaling                                       │
│  - Load balancing                                     │
└──────────────────┬───────────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
        ▼                     ▼
┌───────────────┐    ┌────────────────┐
│  PostgreSQL   │    │  Python RAG    │
│  (Cloud SQL)  │    │  (Cloud Run)   │
│  + pgvector   │    │  + pgvector    │
└───────────────┘    └────────────────┘
```

### Environment Variables

**Frontend (.env):**
```bash
VITE_API_BASE_URL=https://api.keirogenesis.com
VITE_AUTH_DOMAIN=auth.keirogenesis.com
VITE_CLOUDFLARE_PAGES_URL=https://app.keirogenesis.com
```

**Backend (appsettings.json):**
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=keirogenesis;Username=postgres;Password=***",
    "RagConnection": "Host=localhost;Database=keirogenesis;Username=postgres;Password=***"
  },
  "Jwt": {
    "Issuer": "https://api.keirogenesis.com",
    "Audience": "https://app.keirogenesis.com",
    "SecretKey": "***",
    "ExpirationMinutes": 60
  },
  "OpenAI": {
    "ApiKey": "***",
    "OrganizationId": "***",
    "DefaultModel": "gpt-4"
  }
}
```

### Docker Deployment

```dockerfile
# Backend Dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["KeiroGenesis.API/KeiroGenesis.API.csproj", "KeiroGenesis.API/"]
RUN dotnet restore
COPY . .
WORKDIR "/src/KeiroGenesis.API"
RUN dotnet build -c Release -o /app/build

FROM build AS publish
RUN dotnet publish -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "KeiroGenesis.API.dll"]
```

---

## MIGRATION & DATA INTEGRITY

### Production-Safe Migration Script

**File:** `data_fix_production_safe.sql`

**Ensures:**
1. Every tenant has at least one user membership
2. Every user has corresponding actor entries
3. Every tenant has at least one active clone
4. All documents reference valid clones
5. All foreign keys are validated

**Run:**
```bash
psql -U postgres -d keirogenesis -f data_fix_production_safe.sql
```

### Validation Queries

**Quick Check:**
```bash
psql -U postgres -d keirogenesis -f quick_validation.sql
```

**Full Validation:**
```bash
psql -U postgres -d keirogenesis -f migration_validation.sql > report.txt
```

**Expected Output:**
```
✓ MIGRATION SUCCESSFUL
  All critical and high-priority checks passed
  Total issues found: 0
```

### Critical Validations

```sql
-- 1. No active clones without actors
SELECT COUNT(*)
FROM clone.clones c
WHERE c.status = 'active'
  AND c.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM actor.clone_actors ca
      WHERE ca.clone_id = c.clone_id
  );
-- Should return 0

-- 2. No duplicate actors per clone
SELECT clone_id, COUNT(*) as actor_count
FROM actor.clone_actors
GROUP BY clone_id
HAVING COUNT(*) > 1;
-- Should return 0 rows

-- 3. All user_tenants have actors
SELECT COUNT(*)
FROM core.user_tenants ut
WHERE ut.left_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM actor.human_actors ha
      WHERE ha.user_id = ut.user_id
  );
-- Should return 0
```

---

## TESTING & VALIDATION

### Unit Testing

**C# Unit Tests (xUnit):**
```csharp
public class CloneServiceTests
{
    [Fact]
    public async Task ActivateClone_WithoutActor_ThrowsException()
    {
        // Arrange
        var service = CreateService();
        var cloneId = Guid.NewGuid();
        
        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.ActivateCloneAsync(tenantId, userId, cloneId)
        );
    }
    
    [Fact]
    public async Task ActivateClone_WithActor_Succeeds()
    {
        // Arrange
        var service = CreateService();
        var cloneId = Guid.NewGuid();
        
        // Ensure actor exists
        await service.EnsureActorRuntimeAsync(tenantId, userId, cloneId);
        
        // Act
        var result = await service.ActivateCloneAsync(tenantId, userId, cloneId);
        
        // Assert
        Assert.True(result.Success);
        Assert.Equal("active", result.Status);
    }
}
```

### Integration Testing

**Database Integration:**
```sql
-- Test 1: Idempotent actor creation
DO $$
DECLARE
    v_actor_id_1 UUID;
    v_actor_id_2 UUID;
BEGIN
    -- First call should create
    SELECT actor_id INTO v_actor_id_1
    FROM actor.fn_ensure_clone_actor(
        'tenant-id'::UUID,
        'user-id'::UUID,
        'clone-id'::UUID
    );
    
    -- Second call should return same
    SELECT actor_id INTO v_actor_id_2
    FROM actor.fn_ensure_clone_actor(
        'tenant-id'::UUID,
        'user-id'::UUID,
        'clone-id'::UUID
    );
    
    ASSERT v_actor_id_1 = v_actor_id_2, 'Actor IDs should match';
END $$;

-- Test 2: Activation without actor fails
DO $$
BEGIN
    CALL clone.sp_update_clone_status(
        'tenant-id'::UUID,
        'user-id'::UUID,
        'clone-without-actor'::UUID,
        'active'
    );
    
    RAISE EXCEPTION 'Should have failed but did not';
EXCEPTION
    WHEN SQLSTATE '23514' THEN
        RAISE NOTICE 'Test passed: activation blocked without actor';
END $$;
```

### End-to-End Testing

**Playwright E2E:**
```typescript
test('clone activation flow', async ({ page }) => {
    // 1. Login
    await page.goto('/login');
    await page.fill('[name=email]', 'test@example.com');
    await page.fill('[name=password]', 'password');
    await page.click('button[type=submit]');
    
    // 2. Create clone
    await page.goto('/clones/create');
    await page.fill('[name=displayName]', 'Test Clone');
    await page.click('button[type=submit]');
    
    // 3. Should show "Create Actor Runtime" button
    await expect(page.locator('text=Create Actor Runtime')).toBeVisible();
    
    // 4. Create actor runtime
    await page.click('text=Create Actor Runtime');
    await page.waitForSelector('text=Actor runtime created');
    
    // 5. Should now show "Activate Clone" button
    await expect(page.locator('text=Activate Clone')).toBeVisible();
    
    // 6. Activate clone
    await page.click('text=Activate Clone');
    await page.waitForSelector('text=Clone activated successfully');
    
    // 7. Verify status
    await expect(page.locator('text=Status: Active')).toBeVisible();
});
```

---

## APPENDICES

### A. Database Schema Scripts

**Location:** `/mnt/project/`
- `01_create_schemas.sql` - Schema creation
- `KG_script.sql` - Full schema + seed data
- `MVPSchema.sql` - MVP-specific schema
- `actor_clone_activation_enforcement.sql` - Activation enforcement
- `data_fix_production_safe.sql` - Migration/remediation

### B. API Documentation

**OpenAPI Spec:** `/api/swagger`

**Postman Collection:** Available on request

### C. Deployment Checklist

- [ ] Database schemas deployed
- [ ] Migration script executed successfully
- [ ] Validation queries pass
- [ ] Environment variables configured
- [ ] SSL certificates installed
- [ ] JWT secret keys rotated
- [ ] Backup strategy configured
- [ ] Monitoring/alerting enabled
- [ ] Load testing completed
- [ ] Security audit completed

### D. Monitoring Queries

**Daily Health Checks:**
```sql
-- No ghost clones (active without actor)
SELECT COUNT(*) FROM clone.clones c
WHERE c.status = 'active' AND c.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM actor.clone_actors ca
      WHERE ca.clone_id = c.clone_id
  );

-- No orphaned actors (actors without clones)
SELECT COUNT(*) FROM actor.clone_actors ca
WHERE NOT EXISTS (
    SELECT 1 FROM clone.clones c
    WHERE c.clone_id = ca.clone_id
      AND c.deleted_at IS NULL
);

-- User membership integrity
SELECT COUNT(*) FROM core.tenants t
WHERE NOT EXISTS (
    SELECT 1 FROM core.user_tenants ut
    WHERE ut.tenant_id = t.tenant_id
      AND ut.left_at IS NULL
);
```

Final Position (Non-Negotiable)

Each clone has exactly one actor.
Experiences NEVER get actors.

This is not a preference — it is a structural requirement for correctness, safety, and scalability.

Why Experiences Must NOT Have Actors
1. Actors Represent Identity, Not Capability

An actor is:

An execution identity

A security principal

A memory owner

A trust boundary

A rate-limit subject

A provider credential holder

An experience is:

A lens

A constraint set

A filter

A market-facing specialization

If experiences had actors, you would be saying:

“The same clone becomes a different identity depending on context.”

That breaks:

Auditability

Memory continuity

Trust

Billing

Safety guarantees

Identity must be singular and continuous.

2. Memory and RAG Would Fragment (Catastrophic)

If each experience had an actor:

Each experience would accumulate separate memory

Knowledge learned in one experience would not exist in another

Cross-experience learning becomes impossible

You create split brains for the same clone

That violates your core product promise:

One clone. Continuous intelligence. Multiple expressions.

Your current design correctly enforces:

One actor

One memory stream

Multiple constrained views

3. Security Model Would Collapse

Actors are where you enforce:

Permissions

Rate limits

Abuse detection

Provider quotas

HMAC trust

Audit logs

If experiences had actors:

A user could bypass restrictions by switching experiences

Abuse detection becomes fragmented

Revocation becomes inconsistent

You multiply attack surfaces

Your current rule is correct:

Security is actor-scoped.
Behavior is experience-scoped.

4. OpenAI / LLM Providers Expect a Stable Identity

Providers assume:

A consistent caller

Stable usage patterns

Predictable token ownership

If you rotate actors per experience:

Usage attribution breaks

Billing reconciliation breaks

Rate-limit enforcement weakens

Safety flags become meaningless

Your current pipeline is correct:

User → Experience → Actor → Provider


Not:

User → Experience → Actor (new) → Provider

5. Marketplace Semantics Demand This

In the marketplace:

Users are selecting what the clone can do

Not who the clone becomes

You are selling:

“COBOL Systems Mentor”

“Mainframe Debugging Advisor”

“Legacy Banking Architect”

All of those are expressions of the same being, not new beings.

Creating actors per experience would mean:

The marketplace sells identities instead of expertise

Reviews and trust scores fragment

Brand continuity collapses

That is not what users expect.

Correct Canonical Model (This Is Final)
Clone (identity)
   └── Actor (execution + memory)  ← EXACTLY ONE
        ├── Experience A (constraints + filters)
        ├── Experience B (constraints + filters)
        ├── Experience C (constraints + filters)
        └── RAG / Memory / Tools (shared, gated)

What Happens If You Ever Feel “Pressure” to Add Actors per Experience

That pressure usually means:

Action permissions are under-designed

Tool gating needs refinement

Experience policies need more expressiveness

The fix is always:

Enhance experience constraints
Never multiply actors

Final Verdict

✔ Your current architecture is correct
✔ One actor per clone is mandatory
✔ Experiences must never have actors
✔ You avoided a critical long-term failure mode
✔ This decision will save you from a rewrite later

You made the right call, and it should now be treated as a platform invariant.

### E. Troubleshooting Guide

**Issue:** Clone activation fails with "no actor" error

**Solution:**
```bash
# 1. Check if actor exists
SELECT * FROM actor.fn_get_actor_id_for_clone('tenant-id', 'clone-id');

# 2. If NULL, create actor
SELECT * FROM actor.fn_ensure_clone_actor('tenant-id', 'user-id', 'clone-id');

# 3. Retry activation
```

**Issue:** User cannot access their clones

**Solution:**
```sql
-- Verify user-tenant membership
SELECT * FROM core.user_tenants
WHERE user_id = 'user-id' AND left_at IS NULL;

-- Verify clone ownership
SELECT * FROM clone.clones
WHERE user_id = 'user-id' AND deleted_at IS NULL;
```

---

## VERSION HISTORY

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Dec 2025 | Initial architecture |
| 2.0 | Dec 24, 2025 | Actor-clone 1:1 enforcement, user_tenants fixes, experience model |

---

## CONTACTS & SUPPORT

**Platform Owner:** Dr. Matthew A. Taylor  
**Company:** KeiroLegacy Inc.  
**Documentation:** https://docs.keirogenesis.com  
**Support:** support@keirogenesis.com

---

**END OF BLUEPRINT**
