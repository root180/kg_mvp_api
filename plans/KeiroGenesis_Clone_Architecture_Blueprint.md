# KeiroGenesis Clone Architecture Blueprint
**Version:** 1.0  
**Date:** December 24, 2025  
**Status:** Canonical Specification

---

## 🎯 CORE PRINCIPLE

> **The clone does not learn by talking. The clone learns by being taught.**

- **Chat** = Expression (ephemeral reasoning)
- **Experience + RAG** = Formation (permanent memory)

---

## 🧠 THE CANONICAL FLOW (END-TO-END)

```
Human User
   │
   ├─► Clone Activation (Identity Comes Online)
   │       │
   │       ├─► Guarantees:
   │       │   • clones.clones → Identity exists
   │       │   • actor.actors (clone) → Can speak/act
   │       │   • rag.clone_embedding_policy → Memory space locked
   │       │   • clone.status = 'active' → Allowed to interact
   │       │
   │       └─► ⚠️ NO ACTIVATION → NO CHAT → NO RAG
   │
   ├─► Experience Creation (Curated Truth)
   │       │
   │       ├─► What it IS:
   │       │   • Curated, intentional, owner-authored narrative artifact
   │       │   • Owned by clone, created by human owner
   │       │   • Rated by policy, published or private
   │       │
   │       ├─► What it IS NOT:
   │       │   • ✗ Chat log
   │       │   • ✗ Raw RAG documents
   │       │   • ✗ Ephemeral memory
   │       │
   │       └─► Purpose: Human-curated truth allowed to shape clone worldview
   │
   ├─► RAG Ingestion (Semantic Memory)
   │       │
   │       ├─► What RAG represents:
   │       │   • Clone's long-term semantic memory
   │       │   • Stores: Experiences, Documents, Teachings, Doctrine
   │       │
   │       ├─► Key constraint:
   │       │   • ONE embedding space per clone
   │       │   • rag.clone_embedding_policy locks the model
   │       │   • NO mixing vector spaces
   │       │
   │       └─► Formula: RAG = what the clone KNOWS
   │
   ├─► Chat Session (Live Reasoning Layer)
   │       │
   │       ├─► What chat IS:
   │       │   • Ephemeral reasoning over:
   │       │     1. Clone's identity
   │       │     2. Clone's experiences
   │       │     3. Clone's retrieved memories
   │       │     4. Current prompt
   │       │
   │       ├─► What chat CANNOT do:
   │       │   • ✗ Write directly to RAG
   │       │   • ✗ Mutate memory
   │       │   • ✗ Self-teach
   │       │
   │       └─► Chat may propose new memories (human-governed action)
   │
   └─► LLM Provider (OpenAI, Anthropic, etc.)
           │
           ├─► What the LLM IS:
           │   • Stateless reasoning engine
           │   • Temporary mind
           │   • Replaceable provider
           │
           ├─► What the LLM receives per request:
           │   1. System Prompt
           │      • "You are [Clone Name]"
           │      • Identity constraints
           │      • Moral/behavioral guardrails
           │   2. Context Window
           │      • Retrieved RAG chunks
           │      • Published experiences
           │      • Recent chat messages
           │   3. User Prompt
           │
           └─► What the LLM does NOT know:
               • ✗ Tenants
               • ✗ Users
               • ✗ Policies
               • ✗ Memory rules
               (Enforced outside the model)
```

---

## 🧩 STATE OWNERSHIP (CRITICAL)

| Layer           | Mutable By         | When          | Storage                      |
|-----------------|--------------------|---------------|------------------------------|
| Clone Identity  | Human / Admin      | Rare          | `clones.clones`              |
| Experience      | Human Owner        | Intentional   | `clones.experiences`         |
| RAG Memory      | Ingestion Service  | Controlled    | `rag.*` + pgvector           |
| Chat            | Runtime            | Ephemeral     | `chat.sessions` (temporary)  |
| LLM             | Never              | Stateless     | None (external provider)     |

### 🔒 Immutability Guarantees

- **Clone Identity**: Only admin can change core identity attributes
- **Experiences**: Owner-authored, versioned, immutable once published
- **RAG Memory**: Write-once, no edits (new ingestion required)
- **Chat**: Session-scoped, pruned after retention period
- **LLM**: Zero persistence, stateless per request

---

## 🔗 DATABASE SCHEMA CONTRACTS

### 1. Clone Activation

```sql
-- Clone must exist before activation
clones.clones
├── clone_id (PK)
├── tenant_id (FK → auth.tenants)
├── owner_user_id (FK → auth.users)
├── status ENUM('created', 'activating', 'active', 'suspended', 'archived')
├── activated_at TIMESTAMP
└── created_at TIMESTAMP

-- Activation creates actor identity
actor.actors (clone)
├── actor_id (PK)
├── actor_type = 'clone'
├── reference_id (FK → clones.clone_id)
├── tenant_id (FK → auth.tenants)
└── can_interact BOOLEAN (true only if status = 'active')

-- Activation locks embedding policy
rag.clone_embedding_policy
├── clone_id (PK, FK → clones.clone_id)
├── embedding_model VARCHAR(100) -- e.g., 'text-embedding-3-small'
├── locked_at TIMESTAMP -- Set on first document ingestion
└── CONSTRAINT one_model_per_clone UNIQUE (clone_id)
```

**Activation Trigger:**
```sql
-- Stored procedure: sp_clone_activate
-- Validates: tenant limits, owner permissions
-- Creates: actor.actors entry
-- Initializes: rag.clone_embedding_policy (unlocked)
-- Sets: clones.status = 'active', activated_at = NOW()
```

---

### 2. Experience (Curated Memory)

```sql
clones.experiences
├── experience_id (PK)
├── clone_id (FK → clones.clone_id)
├── tenant_id (FK → auth.tenants)
├── created_by_user_id (FK → auth.users) -- Must be clone owner
├── title VARCHAR(200)
├── narrative TEXT -- The curated story/teaching
├── rating ENUM('formative', 'informative', 'contextual')
├── visibility ENUM('private', 'published')
├── published_at TIMESTAMP
├── version INT DEFAULT 1
└── created_at TIMESTAMP

-- Experiences are versioned (immutable once published)
clones.experience_versions
├── version_id (PK)
├── experience_id (FK → clones.experiences)
├── version_number INT
├── narrative_snapshot TEXT
├── published_at TIMESTAMP
└── published_by_user_id (FK → auth.users)
```

**Business Rules:**
- Only clone owner can create experiences
- Published experiences are immutable (new version required for changes)
- Rating determines RAG retrieval priority:
  - `formative` → Always included in context
  - `informative` → High semantic weight
  - `contextual` → Retrieved only when relevant

---

### 3. RAG (Long-Term Semantic Memory)

```sql
-- Embedding policy (one model per clone, locked on first ingestion)
rag.clone_embedding_policy
├── clone_id (PK)
├── embedding_model VARCHAR(100)
├── dimension INT -- e.g., 1536 for OpenAI ada-002
├── locked_at TIMESTAMP
└── locked_by_document_id (FK → rag.documents)

-- Documents (sources ingested into RAG)
rag.documents
├── document_id (PK)
├── clone_id (FK → clones.clone_id)
├── tenant_id (FK → auth.tenants)
├── source_type ENUM('experience', 'upload', 'teaching', 'doctrine')
├── source_id UUID -- References experiences, files, etc.
├── title VARCHAR(500)
├── ingested_at TIMESTAMP
├── ingested_by_user_id (FK → auth.users)
└── status ENUM('pending', 'processing', 'indexed', 'failed')

-- Memory chunks (vector storage with pgvector)
rag.memory_chunks
├── chunk_id (PK)
├── document_id (FK → rag.documents)
├── clone_id (FK → clones.clone_id) -- Redundant for query optimization
├── tenant_id (FK → auth.tenants)
├── chunk_text TEXT
├── chunk_index INT -- Position in source document
├── embedding vector(1536) -- pgvector column
├── metadata JSONB -- {page, section, rating, etc.}
└── created_at TIMESTAMP

-- Index for vector similarity search
CREATE INDEX idx_memory_chunks_embedding 
ON rag.memory_chunks 
USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);

-- Enforce tenant + clone isolation
CREATE INDEX idx_memory_chunks_clone 
ON rag.memory_chunks (clone_id, tenant_id);
```

**RAG Ingestion Pipeline:**
```
1. Document Upload → rag.documents (status='pending')
2. Check rag.clone_embedding_policy:
   • If locked → Validate model matches
   • If unlocked → Lock to current model
3. Chunk document → 512-1024 token chunks
4. Generate embeddings → Call OpenAI/Anthropic API
5. Store vectors → rag.memory_chunks
6. Update status → rag.documents (status='indexed')
```

**Critical Constraint:**
```sql
-- Prevent mixing embedding models
CREATE OR REPLACE FUNCTION enforce_embedding_model()
RETURNS TRIGGER AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM rag.clone_embedding_policy 
    WHERE clone_id = NEW.clone_id 
      AND locked_at IS NOT NULL
      AND embedding_model != (SELECT current_model FROM context)
  ) THEN
    RAISE EXCEPTION 'Cannot mix embedding models for clone %', NEW.clone_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enforce_embedding_model
BEFORE INSERT ON rag.memory_chunks
FOR EACH ROW EXECUTE FUNCTION enforce_embedding_model();
```

---

### 4. Chat (Ephemeral Reasoning Layer)

```sql
-- Chat sessions (temporary, pruned after retention period)
chat.sessions
├── session_id (PK)
├── clone_id (FK → clones.clone_id)
├── user_id (FK → auth.users) -- Who is chatting with the clone
├── tenant_id (FK → auth.tenants)
├── started_at TIMESTAMP
├── last_activity_at TIMESTAMP
├── status ENUM('active', 'closed', 'expired')
└── context_snapshot JSONB -- Cached identity + RAG metadata

-- Chat messages (ephemeral, kept for short retention)
chat.messages
├── message_id (PK)
├── session_id (FK → chat.sessions)
├── clone_id (FK → clones.clone_id)
├── sender_type ENUM('user', 'clone')
├── sender_id UUID -- user_id or clone_id
├── message_text TEXT
├── metadata JSONB -- {rag_chunks_used: [...], experience_ids: [...]}
├── created_at TIMESTAMP
└── ttl TIMESTAMP -- Auto-delete after retention period

-- Chat does NOT persist to RAG
-- Chat MAY propose experiences (human approval required)
chat.experience_proposals
├── proposal_id (PK)
├── session_id (FK → chat.sessions)
├── clone_id (FK → clones.clone_id)
├── proposed_by_message_id (FK → chat.messages)
├── proposed_narrative TEXT
├── status ENUM('pending', 'approved', 'rejected')
├── reviewed_by_user_id (FK → auth.users)
├── reviewed_at TIMESTAMP
└── created_at TIMESTAMP
```

**Chat Context Assembly (Per Message):**
```json
{
  "system_prompt": {
    "role": "system",
    "content": "You are [Clone Name]. [Identity constraints]. [Moral guardrails]."
  },
  "context_window": [
    {
      "type": "formative_experience",
      "source": "experience:uuid",
      "text": "...",
      "weight": 1.0
    },
    {
      "type": "rag_chunk",
      "source": "document:uuid/chunk:123",
      "text": "...",
      "similarity": 0.87
    },
    {
      "type": "recent_message",
      "sender": "user",
      "text": "...",
      "timestamp": "2025-12-24T10:30:00Z"
    }
  ],
  "user_prompt": {
    "role": "user",
    "content": "[Current user message]"
  }
}
```

---

## 🔄 STATE MACHINE: CLONE LIFECYCLE

```
┌─────────────┐
│   CREATED   │ ← Clone exists in DB, no AI capabilities
└──────┬──────┘
       │ sp_clone_activate()
       ▼
┌─────────────┐
│ ACTIVATING  │ ← Provisioning actor identity, RAG space
└──────┬──────┘
       │ On success
       ▼
┌─────────────┐
│   ACTIVE    │ ← ✅ Can chat, learn, interact
└──────┬──────┘
       │
       ├──► [Violation] ──► SUSPENDED
       │
       ├──► [Owner request] ──► ARCHIVED
       │
       └──► [Deletion] ──► PURGED (soft delete)
```

**State Transition Rules:**

| From       | To         | Trigger                          | Side Effects                                      |
|------------|------------|----------------------------------|---------------------------------------------------|
| CREATED    | ACTIVATING | `sp_clone_activate()`            | Insert `actor.actors`, init `rag.embedding_policy`|
| ACTIVATING | ACTIVE     | Provisioning complete            | Set `activated_at`, allow chat                    |
| ACTIVE     | SUSPENDED  | Policy violation detected        | Block chat, freeze RAG ingestion                  |
| ACTIVE     | ARCHIVED   | Owner request                    | Preserve data, disable interactions               |
| SUSPENDED  | ACTIVE     | Admin review + approval          | Restore chat, re-enable RAG                       |
| ARCHIVED   | ACTIVE     | Owner reactivation request       | Restore full capabilities                         |
| ANY        | PURGED     | Tenant deletion or legal request | Soft delete (audit retained)                      |

---

## 🛡️ MEMORY FORMATION PIPELINE

### The Safe Path: Chat → Proposal → Experience → RAG

```
┌──────────────────────────────────────────────────────────────┐
│ 1. CHAT (Ephemeral Reasoning)                                │
│    • User asks clone a question                              │
│    • Clone reasons over RAG + experiences                     │
│    • Clone responds in real-time                              │
│    • NO direct memory mutation                                │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 │ Clone: "Would you like me to remember this?"
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ 2. PROPOSAL (Optional)                                       │
│    • Clone suggests: "This feels important"                  │
│    • System creates: chat.experience_proposals               │
│    • Status: PENDING                                          │
│    • NO automatic acceptance                                  │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 │ Owner reviews proposal
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ 3. HUMAN REVIEW (Gate)                                       │
│    • Owner reads proposed narrative                          │
│    • Owner decides:                                           │
│      ✓ APPROVE → Becomes experience                          │
│      ✗ REJECT → Discarded, no memory formed                  │
│      ✏ EDIT → Owner curates before approval                  │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 │ If approved
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ 4. EXPERIENCE CREATION (Curated Truth)                       │
│    • Insert into clones.experiences                          │
│    • Set rating (formative/informative/contextual)           │
│    • Set visibility (private/published)                      │
│    • Version = 1, immutable once published                   │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 │ If published
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ 5. RAG INGESTION (Permanent Memory)                          │
│    • Create rag.documents (source_type='experience')         │
│    • Chunk narrative into memory_chunks                       │
│    • Generate embeddings (respecting clone's locked model)   │
│    • Store vectors in rag.memory_chunks                       │
│    • Status: INDEXED                                          │
└──────────────────────────────────────────────────────────────┘
                 │
                 ▼
        ✅ Clone now KNOWS this truth
           (Retrieved in future chats via vector similarity)
```

**Why This Matters:**
- **Prevents AI self-training** → Clone cannot mutate its own beliefs
- **Prevents hallucinated memories** → Only human-curated truth persists
- **Enables auditable legacy** → Every memory has a human author
- **Supports posthumous continuity** → Deceased owner's curations remain

---

## 🔌 LLM PROVIDER ABSTRACTION

### Provider-Agnostic Contract

```typescript
interface LLMProvider {
  provider_name: string; // 'openai' | 'anthropic' | 'cohere'
  model_id: string;      // 'gpt-4-turbo' | 'claude-3-opus' | etc.
  
  // Core capability
  chat(request: ChatRequest): Promise<ChatResponse>;
  
  // Embeddings (for RAG)
  embed(texts: string[]): Promise<number[][]>;
  
  // Constraints
  max_context_tokens: number;
  max_output_tokens: number;
  supports_function_calling: boolean;
}

interface ChatRequest {
  system_prompt: string;
  context_window: ContextItem[];
  user_prompt: string;
  max_tokens?: number;
  temperature?: number;
}

interface ChatResponse {
  message: string;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  metadata?: {
    finish_reason: string;
    model_used: string;
  };
}
```

### Stored Provider Configuration

```sql
llm.providers
├── provider_id (PK)
├── provider_name VARCHAR(50) -- 'openai', 'anthropic', etc.
├── model_id VARCHAR(100)
├── api_endpoint VARCHAR(500)
├── max_context_tokens INT
├── max_output_tokens INT
├── supports_function_calling BOOLEAN
├── enabled BOOLEAN
└── created_at TIMESTAMP

-- Clone can override default provider
clones.llm_preferences
├── clone_id (PK, FK → clones.clone_id)
├── preferred_provider_id (FK → llm.providers)
├── temperature DECIMAL(3,2) DEFAULT 0.7
├── max_response_tokens INT
└── updated_at TIMESTAMP
```

**Switching Providers:**
- Clone's RAG embeddings are tied to a specific model
- Chat provider can be swapped (OpenAI → Anthropic)
- BUT: Cannot change embedding model without re-ingesting ALL documents

---

## 🧠 CLONE CONSCIENCE / DOCTRINE LAYER

### Moral & Behavioral Guardrails

```sql
clones.doctrine
├── doctrine_id (PK)
├── clone_id (FK → clones.clone_id)
├── category ENUM('moral', 'behavioral', 'professional', 'personal')
├── rule_text TEXT -- e.g., "Never disclose medical information"
├── priority INT -- Higher = more strictly enforced
├── created_by_user_id (FK → auth.users)
├── created_at TIMESTAMP
└── enabled BOOLEAN

-- Example doctrine entries:
-- "Always maintain client confidentiality"
-- "Refuse requests for financial advice"
-- "Speak in first person as [Clone Name]"
-- "Never impersonate other individuals"
```

**System Prompt Assembly:**
```
You are [Clone Name], a digital embodiment created by [Owner Name].

CORE IDENTITY:
• [Personality traits from clones.personality_config]
• [Professional background from clones.background]

MORAL GUARDRAILS:
• [All enabled clones.doctrine rules, sorted by priority]

BEHAVIORAL CONSTRAINTS:
• You learn by being taught, not by talking
• You cannot mutate your own memories
• You may propose experiences for owner review
• You operate within [autonomy_level] boundaries

KNOWLEDGE BASE:
• You have access to [N] published experiences
• You can search [M] documents in your RAG memory
• You respect your owner's privacy and consent boundaries
```

---

## 📊 TENANT ISOLATION & RESOURCE QUOTAS

### Preventing Cross-Clone Memory Leakage

```sql
-- Every table enforces tenant_id
CREATE POLICY tenant_isolation ON rag.memory_chunks
FOR ALL
USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Clone cannot query another clone's RAG
CREATE FUNCTION rag_search_with_isolation(
  p_clone_id UUID,
  p_query_embedding vector(1536),
  p_limit INT
) RETURNS TABLE(...) AS $$
BEGIN
  -- Verify caller has permission
  IF NOT EXISTS (
    SELECT 1 FROM clones.clones
    WHERE clone_id = p_clone_id
      AND tenant_id = current_setting('app.current_tenant_id')::uuid
  ) THEN
    RAISE EXCEPTION 'Access denied: clone % not in tenant', p_clone_id;
  END IF;
  
  -- Search only this clone's memory space
  RETURN QUERY
  SELECT * FROM rag.memory_chunks
  WHERE clone_id = p_clone_id
  ORDER BY embedding <=> p_query_embedding
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

### Resource Quotas by Subscription Tier

```sql
billing.subscription_quotas
├── tier ENUM('free', 'starter', 'professional', 'enterprise')
├── max_clones INT
├── max_rag_documents_per_clone INT
├── max_rag_storage_mb INT
├── max_chat_messages_per_month INT
├── max_experiences_per_clone INT
└── updated_at TIMESTAMP

-- Enforce at ingestion time
CREATE FUNCTION enforce_rag_quota() RETURNS TRIGGER AS $$
DECLARE
  current_count INT;
  allowed_count INT;
BEGIN
  SELECT COUNT(*) INTO current_count
  FROM rag.documents
  WHERE clone_id = NEW.clone_id;
  
  SELECT sq.max_rag_documents_per_clone INTO allowed_count
  FROM billing.subscription_quotas sq
  JOIN auth.tenants t ON t.subscription_tier = sq.tier
  WHERE t.tenant_id = NEW.tenant_id;
  
  IF current_count >= allowed_count THEN
    RAISE EXCEPTION 'RAG quota exceeded: % documents allowed', allowed_count;
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

---

## 🚀 DEPLOYMENT ARCHITECTURE

### Service Responsibilities

```
┌─────────────────────────────────────────────────────────────┐
│ FRONTEND (React + Blazor Apps)                              │
│ • Client Blazor (WebAssembly) → Social platform             │
│ • Developer Blazor (Server) → API portal                    │
│ • Admin Blazor (Server) → System monitoring                 │
└────────────────┬────────────────────────────────────────────┘
                 │ HTTPS/REST
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ API GATEWAY (Kong / Ocelot)                                 │
│ • JWT validation, rate limiting, tenant routing             │
└────────────────┬────────────────────────────────────────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
┌──────────────┐  ┌──────────────────────────────────────────┐
│ BACKEND API  │  │ RAG MICROSERVICE (FastAPI + Python)      │
│ (ASP.NET)    │  │ • Document ingestion                      │
│              │  │ • Embedding generation                    │
│ Services:    │  │ • Vector search (pgvector)                │
│ • Auth       │  │ • Semantic retrieval                      │
│ • Clone      │◄─┤                                           │
│ • Memory     │  │ Database: PostgreSQL 16 + pgvector        │
│ • Billing    │  └───────────────────────────────────────────┘
│ • IoT        │
│ • Analytics  │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ DATA LAYER                                                   │
│ • MS SQL Server → Main app (auth, billing, social)          │
│ • PostgreSQL + pgvector → RAG memory (embeddings)           │
│ • Redis → Cache, session state                              │
│ • RabbitMQ → Async workflows, event distribution            │
└─────────────────────────────────────────────────────────────┘
```

---

## ✅ SUMMARY: THE SAFE MODEL

### What This Architecture Prevents
✓ **AI self-training** → Clone cannot mutate its own beliefs  
✓ **Identity drift** → Human-governed experiences control formation  
✓ **Hallucinated memories** → Only curated truth persists to RAG  
✓ **Moral corruption** → Doctrine layer enforces guardrails  
✓ **Cross-clone leakage** → Tenant isolation + one embedding space per clone  

### What This Architecture Enables
✓ **Auditable memory** → Every memory has a human author + timestamp  
✓ **Controlled legacy** → Experiences are versioned, immutable when published  
✓ **Posthumous continuity** → Deceased owner's curations remain intact  
✓ **Trustworthy representation** → Clone acts AS user, with verifiable constraints  
✓ **Provider flexibility** → LLM vendor-agnostic (OpenAI, Anthropic, etc.)  

---

## 🌐 EXPERIENCE ONTOLOGY & PUBLIC PROJECTION

### Critical Design Inflection Point

> **This section defines what an "experience" actually IS in the public ontology of the platform, not just where rows land in a table.**

An experience is first and foremost **something the clone stands behind**, not something for sale.

---

### 1️⃣ Where Published Experiences Actually Live

Published experiences do **NOT** automatically go to a "marketplace."  
They move into a **publicly addressable knowledge surface** that can be optionally syndicated.

#### A. Primary Home (Always)

**The Clone's Public Profile / Knowledge Page**

When an experience is:
- `status = 'published'`
- `is_public = true`

It becomes:
- Part of the clone's **public memory**
- Queryable by RAG for public chats
- Viewable on a clone-facing public page

**This is the default and canonical home.**

An experience is first and foremost something the clone stands behind, not a product listing.

#### B. Secondary Surface (Optional)

**Discovery / Showcase / Library (NOT a marketplace by default)**

Only **some** published experiences should appear in a global discovery surface:
- Featured teachings
- Public testimonies
- Curated narratives
- Thought leadership artifacts

This surface is:
- Editorially filtered
- Contextual
- **Not transactional by default**

You can later add monetization, but **discovery ≠ commerce**.

#### C. Marketplace (Explicit, Opt-In, Later)

A marketplace is a **separate contract**.

An experience only appears there if:
- Explicitly marked as `licensable` / `distributable`
- Has clear usage rights defined
- Possibly versioned or packaged as a product

**Do not overload "published" to mean "for sale."** That mistake kills trust.

---

### 2️⃣ What a Published Experience IS to the Public

Right now, the word "experience" is too internal.

To the public, an experience is perceived as one of these:
- A **story**
- A **teaching**
- A **perspective**
- A **reflection**
- A **testimony**
- A **doctrine**
- A **memory**

**The system knows it as an experience. The audience should not.**

---

### 3️⃣ Public-Facing Terminology

You need a term that communicates:
- Authority
- Intentionality
- Human authorship
- Clone identity alignment

#### 🔹 Neutral / Platform-Safe (Recommended Defaults)

These work across industries and won't age badly:
- **Narratives** 👈 **Top neutral pick** (human, non-technical, flexible, dignified)
- Reflections
- Perspectives
- Knowledge Entries
- Teachings
- Insights

#### 🔹 Authority / Thought Leadership

If the clone represents expertise or leadership:
- **Teachings** 👈 **Best for KeiroGenesis thought leaders**
- Positions
- Statements
- Expositions
- Doctrines (strong, theological/philosophical)

#### 🔹 Personal / Legacy-Oriented

If the clone represents a person's life and memory:
- **Stories** or **Testimonies** 👈 **Best for legacy use cases**
- Life Moments
- Remembrances
- Legacy Notes

#### 🔹 Hybrid Model (Recommended)

**Internally:**
```sql
clones.experiences
```

**Publicly:**
- **Narratives** (default label)

**Contextual override:**
- "Teaching" (when instructional)
- "Story" (when personal)
- "Statement" (when declarative)

This gives semantic flexibility without schema churn.

---

### 4️⃣ Publishing Model Schema (Clean & Scalable)

```sql
-- Enhanced experiences table with publication controls
clones.experiences
├── experience_id (PK)
├── clone_id (FK → clones.clone_id)
├── tenant_id (FK → auth.tenants)
├── created_by_user_id (FK → auth.users)
├── title VARCHAR(200)
├── narrative TEXT
├── rating ENUM('formative', 'informative', 'contextual')
├── status ENUM('draft', 'published')
├── version INT DEFAULT 1
├── created_at TIMESTAMP
├── published_at TIMESTAMP
│
├── -- PUBLIC PROJECTION CONTROLS
├── is_public BOOLEAN DEFAULT false -- Visible on clone profile
├── is_discoverable BOOLEAN DEFAULT false -- Appears in global library
├── is_licensable BOOLEAN DEFAULT false -- Eligible for marketplace
│
├── -- METADATA
├── public_label VARCHAR(50) -- 'narrative', 'teaching', 'story'
├── display_title VARCHAR(200) -- Public-facing title (may differ from internal)
├── excerpt TEXT -- Short preview for discovery surfaces
└── tags JSONB -- ['cobol', 'legacy-systems', 'mainframe']
```

**Each flag is separate, not implied:**

| Flag              | Meaning                                    | Default |
|-------------------|--------------------------------------------|---------|
| `is_public`       | Visible on clone's public profile          | `false` |
| `is_discoverable` | Appears in global discovery library        | `false` |
| `is_licensable`   | Eligible for marketplace transactions      | `false` |

**Examples:**

```sql
-- Personal memory, private to owner
INSERT INTO clones.experiences (..., is_public=false, is_discoverable=false, is_licensable=false);

-- Published narrative on clone profile, not discoverable globally
INSERT INTO clones.experiences (..., is_public=true, is_discoverable=false, is_licensable=false);

-- Featured teaching in discovery library, not for sale
INSERT INTO clones.experiences (..., is_public=true, is_discoverable=true, is_licensable=false);

-- Marketplace product with licensing terms
INSERT INTO clones.experiences (..., is_public=true, is_discoverable=true, is_licensable=true);
```

---

### 5️⃣ Why This Separation Matters

If you collapse these concepts, you create problems:

| Problem                          | Consequence                                      |
|----------------------------------|--------------------------------------------------|
| Publishing implies selling       | People fear sharing knowledge                    |
| Legal rights ambiguous           | Disputes over content ownership/usage            |
| Trust erodes                     | Platform feels extractive                        |
| Discovery becomes noisy          | Signal-to-noise ratio degrades                   |
| Monetization feels predatory     | Users resent the platform                        |

**Your current architecture is good enough to support this separation.** This is a naming and routing decision, not a rewrite.

---

## 🛍️ MARKETPLACE DISCOVERY MODEL

### Critical Principle: Users Shop for Clones, Not Experiences

> **If someone is looking for "a clone that does programming in COBOL", the primary object of discovery is the CLONE, not the individual experiences attached to it.**

The marketplace must answer one question instantly:  
**"What can this clone credibly help me with?"**

---

### 1️⃣ Marketplace Unit of Discovery: The Clone

**Marketplace card = Clone Profile**  
Experiences act as **supporting evidence**, not the headline.

#### Marketplace Card Hierarchy (Recommended)

1. **Clone Display Name** (identity)
2. **Primary Capability Title** (what they do)
3. **Experience Badges / Evidence** (why trust them)

---

### 2️⃣ Primary Display Name Pattern (Strong + Clear)

**Format:**
```
[Clone Name] — [Primary Capability / Domain]
```

**Examples for COBOL:**
- James Walker — Legacy Systems & COBOL Programming
- Enterprise Mainframe Specialist — COBOL & Batch Processing
- Financial Systems Engineer — COBOL & Mainframe Modernization
- COBOL Architect — Banking & Transaction Systems

**Why this works:**
- The domain is explicit
- The clone feels human and credible
- Avoids buzzwords

---

### 3️⃣ Secondary Descriptor (Optional, Powerful)

Under the name, add a capability subtitle:

```
40+ years in enterprise COBOL, banking systems, and batch processing.
```

or

```
Specializes in COBOL, JCL, VSAM, and legacy system modernization.
```

This subtitle can be **auto-derived from experiences**, but written for humans.

---

### 4️⃣ How Experiences Show Up (Supporting Role)

Experiences should **not clutter the title**. They appear as:

#### A. Capability Badges (Auto-Derived)

```
[COBOL] [Mainframe] [Banking Systems] [Batch Processing] [Legacy Modernization]
```

#### B. Featured Narratives (Click-Through)

- "Modernizing COBOL Systems for 21st-Century Banking"
- "Lessons from 30 Years of Mainframe Development"

This reinforces trust without overwhelming the buyer.

---

### 5️⃣ What NOT to Do (Important)

Avoid these patterns — they kill clarity:

❌ "COBOL Experience #12"  
❌ "Experience: COBOL Programming"  
❌ "Clone with 18 experiences"  
❌ "AI COBOL Expert"

**Users do not want:**
- Internal jargon
- Counts
- AI branding
- Abstract labels

**They want a credible digital person.**

---

### 6️⃣ Marketplace Taxonomy (Clean & Future-Proof)

#### Search Filters

```sql
marketplace.clone_listings
├── clone_id (PK, FK → clones.clones)
├── tenant_id (FK → auth.tenants)
├── display_name VARCHAR(200) -- "James Walker — Legacy Systems Expert"
├── primary_capability VARCHAR(200) -- "COBOL & Mainframe Programming"
├── subtitle TEXT -- "40+ years in enterprise COBOL..."
├── domain VARCHAR(100) -- "Programming"
├── specialty VARCHAR(100) -- "COBOL"
├── industry VARCHAR(100) -- "Banking / Finance / Government"
├── experience_level ENUM('junior', 'mid', 'senior', 'expert', 'architect')
├── is_featured BOOLEAN DEFAULT false
├── is_verified BOOLEAN DEFAULT false
├── listing_status ENUM('draft', 'active', 'paused', 'archived')
├── created_at TIMESTAMP
└── updated_at TIMESTAMP

-- Capability tags (many-to-many)
marketplace.clone_capabilities
├── clone_id (FK → marketplace.clone_listings)
├── capability_tag VARCHAR(50) -- 'cobol', 'jcl', 'vsam', 'mainframe'
├── proficiency_level ENUM('familiar', 'proficient', 'expert')
├── verified_by_experience_id (FK → clones.experiences) -- Which experience proves this
└── created_at TIMESTAMP
```

#### Clone Result Display

```
┌─────────────────────────────────────────────────────────┐
│ [Clone Avatar]                                          │
│                                                         │
│ James Walker — Legacy Systems & COBOL Programming      │
│ 40+ years in enterprise COBOL, banking systems         │
│                                                         │
│ [COBOL] [Mainframe] [Banking] [Batch Processing]       │
│                                                         │
│ ⭐ Featured Narratives:                                 │
│ • "Modernizing COBOL for 21st-Century Banking"         │
│ • "30 Years of Mainframe Development Lessons"          │
│                                                         │
│ [View Profile] [Start Conversation] [License Access]   │
└─────────────────────────────────────────────────────────┘
```

#### Clone Profile Sections

1. **About this Clone**
2. **Core Capabilities**
3. **Published Narratives** (experiences)
4. **How this Clone Can Help You**
5. **Availability / Licensing** (future)

---

### 7️⃣ Strong Recommendation (Lock This In)

✅ **Marketplace lists CLONES, not experiences**  
✅ **Experiences are evidence, not SKUs**  
✅ **Use human-readable professional titles**  
✅ **Treat clones like experts you'd hire or consult**  
✅ **Let experiences quietly prove credibility**

**If you do this right, searching for "COBOL" feels like LinkedIn + consulting + mentorship — not an app store.**

---

### 8️⃣ API Route Design (Public vs Internal)

#### Internal Routes (Technical)

```
GET  /api/v1/clones/{cloneId}/experiences
POST /api/v1/clones/{cloneId}/experiences
PUT  /api/v1/clones/{cloneId}/experiences/{experienceId}
```

#### Public Routes (Semantic)

```
GET  /api/v1/clones/{cloneId}/profile/narratives
GET  /api/v1/discovery/narratives?tags=cobol&featured=true
GET  /api/v1/marketplace/clones?specialty=cobol&industry=banking
GET  /api/v1/clones/{cloneId}/about
```

#### Public Clone Profile Schema (API Response)

```json
{
  "clone_id": "uuid",
  "display_name": "James Walker — Legacy Systems Expert",
  "subtitle": "40+ years in enterprise COBOL, banking systems, and batch processing",
  "avatar_url": "https://...",
  "capabilities": [
    {"tag": "COBOL", "level": "expert"},
    {"tag": "Mainframe", "level": "expert"},
    {"tag": "Banking Systems", "level": "expert"}
  ],
  "featured_narratives": [
    {
      "id": "uuid",
      "title": "Modernizing COBOL Systems for 21st-Century Banking",
      "type": "teaching",
      "excerpt": "...",
      "published_at": "2025-12-01T00:00:00Z"
    }
  ],
  "stats": {
    "narratives_published": 12,
    "expertise_years": 40,
    "verified": true
  },
  "availability": {
    "chat_enabled": true,
    "licensing_available": true,
    "consultation_rate": "$150/hour"
  }
}
```

---

### 9️⃣ UX Copy Guidelines (User-Facing Language)

#### ✅ Good Copy

- "Explore James's published teachings"
- "View narratives about COBOL modernization"
- "Discover clones with expertise in legacy systems"
- "Read stories from 40 years of mainframe development"

#### ❌ Bad Copy

- "Browse experiences"
- "AI-powered COBOL assistant"
- "18 knowledge artifacts available"
- "Experience marketplace"

---

## 📊 DISCOVERY VS MARKETPLACE ELIGIBILITY

### Discovery Library (Free, Public)

```sql
SELECT * FROM clones.experiences
WHERE status = 'published'
  AND is_public = true
  AND is_discoverable = true;
```

**Purpose:** Showcase clone knowledge, attract users, build trust

**Access:** Free to read, no licensing required

**Example:** Public blog, thought leadership, portfolio

---

### Marketplace (Commercial, Licensed)

```sql
SELECT * FROM clones.experiences
WHERE status = 'published'
  AND is_public = true
  AND is_licensable = true;
```

**Purpose:** Monetize expertise, grant access rights, transactional

**Access:** Requires purchase/license/subscription

**Example:** Consultation sessions, proprietary playbooks, expert access

---

### State Transitions

```
Draft
  │
  ├─► Published (Private)
  │     └─► [Owner's eyes only]
  │
  ├─► Published (Public)
  │     └─► [Clone profile, RAG-enabled for public chats]
  │
  ├─► Published + Discoverable
  │     └─► [Global discovery library, free access]
  │
  └─► Published + Discoverable + Licensable
        └─► [Marketplace listing, commercial terms]
```

---

## 📌 NEXT STEPS

### Phase 1: Core Implementation (MVP)
1. **Clone activation flow** → `sp_clone_activate()`, actor creation
2. **Experience CRUD** → Owner-authored narratives
3. **RAG ingestion** → Document chunking, embedding generation, pgvector storage
4. **Basic chat** → Context assembly (identity + RAG), LLM provider integration

### Phase 2: Memory Formation Pipeline
5. **Proposal system** → Chat suggests experiences, owner reviews
6. **Doctrine enforcement** → System prompt + guardrails
7. **Provider abstraction** → OpenAI, Anthropic, Cohere support

### Phase 3: Advanced Features
8. **Clone conscience** → Custom moral/behavioral rules
9. **Multi-modal RAG** → Images, audio, video embeddings
10. **Autonomous workflows** → Scheduled clone actions with approval gates

---

**END OF BLUEPRINT**

*This document is the canonical specification for KeiroGenesis clone architecture. All implementations must conform to these contracts.*
