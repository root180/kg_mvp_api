# KeiroClone MVP Plan v2

**Version:** 2.0  
**Date:** December 15, 2025  
**Status:** Active Development

---

## 🎯 Platform Overview

| Component | Technology | Purpose |
|-----------|------------|---------|
| **KeiroClone** | React + Vite | Consumer-facing frontend (social platform) |
| **KeiroGenesis** | ASP.NET Core 8 | Backend REST API |
| **RAG Service** | Python FastAPI | Document processing + vector search |
| **Database** | PostgreSQL 16 + pgvector | Primary data store |
| **Cache** | Redis | Session + high-frequency lookups |

---

## 📦 MVP Modules (Completed Backend)

### Core Modules (9 Total)

| # | Module | Endpoints | Status |
|---|--------|-----------|--------|
| 1 | Health | 3 | ✅ Complete |
| 2 | Tenants | 9 | ✅ Complete |
| 3 | Users | 8 | ✅ Complete |
| 4 | Clones | 17 | ✅ Complete |
| 5 | Actors | 8 | ✅ Complete |
| 6 | Social | 17 | ✅ Complete |
| 7 | Messaging | 13 | ✅ Complete |
| 8 | RAG | 9 | ✅ Complete |
| 9 | Capabilities | 21 | ✅ Complete |

**Total Endpoints:** 105

---

## 🏗️ Architecture Decisions

### MVP Simplifications

| Decision | MVP Approach | Post-MVP |
|----------|--------------|----------|
| **Tenant per User** | 1:1 relationship | Multi-user tenants |
| **Email Verification** | Skipped | SendGrid integration |
| **Password Reset** | Admin/manual | Self-service email flow |
| **2FA** | Optional | Required for enterprise |
| **File Storage** | Local/basic | AWS S3/Google Cloud |

### Technical Patterns

```
Controller → Service → Repository → Stored Procedure
     ↓
Tenant from JWT claims (not URL)
     ↓
Dynamic returns (no DTOs for MVP)
```

### Route Pattern (MVP-Correct)

```
✅ api/v1/clones
✅ api/v1/clones/{cloneId}
✅ api/v1/social/posts/{postId}

❌ api/v1/tenants/{tenantId}/clones  (WRONG - tenant from JWT)
```

---

## 📅 Development Phases

### Phase 1: Foundation (Weeks 1-2) ✅ COMPLETE

- [x] PostgreSQL schemas (29 total)
- [x] Core stored procedures
- [x] JWT authentication
- [x] Multi-tenant isolation
- [x] 9 backend modules
- [x] Postman collection (105 endpoints)

### Phase 2: Frontend Core (Weeks 3-4) 🔄 IN PROGRESS

- [x] React project setup (Vite)
- [x] AuthContext + TokenManager
- [x] Login/Registration flows
- [x] Dashboard layout (5-region)
- [ ] Clone creation wizard (6 steps)
- [ ] Clone management dashboard
- [ ] Profile settings

### Phase 3: Social Features (Weeks 5-6)

- [ ] Feed component (posts, reactions, comments)
- [ ] Follow system (actors following actors)
- [ ] Messaging UI (conversations, real-time)
- [ ] Notifications center
- [ ] Search (users, clones, actors)

### Phase 4: Clone Intelligence (Weeks 7-8)

- [ ] RAG document upload
- [ ] Training materials management
- [ ] Clone personality configuration
- [ ] Autonomy settings UI
- [ ] Approval workflows

### Phase 5: Polish & Launch (Weeks 9-10)

- [ ] Mobile responsiveness
- [ ] Performance optimization
- [ ] Error handling
- [ ] Analytics dashboard
- [ ] Production deployment

---

## 🗃️ Database Schemas (29)

```
analytics    audit        auth         backup       billing
clone        config       core         documentation experiment
feedback     health       identity     integration  iot
knowledge    media        memory       moderation   monetization
notification onboarding   public       scheduling   search
security     social       training     workflow
```

### Key Tables by Schema

| Schema | Primary Tables |
|--------|---------------|
| core | tenants, users |
| auth | login_history, sessions, api_keys |
| clone | clones, personalities, expertise, autonomy_settings |
| actor | actors (unified identity for users/clones) |
| social | posts, reactions, comments, follows |
| messaging | conversations, messages, participants |
| rag | documents, chunks, embeddings |
| capability | capabilities, user_capabilities, clone_capabilities |

---

## 🔐 Authentication Flow

### Login Flow
```
1. POST /api/v1/auth/login
2. Validate credentials (bcrypt)
3. Check email verification (skipped for MVP)
4. Generate JWT (access_token + refresh_token)
5. Set HTTP-only cookie (refresh_token)
6. Return access_token in body
```

### JWT Claims
```json
{
  "sub": "user_id",
  "tenant_id": "guid",
  "email": "user@example.com",
  "role": "owner",
  "subscription_tier": "free",
  "exp": 1234567890
}
```

### Token Lifecycle
| Token | Storage | Lifetime |
|-------|---------|----------|
| Access | Memory/localStorage | 15 minutes |
| Refresh | HTTP-only cookie | 7 days |

---

## 📊 Subscription Tiers

| Tier | Clones | Storage | Price |
|------|--------|---------|-------|
| Free | 1 | 100MB | $0 |
| Starter | 3 | 1GB | $9/mo |
| Professional | 10 | 10GB | $29/mo |
| Enterprise | Unlimited | Unlimited | Custom |

---

## 🎨 Frontend Pages (React)

### Auth Domain
- `/login` - Login page
- `/register` - Registration
- `/verify-account` - Email verification (future)
- `/forgot-password` - Password reset (future)

### Dashboard Domain
- `/dashboard` - Personal home (12 dimensions)
- `/dashboard/clones` - Clone list
- `/dashboard/clones/create` - Clone wizard (6 steps)
- `/dashboard/clones/:id` - Clone details
- `/dashboard/settings` - User settings
- `/dashboard/settings/profile` - Profile editor
- `/dashboard/settings/security` - Security settings
- `/dashboard/settings/billing` - Subscription management

### Social Domain
- `/feed` - Social feed
- `/messages` - Messaging center
- `/@:handle` - Public profile (user or clone)
- `/search` - Search results

### Organization Domain (Post-MVP)
- `/org/:name/dashboard` - Org dashboard
- `/org/:name/members` - Member management
- `/org/:name/clones` - Shared clones

---

## 🚀 Deployment

### Local Development
```bash
# Backend
cd KeiroGenesis.API
dotnet run

# Frontend
cd keiroclone
npm run dev

# Database
docker-compose up -d postgres redis
```

### Production (Target)
| Service | Platform |
|---------|----------|
| Frontend | Cloudflare Pages |
| Backend API | Google Cloud Run |
| Database | Google Cloud SQL |
| Cache | Redis Cloud |
| RAG Service | Cloud Run (Python) |

---

## 📝 Deferred Features (Post-MVP)

| Feature | Reason | Target |
|---------|--------|--------|
| Email system | Requires SMTP setup | v1.1 |
| SMS verification | Requires Twilio | v1.1 |
| KeiroBit wearable | Hardware dependency | v1.2 |
| Marketplace | Needs billing complete | v1.3 |
| IoT integrations | Third-party APIs | v1.3 |
| Mobile apps | Web MVP first | v2.0 |

---

## 🔧 Tech Stack Summary

### Frontend (KeiroClone)
- React 18 + Vite
- React Router 6
- Lucide React (icons)
- TailwindCSS / Custom CSS
- Axios (HTTP client)

### Backend (KeiroGenesis)
- ASP.NET Core 8
- Dapper (data access)
- Npgsql + pgvector
- JWT Bearer authentication
- BCrypt password hashing

### Infrastructure
- PostgreSQL 16 + pgvector
- Redis 7.2
- Docker / Docker Compose
- Nginx (reverse proxy)

---

## ✅ Success Criteria (MVP)

- [ ] User can register and login
- [ ] User can create a clone (6-step wizard)
- [ ] User can train clone with documents
- [ ] User can chat with their clone
- [ ] Clone can post to social feed
- [ ] Users can follow other users/clones
- [ ] Basic messaging between actors
- [ ] Profile management working
- [ ] Responsive on mobile

---

## 📞 Contact

**Project:** KeiroClone / KeiroGenesis  
**Owner:** Dr. Matthew A. Taylor  
**Company:** KeiroLegacy Inc.

---

*Last Updated: December 15, 2025*
