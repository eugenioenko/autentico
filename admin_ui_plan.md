# Admin UI Implementation Plan

## Context

Autentico is a Go OIDC server with no admin UI. This plan adds a React admin UI embedded in the Go binary, served at `/admin/`. The admin UI lets admins manage clients, users, and sessions.

## Tech Stack
React 18 + Vite, Ant Design 5, React Router v6, TanStack Query v5, Axios, TypeScript

## Deployment
Vite builds to `admin-ui/dist/` → copied to `pkg/admin/dist/` → Go `//go:embed` serves at `/admin/`

## UI guide 
Use base Ant Design theme so that it can be modified later. While implementing components, use as little as possible of custom css styles. Prioritize usage of Ant Design layout components like divider, space, etc
---

## Phase 1: Project Scaffolding

**Goal:** Vite project setup + Go embed serving a placeholder page at `/admin/`

### Frontend (`admin-ui/`)
- `package.json` with deps: react 18, antd 5, react-router-dom 6, @tanstack/react-query 5, axios
- `vite.config.ts` — `base: '/admin/'`, dev proxy `/oauth2` and `/admin/api` → `localhost:9999`
- `tsconfig.json`, `index.html`, `src/main.tsx`, `src/App.tsx` (placeholder)
- `.gitignore` — `node_modules/`, `dist/`

### Backend
- **New `pkg/admin/embed.go`** — `//go:embed all:dist` + SPA handler (serves files, falls back to `index.html`)
- **Modify `main.go`** — Add `mux.Handle("/admin/", admin.Handler())`
- **Modify `Makefile`** — Add `admin-ui-build` target (npm build + copy dist to `pkg/admin/dist/`) and `build-all` target
- **Modify `pkg/middleware/cors.go`** — Add `PUT, DELETE` to allowed methods
- **Modify `.gitignore`** — Add `admin-ui/node_modules/`, `pkg/admin/dist/`
- **Modify `dockerfile`** — Add Node.js build step before Go build

### Verification
- `make admin-ui-build && make build && ./autentico` → placeholder page at `http://localhost:9999/admin/`
- `cd admin-ui && npm run dev` → dev server at `http://localhost:5173/admin/` with API proxy

---

## Phase 2: Authentication & Layout

**Goal:** Admin login, auth context with token refresh, protected routes, Ant Design shell layout

### Files to create in `admin-ui/src/`
- **`api/client.ts`** — Axios instance + request interceptor (attach bearer token) + response interceptor (refresh on 401)
- **`api/auth.ts`** — `login(username, password)` via `POST /oauth2/token` (password grant, form-encoded), `logout()`, `refreshToken()`
- **`context/AuthContext.tsx`** — Manages tokens in localStorage, decoded JWT claims, `isAuthenticated`, login/logout methods
- **`components/ProtectedRoute.tsx`** — Redirects to `/login` if not authenticated
- **`pages/LoginPage.tsx`** — Ant Design Form with username/password, calls password grant
- **`layouts/AdminLayout.tsx`** — Ant Design Layout + Sider with Menu (Dashboard, Clients, Users, Sessions) + Header with logout
- **`types/auth.ts`** — `TokenResponse`, `JWTPayload` interfaces
- **Placeholder pages** — `DashboardPage`, `ClientsPage`, `UsersPage`, `SessionsPage`
- **Update `App.tsx`** — React Router with `BrowserRouter basename="/admin"`, nested routes under ProtectedRoute + AdminLayout

### Key details
- Password grant: `POST /oauth2/token` with `grant_type=password&username=...&password=...` (no client_id needed)
- Admin verification: rely on backend returning 403 from AdminAuthMiddleware for non-admin users
- JWT decode for display (sub, email) — no role claim in JWT, so no client-side role check

### Verification
- Login at `/admin/login` with admin credentials → redirected to dashboard shell
- Non-admin login → 403 error shown, redirected back to login
- Sidebar navigation works between placeholder pages
- Logout clears tokens and redirects to login

---

## Phase 3: Client Management (no backend changes)

**Goal:** Full CRUD for OAuth2 clients using existing `/oauth2/register` endpoints

### Files to create in `admin-ui/src/`
- **`api/clients.ts`** — `listClients()`, `getClient(id)`, `createClient(data)`, `updateClient(id, data)`, `deleteClient(id)`
- **`types/client.ts`** — `ClientCreateRequest`, `ClientUpdateRequest`, `ClientInfoResponse`, `ClientResponse`
- **`hooks/useClients.ts`** — TanStack Query hooks with mutations + cache invalidation
- **`pages/ClientsPage.tsx`** — Table (name, client_id, type, grant_types as tags, status, actions), "Create Client" button
- **`components/clients/ClientCreateForm.tsx`** — Drawer with form: client_name, redirect_uris (dynamic list), grant_types (multi-select), response_types, client_type, scopes, auth_method
- **`components/clients/ClientEditForm.tsx`** — Pre-populated edit form
- **`components/clients/ClientDetail.tsx`** — Read-only detail drawer

### Key details
- Client endpoints return data directly (NOT wrapped in `{data: T}`), unlike user endpoints
- On create success: show client_secret in modal with copy button + warning it won't be shown again
- Deactivate = `DELETE /oauth2/register/{client_id}` (soft delete)

### Verification
- List existing clients in table
- Create new client → secret shown → can copy
- Edit client name/redirect URIs → saved
- Deactivate client → status changes in table

---

## Phase 4: User Management (backend + frontend)

**Goal:** Add admin user management endpoints + build frontend CRUD

### Backend changes
- **`pkg/user/model.go`** — Add `UserUpdateRequest{Email, Role}` struct with validation; add JSON tags to `UserResponse`
- **`pkg/user/read.go`** — Add `ListUsers() ([]*User, error)` — `SELECT ... FROM users WHERE deactivated_at IS NULL`
- **`pkg/user/handler.go`** — Add `HandleListUsers`, add `HandleUserAdminEndpoint` (combined GET/POST/PUT/DELETE dispatcher); fix `HandleUpdateUser` to use `UserUpdateRequest` instead of `UserCreateRequest`
- **`pkg/user/delete.go`** — Change `DeleteUser` from hard delete to soft delete: `UPDATE users SET deactivated_at = CURRENT_TIMESTAMP`
- **`main.go`** — Add admin user routes: `mux.Handle("/admin/api/users", middleware.AdminAuthMiddleware(http.HandlerFunc(user.HandleUserAdminEndpoint)))`

### Frontend (`admin-ui/src/`)
- **`api/users.ts`** — CRUD via `/admin/api/users` (with `?id=` query param for single user ops)
- **`types/user.ts`** — `UserResponse`, `UserCreateRequest`, `UserUpdateRequest`
- **`hooks/useUsers.ts`** — TanStack Query hooks
- **`pages/UsersPage.tsx`** — Table (username, email, role as tag, created_at, actions)
- **`components/users/UserCreateForm.tsx`** — Form: username, password, email, role select
- **`components/users/UserEditForm.tsx`** — Form: email, role select

### Key details
- User responses use `SuccessResponse` wrapper: `{data: T}` — different from client endpoints
- Admin endpoint at `/admin/api/users` to avoid conflict with existing `/user` (which allows non-admin user creation)
- Soft delete sets `deactivated_at`, preserving audit trail

### Verification
- List users in table, create new user, edit role/email, deactivate user
- `go test ./pkg/user/...` passes

---

## Phase 5: Session Management (backend + frontend)

**Goal:** Session listing endpoint + frontend viewer with deactivation

### Backend changes
- **`pkg/session/model.go`** — Add `SessionResponse` struct (excludes access_token/refresh_token for security)
- **`pkg/session/read.go`** — Add `ListSessions()` and `ListSessionsByUser(userID)` functions
- **`pkg/session/admin_handler.go`** — New file: `HandleSessionAdminEndpoint` — GET lists sessions (optional `?user_id=` filter), DELETE deactivates session by `?id=`
- **`main.go`** — Add `mux.Handle("/admin/api/sessions", middleware.AdminAuthMiddleware(...))`

### Frontend (`admin-ui/src/`)
- **`api/sessions.ts`** — `listSessions(userId?)`, `deactivateSession(id)`
- **`types/session.ts`** — `SessionResponse`
- **`hooks/useSessions.ts`** — TanStack Query hooks
- **`pages/SessionsPage.tsx`** — Table (session ID truncated, user, IP, user agent, created, expires, status badge, actions), filter by user/status
- **`components/sessions/SessionDetail.tsx`** — Detail drawer

### Key details
- Session responses must NOT include access_token or refresh_token (security)
- `last_activity_at` and `device_id` may be NULL — scan into pointer types
- Status derived: active (not deactivated, not expired), expired, deactivated

### Verification
- View sessions, filter by user ID, deactivate a session, verify status updates
- `go test ./pkg/session/...` passes

---

## Phase 6: Dashboard

**Goal:** Overview page with system stats

### Backend changes
- **New `pkg/admin/stats.go`** — `HandleStats` handler: counts users, active clients, active/total sessions, recent logins (24h) via SQL COUNT queries
- **`main.go`** — Add `mux.Handle("/admin/api/stats", middleware.AdminAuthMiddleware(...))`

### Frontend (`admin-ui/src/`)
- **`api/stats.ts`** — `getStats()`
- **`hooks/useStats.ts`** — TanStack Query hook with 30s refetchInterval
- **`pages/DashboardPage.tsx`** — Ant Design Statistic cards (Total Users, Active Clients, Active Sessions, Recent Logins), quick action buttons (Create User, Create Client)

### Verification
- Dashboard shows correct counts
- Auto-refreshes every 30s
- Quick action buttons navigate to respective create forms

---

## Summary of backend files modified across all phases

| File | Phases | Changes |
|------|--------|---------|
| `main.go` | 1, 4, 5, 6 | Admin SPA handler, user/session/stats admin routes |
| `Makefile` | 1 | Frontend build targets |
| `dockerfile` | 1 | Add Node.js build step |
| `.gitignore` | 1 | Ignore node_modules and build artifacts |
| `pkg/admin/embed.go` | 1 | New: Go embed + SPA handler |
| `pkg/admin/stats.go` | 6 | New: Dashboard stats endpoint |
| `pkg/middleware/cors.go` | 1 | Add PUT, DELETE methods |
| `pkg/user/model.go` | 4 | Add UserUpdateRequest, JSON tags on UserResponse |
| `pkg/user/read.go` | 4 | Add ListUsers |
| `pkg/user/handler.go` | 4 | Add HandleListUsers, HandleUserAdminEndpoint, fix HandleUpdateUser |
| `pkg/user/delete.go` | 4 | Change to soft delete |
| `pkg/session/model.go` | 5 | Add SessionResponse |
| `pkg/session/read.go` | 5 | Add ListSessions, ListSessionsByUser |
| `pkg/session/admin_handler.go` | 5 | New: Admin session endpoints |
