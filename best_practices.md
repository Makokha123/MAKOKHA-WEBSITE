# 📘 Project Best Practices

## 1. Project Purpose
Telemedicine web application enabling patients and doctors to interact via appointments, real‑time messaging (text, files, voice), and audio/video calls. The platform includes user roles (admin/doctor/patient), authentication (email/password and Google OAuth), payments gating for communication features, and admin/user management. Backend is Flask with SQLAlchemy ORM, Flask‑Login, Flask‑Limiter, Flask‑SocketIO over Eventlet; frontend is Jinja2 templates with vanilla JS.

## 2. Project Structure
- Root
  - app.py: Monolithic Flask app containing configuration, models, routes, Socket.IO event handlers, and utilities.
  - wsgi.py: Production entry (Eventlet + Socket.IO) and DB initialization.
  - config.py: Configuration classes (Development/Production/Testing). Not yet wired into app.py.
  - requirements.txt: Python dependencies.
  - nginx.conf: Example reverse proxy + TLS and security headers.
  - security_update_check.py: Utility to check dependency updates.
  - templates/: Jinja2 HTML templates (admin, doctor, patient pages; messaging; voice/video; auth; dashboards). Uses inline CSS/JS.
  - static/: Static assets. Uploads are stored under static/uploads/* (voice_messages, message_files, voice_recordings, recordings).
  - instance/: Flask instance directory (for per‑environment files, if any).
  - backend/app/__init__.py: Present but empty (no factory pattern yet).

Recommended modularization (as the codebase grows):
- app/
  - __init__.py (application factory using config objects)
  - extensions.py (db, login_manager, mail, csrf, limiter, socketio)
  - models/ (user.py, patient.py, doctor.py, appointment.py, message.py, etc.)
  - blueprints/
    - auth/
    - admin/
    - appointments/
    - messaging/
    - payments/
  - services/ (email, payments, files, security, timezone)
  - tasks/ (async jobs if added)
  - config.py (move or keep root config.py)
  - wsgi.py
  - templates/, static/

Entry points and configuration patterns:
- Development: run Socket.IO via app.py or wsgi.py using Eventlet.
- Production: wsgi.py with eventlet monkey patch at the top; reverse‑proxy via NGINX with TLS and security headers.
- Configuration: Prefer using config.py classes via app.config.from_object(...) and env vars via python‑dotenv.

## 3. Test Strategy
Current status: No test suite present. Adopt the following strategy:
- Frameworks
  - Pytest + pytest���flask for app/test client
  - coverage/pytest‑cov for code coverage
  - freezegun for time‑sensitive tests (appointments, audit timestamps)
  - requests‑mock or responses for external calls (Google OAuth, ipapi)
  - flask‑socketio test client for Socket.IO event tests
  - factory‑boy/Faker for fixtures

- Structure and conventions
  - tests/
    - conftest.py (app factory using TestingConfig, db fixture, client, socketio client, tmp upload dir)
    - test_auth.py (signup/login, account lockout, CSRF)
    - test_admin_users.py (CRUD, RBAC)
    - test_messaging_http.py (file/voice uploads, access control)
    - test_messaging_socketio.py (join/send/typing lifecycle)
    - test_appointments.py (ACL and local timezone conversion)
    - test_security.py (rate‑limits, sanitizer, headers)

- Philosophy
  - Unit tests for utilities (sanitize_input, validators, timezone helpers)
  - Integration tests for endpoints and DB interactions
  - Event tests for Socket.IO rooms and emissions
  - Security tests for ACL checks around appointments and role‑based access
  - Target coverage ≥ 80%; focus on critical paths: auth, ACL, uploads, messaging

- Mocking
  - Mock external HTTP (Google, ipapi)
  - Use temp directories and size/type constraints for uploads
  - Simulate Redis or use in‑memory limiter in tests

## 4. Code Style
- Python
  - Use PEP8 naming: snake_case for functions/vars, PascalCase for classes
  - Prefer type hints (typing) and optional mypy for critical modules
  - Avoid global state where possible; prefer application factory + extensions pattern
  - All datetimes in DB should be timezone‑aware (UTC); convert per user’s TZ at edges
  - Use db.session.get(Model, id) over deprecated Query.get
  - Centralize config via config.py; avoid hardcoding in app.py
  - Use structured logging (JSON or consistent key=value) via app.logger
  - Handle exceptions with precise except blocks and return consistent JSON errors for APIs

- JavaScript (in templates)
  - Use const/let, strict mode, minimal global leaks
  - Escape user‑generated content before DOM insertion; rely on sanitized server content
  - Keep Socket.IO event names and payload shapes stable; encapsulate WebSocket init/handlers

- HTML/CSS
  - Reuse base.html; keep components consistent
  - Store reusable styles/scripts externally to reduce inline duplication when possible

- Security and input handling
  - Sanitize user input with bleach (server‑side) and escape client rendering
  - Validate emails/phones strictly; keep password policy (uppercase/lowercase/number/special)
  - Keep CSRF enabled everywhere except testing
  - Rate limit sensitive endpoints (signup, login, upload)

## 5. Common Patterns
- Real‑time communication
  - Flask‑SocketIO with Eventlet; monkey_patch at process start (wsgi.py) and early in app.py
  - Room naming: appointment_<id>; user personal rooms: user_<user_id>
  - Emit dual: room broadcast + receiver personal room for immediate updates

- Access control
  - Appointment‑scoped ACL checks for both patient and doctor before actions
  - Payment gating: certain actions (doctor sending voice/files) require payment_status == 'completed'

- Database and models
  - SQLAlchemy models defined centrally; relationships with cascade deletes
  - UTC timestamps; convert to user timezone at boundaries

- Utilities
  - sanitize_input with strict allowed tags
  - log_audit for security events; record remote IP and user‑agent
  - Timezone helpers: get_user_timezone via session, IP, or header fallback

- Configuration
  - PostgreSQL URL normalization (postgres:// → postgresql://) with sslmode=require in production
  - Redis‑backed rate limiting when available, memory fallback otherwise

## 6. Do's and Don'ts
- Do
  - Use config.py classes and app.config.from_object per environment
  - Keep CSRF enabled and include meta csrf-token in templates that POST
  - Restrict Socket.IO CORS origins in production to known domains
  - Validate file uploads by type and size; store under static/uploads with secure filenames
  - Use db.session.get for entity retrieval and check ACLs before returning/modifying data
  - Log audit events for security‑sensitive actions
  - Initialize Flask‑Migrate and create repeatable migrations
  - Externalize secrets (SECRET_KEY, STRIPE, GOOGLE, MAIL) via environment variables

- Don’t
  - Don’t allow cors_allowed_origins='*' in production
  - Don’t block within Eventlet green threads with long CPU or blocking I/O
  - Don’t store plaintext passwords or weak password hashes
  - Don’t trust client‑provided IDs without verifying ownership/role
  - Don’t serve uploads without validation/sanitization of filenames and content types

## 7. Tools & Dependencies
- Core
  - Flask, Jinja2, SQLAlchemy, Flask‑SQLAlchemy, Flask‑Login
  - Flask‑Limiter (Redis storage preferred), Flask‑WTF/CSRF, Flask‑Mail
  - Flask‑SocketIO + Eventlet (async), optional Redis message queue
  - bleach (XSS sanitization), bcrypt (password hashing)
  - requests (external APIs), python‑dotenv (env management)
  - Stripe (payments; ensure webhooks and secure server‑side confirmations)

- Setup
  - Python 3.10+
  - pip install -r requirements.txt
  - Create .env with at least:
    - SECRET_KEY, CSRF_SECRET_KEY
    - DATABASE_URL (Postgres in production) or default SQLite
    - GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET
    - STRIPE_PUBLIC_KEY/STRIPE_SECRET_KEY
    - EMAIL_USER/EMAIL_PASS
    - REDIS_URL (for rate limiting and optionally Socket.IO message queue)

- Running
  - Development: eventlet‑based Socket.IO
    - python wsgi.py (preferred) or python app.py if you add a dev entry
  - Production:
    - Run wsgi.py under a process manager (e.g., systemd) with Eventlet workers
    - NGINX reverse proxy with TLS and security headers (see nginx.conf)

- Database
  - Initialize Flask‑Migrate (alembic) and maintain migrations

## 8. Other Notes
- LLM/code‑gen guidelines
  - Preserve access control semantics tied to Appointment and user role
  - Maintain UTC timestamps in DB; convert at edges using helpers
  - Keep API shapes stable for frontend JS (e.g., messaging endpoints and WebSocket events)
  - Prefer adding new endpoints behind @login_required and @limiter
  - When adding uploads, enforce extension allow‑lists and MIME checks; ensure MAX_CONTENT_LENGTH
  - If introducing Blueprints/factory, adjust imports in wsgi.py and templates’ url_for endpoints
  - Restrict Socket.IO CORS and configure Redis broker in production for scale

- Hardening suggestions
  - Adopt Content Security Policy (via Flask‑Talisman) with proper nonce/hashes (minimize inline JS)
  - Replace print with structured logging; forward logs to stdout for containerized deploys
  - Use separate read/write DB users and rotate credentials
  - Enable account recovery flows and 2FA if required by policy
  - Add e2e tests for critical patient/doctor flows
