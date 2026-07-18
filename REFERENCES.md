# References

Running list of libraries, frameworks, documentation, tutorials, and AI tools used during the NovaForge hackathon.

> **Note:** Update this file whenever a new package, framework, API, tutorial, or external resource is introduced. This ensures the project documentation remains accurate and complete.

---

# AI Tools

| Tool | Purpose |
|------|---------|
| Claude Code (Anthropic) | Initial project scaffolding (repository structure, Prisma schema, Express/Vite setup) and pair programming during development. |
| ChatGPT (OpenAI) | Debugging, architecture discussions, documentation, QA planning, testing strategy, feature explanations, demo preparation, and presentation support. |

---

# Libraries & Frameworks

| Library / Framework | Purpose | Official Documentation |
|---------------------|---------|------------------------|
| Express | Backend HTTP server | https://expressjs.com |
| Prisma | ORM for database operations | https://www.prisma.io/docs |
| PostgreSQL | Relational database | https://www.postgresql.org/docs |
| @simplewebauthn/server | Server-side WebAuthn verification | https://simplewebauthn.dev |
| @simplewebauthn/browser | Browser WebAuthn implementation | https://simplewebauthn.dev |
| otplib | TOTP authentication | https://github.com/yeojz/otplib |
| socket.io | Real-time communication | https://socket.io/docs |
| socket.io-client | Frontend Socket.IO client | https://socket.io/docs |
| jsonwebtoken | JWT access & refresh tokens | https://github.com/auth0/node-jsonwebtoken |
| zod | Runtime validation | https://zod.dev |
| React | Frontend framework | https://react.dev |
| Vite | Frontend build tool | https://vitejs.dev |
| TypeScript | Type-safe JavaScript | https://www.typescriptlang.org/docs |
| Tailwind CSS | Utility-first CSS framework | https://tailwindcss.com/docs |
| React Router DOM | Client-side routing | https://reactrouter.com |

---

# Documentation & Learning Resources

| Resource | Purpose |
|----------|---------|
| SimpleWebAuthn Documentation | WebAuthn implementation and passkey authentication |
| Prisma Documentation | Database schema, migrations, and ORM usage |
| Express Documentation | API development and middleware |
| React Documentation | Frontend development |
| Tailwind CSS Documentation | Styling and responsive UI |
| Socket.IO Documentation | Real-time communication |
| PostgreSQL Documentation | Database reference |
| JWT.io | Understanding JSON Web Tokens |
| MDN Web Docs (WebAuthn API) | Browser WebAuthn concepts and APIs |

---

# Features Implemented Using These References

## Authentication

- Passwordless authentication using Passkeys (WebAuthn)
- TOTP authentication
- Recovery codes
- JWT access tokens
- Refresh tokens
- Secure session management

---

## Approval Engine

- Multi-person approval workflow
- Approval policies
- Delegation
- Escalation
- Real-time approval notifications

---

## Security

- Adaptive trust verification
- Audit logging
- Secure authentication flow
- Session validation

---

# External References

The following official documentation was consulted during development:

- Express Documentation
- Prisma Documentation
- PostgreSQL Documentation
- SimpleWebAuthn Documentation
- React Documentation
- Tailwind CSS Documentation
- Socket.IO Documentation
- TypeScript Documentation
- MDN Web Docs
- JWT.io

---

# Documentation Guidelines

Whenever a new dependency or external resource is introduced:

- Add the package or library.
- Include its purpose.
- Add the official documentation link.
- Mention where it is used in the project.

---

# Reference Changelog

| Date         | Updated By | Changes                                      |
|              |            |                                              |
| 19 July 2026 | Aryan      | Initial documentation created and organized. |