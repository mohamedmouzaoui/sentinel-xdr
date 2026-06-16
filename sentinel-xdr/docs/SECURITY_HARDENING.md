# Sentinel XDR Pro — Security Hardening & Pen-Test Validation

## Platform Self-Security (Addresses Gap #15)

### Authentication & Session
- [x] JWT HS256 with expiring tokens (60min access, 7d refresh)
- [x] bcrypt password hashing (cost factor 12)
- [x] Token type validation (access vs refresh)
- [x] Forced re-auth on token refresh failure
- [ ] TODO: TOTP/MFA (mfa_enabled field in User model — wire up TOTP)
- [ ] TODO: Account lockout after N failed logins

### Transport Security
- [x] CORS allowlist (ALLOWED_ORIGINS env var)
- [x] Nginx security headers (X-Frame-Options, CSP, X-Content-Type-Options)
- [ ] PROD: Force HTTPS — add TLS cert to nginx or use reverse proxy
- [ ] PROD: HSTS header

### Input Validation
- [x] Pydantic models validate all API inputs
- [x] Tenant isolation on all DB queries (tenant_id filter mandatory)
- [x] Bulk import limit (500 IoCs max per call)
- [ ] TODO: Rate limiting (add slowapi: pip install slowapi)

### Secrets Management
- [x] .env file excluded from Docker image
- [x] Secret key via environment variable
- [x] API keys never logged
- [ ] PROD: Use Vault / AWS Secrets Manager instead of .env

### Pen-Test Checklist
Run these against your instance before production:

```bash
# 1. OWASP ZAP passive scan
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://localhost:8000

# 2. JWT secrets check
pip install jwt-tool
python3 jwt_tool.py <token> -T  # Try common secret bruteforce

# 3. SQLi check (sqlmap on /alerts endpoint)
sqlmap -u "http://localhost:8000/api/v1/alerts?severity=HIGH" \
  --headers="Authorization: Bearer <token>" --level=3

# 4. Dependency vulnerability scan
pip install pip-audit
pip-audit -r requirements.txt

# 5. Static analysis
pip install bandit
bandit -r backend/ -ll
```

### Rate Limiting (add to main.py)
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@router.post("/auth/login")
@limiter.limit("10/minute")  # Max 10 login attempts/min per IP
async def login(request: Request, ...):
    ...
```

### ISO 27001 Controls Covered
| Control | Implementation |
|---------|---------------|
| A.9.2.1 User registration | POST /auth/register (admin only) |
| A.9.4.2 Secure log-on | JWT + bcrypt, audit on login |
| A.9.4.4 Privileged utilities | RBAC 6-level hierarchy |
| A.12.4.1 Event logging | AuditLog table, every mutation |
| A.12.4.2 Log protection | Append-only model, no delete endpoint |
| A.12.4.3 Clock synchronisation | UTC timestamps throughout |
| A.16.1.1 Incident management | Full incident workflow + events |
| A.16.1.7 Evidence collection | PlaybookExecution steps_log |
