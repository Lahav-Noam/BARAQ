# Security Best Practices Guide

This guide covers security hardening recommendations for BARAQ deployments.

## Authentication

### Strong Passwords

- Enforce minimum 8 characters with uppercase, lowercase, and digits
- Use unique passwords for each account
- Change the generated admin password immediately on first login (read it
  from `first_run_credentials.txt`; the file is deleted after the change)

### Multi-Factor Authentication (MFA)

Enable TOTP-based 2FA for all admin accounts:

1. Navigate to Settings > Security > Two-Factor Authentication
2. Scan the QR code with an authenticator app
3. Enter the verification code to confirm

### API Key Management

- Rotate API keys regularly (quarterly recommended)
- Use separate keys for development and production
- Store keys in the DPAPI vault (Windows) or environment variables
- Never commit keys to version control

## Network Security

### TLS/HTTPS

TLS is **required** in production (`BARAQ_ENV=production` refuses to start
without it). Enable and point it at your certificate:

```env
BARAQ_TLS=1
BARAQ_TLS_CERT=/path/to/cert.pem
BARAQ_TLS_KEY=/path/to/key.pem
```

The launcher serves real HTTPS from these paths and **exits with an error if
they are missing or unreadable** — the configuration can no longer claim
encryption that the listener is not providing. Verify the scheme in the startup
log (`BARAQ backend starting on https://...`).

Agents connect over HTTPS and pin this certificate (`-TlsCert`); see
`docs/agent-deployment.md`. Set `BARAQ_CORS_ORIGINS` to the real console
origin — production rejects `localhost` in that list.

### CORS Configuration

Restrict CORS origins to your actual domain(s):

```env
BARAQ_CORS_ORIGINS=https://your-domain.com
```

**Never use localhost in production CORS configuration.**

### IP Allowlisting

Restrict API access to known IP ranges:

```env
BARAQ_API_IP_WHITELIST=10.0.0.0/8,172.16.0.0/12
```

### Rate Limiting

Configure API rate limits to prevent abuse:

```env
BARAQ_API_RATE_LIMIT=600    # requests per minute
BARAQ_API_RATE_BURST=900    # burst allowance
```

## Database Security

### Connection Security

- Use TLS for database connections in production
- Use dedicated database credentials with minimal privileges
- Rotate database passwords regularly

### Backup Security

- Encrypt database backups
- Store backups in a separate, secure location
- Test backup restoration regularly

## Secrets Management

### DPAPI Vault

BARAQ uses Windows DPAPI for encrypted secret storage:

- Secrets are encrypted at rest in `secrets.dat`
- Only the same user account can decrypt secrets
- Back up `secrets.dat` when migrating installations

### Environment Variables

For non-Windows deployments, use environment variables:

```env
BARAQ_ADMIN_PASSWORD=your-strong-password
BARAQ_API_KEYS={"your-key": "admin"}
BARAQ_TOKEN_SECRET=your-random-hex-string
```

## Audit and Monitoring

### Audit Trail

BARAQ maintains a tamper-evident audit log:

- All authentication events are logged
- Administrative actions are recorded
- Export audit logs to your SIEM regularly

### Monitoring

Monitor these health endpoints:

- `GET /api/health` - Overall system health
- `GET /api/system/collectors/health` - Collector status
- `GET /api/system/notifications/health` - Alert delivery status

## Deployment Hardening

### Production Configuration

Set `BARAQ_ENV=production` to enable security gates:

```env
BARAQ_ENV=production
BARAQ_AUTH_ENABLED=1
BARAQ_CSRF_ENABLED=1
BARAQ_SECURITY_HEADERS=1
```

### Docker/Kubernetes

- Run containers as non-root user
- Use read-only filesystem where possible
- Limit container resources (CPU, memory)
- Use network policies to restrict inter-pod communication

## Incident Response

### Credential Compromise

1. Immediately rotate all API keys
2. Force password reset for affected accounts
3. Review audit logs for unauthorized access
4. Check for data exfiltration indicators

### System Compromise

1. Isolate the affected system
2. Preserve forensic evidence
3. Review detection alerts for IOCs
4. Follow your incident response playbook

## Regular Maintenance

### Weekly

- Review alert trends and false positive rates
- Check system health endpoints
- Verify backup integrity

### Monthly

- Review user accounts and permissions
- Update Sigma rules (`scripts/sigma_pull.py`)
- Check for BARAQ updates

### Quarterly

- Rotate API keys and database passwords
- Review and update detection rules
- Conduct security audit of configuration
