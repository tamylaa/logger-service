# Cloudflare Workers Setup Guide

This guide covers all the steps needed to properly deploy the Logger Service as a Cloudflare Worker.

## Prerequisites

1. **Cloudflare Account**: Create a free account at [cloudflare.com](https://cloudflare.com)
2. **Node.js**: Ensure Node.js 18+ is installed
3. **Wrangler CLI**: We'll use `npx wrangler` (no global installation needed)

## Step 1: Cloudflare Authentication

First, authenticate with Cloudflare:

```bash
npx wrangler login
```

This will open a browser window for you to authorize Wrangler with your Cloudflare account.

Verify authentication:
```bash
npx wrangler whoami
```

## Step 2: Create Required Resources

### KV Namespaces (for fast log access and caching)

Create KV namespaces for each environment:

```bash
# Development
npx wrangler kv:namespace create "LOGS_KV"
npx wrangler kv:namespace create "LOGS_KV" --preview

# Staging  
npx wrangler kv:namespace create "LOGS_KV" --env staging
npx wrangler kv:namespace create "LOGS_KV" --env staging --preview

# Production
npx wrangler kv:namespace create "LOGS_KV" --env production
npx wrangler kv:namespace create "LOGS_KV" --env production --preview
```

> **Note**: We're using your existing **data-access service** for persistent storage and complex queries instead of D1. The KV store will handle fast access and temporary log storage.

## Step 3: Update wrangler.toml

After creating KV namespaces, update `wrangler.toml` with the actual IDs returned from the commands above:

```toml
# Replace the placeholder IDs with actual ones from the creation commands
[[kv_namespaces]]
binding = "LOGS_KV"
id = "YOUR_ACTUAL_KV_ID_HERE"
preview_id = "YOUR_ACTUAL_PREVIEW_ID_HERE"
```

Repeat for staging and production environments with their respective IDs.

## Step 4: Data Service Integration

Since you have an existing **data-access service**, we'll integrate with it instead of using D1:

### Required Configuration
- Ensure your `DATA_SERVICE_URL` points to your data-access service
- The logger service will use KV for fast access and your data service for persistence
- No database schema setup needed (handled by your data service)

## Step 5: Configure Secrets

Set up required secrets for each environment:

### Development Secrets
```bash
npx wrangler secret put JWT_SECRET
# Enter a strong secret when prompted (e.g., generated with: openssl rand -base64 32)

npx wrangler secret put API_KEY  
# Enter your API key when prompted

# Optional service URLs (if you have them)
npx wrangler secret put AUTH_SERVICE_URL
npx wrangler secret put DATA_SERVICE_URL
npx wrangler secret put CONTENT_SKIMMER_URL
npx wrangler secret put WEBHOOK_URL
npx wrangler secret put SLACK_WEBHOOK_URL
```

### Staging Secrets
```bash
npx wrangler secret put JWT_SECRET --env staging
npx wrangler secret put API_KEY --env staging
# ... repeat for other secrets
```

### Production Secrets
```bash
npx wrangler secret put JWT_SECRET --env production
npx wrangler secret put API_KEY --env production
# ... repeat for other secrets
```

## Step 6: Environment Variables

The following environment variables are configured in `wrangler.toml` and can be adjusted:

### Required Variables (already configured)
- `ENVIRONMENT`: deployment environment (development/staging/production)
- `LOG_LEVEL`: logging level (debug/info/warn/error)
- `SERVICE_NAME`: name of the service
- `MAX_LOG_SIZE`: maximum size for individual logs (default: 10MB)
- `RATE_LIMIT_PER_MINUTE`: API rate limiting (default: 1000/5000/10000)
- `RETENTION_DAYS`: log retention period (default: 30/90/365 days)

### Optional Variables (set as secrets if needed)
- `AUTH_SERVICE_URL`: URL for authentication service
- `DATA_SERVICE_URL`: URL for data service  
- `CONTENT_SKIMMER_URL`: URL for content skimmer service
- `WEBHOOK_URL`: General webhook endpoint
- `SLACK_WEBHOOK_URL`: Slack notifications webhook

## Step 7: Deploy the Worker

Deploy to different environments:

```bash
# Development (default)
npx wrangler deploy

# Staging
npx wrangler deploy --env staging

# Production  
npx wrangler deploy --env production
```

## Step 8: Verify Deployment

Test the deployed worker:

```bash
# Health check
curl https://logger-service.YOUR_SUBDOMAIN.workers.dev/health

# With staging
curl https://logger-service-staging.YOUR_SUBDOMAIN.workers.dev/health

# With production
curl https://logger-service-production.YOUR_SUBDOMAIN.workers.dev/health
```

## Security Considerations

1. **JWT Secret**: Must be a cryptographically secure random string (minimum 32 characters)
   ```bash
   # Generate secure secret
   openssl rand -base64 32
   ```

2. **API Keys**: Should be unique per environment and rotated regularly

3. **Service URLs**: Use HTTPS endpoints only

4. **Rate Limiting**: Adjust `RATE_LIMIT_PER_MINUTE` based on expected traffic

## Troubleshooting

### Common Issues

1. **Authentication Error**: Run `npx wrangler login` again
2. **Resource Not Found**: Check that KV/D1 IDs in `wrangler.toml` match created resources
3. **Database Error**: Ensure schema.sql was executed successfully
4. **Secret Missing**: Verify all required secrets are set with `npx wrangler secret list`

### Debug Commands

```bash
# List KV namespaces
npx wrangler kv:namespace list

# List D1 databases  
npx wrangler d1 list

# List secrets
npx wrangler secret list

# View logs
npx wrangler tail

# Test locally
npx wrangler dev
```

## Production Checklist

Before going live:

- [ ] JWT_SECRET set to cryptographically secure value
- [ ] API_KEY configured and documented
- [ ] All service URLs configured (if applicable)
- [ ] Database schema applied
- [ ] Rate limits configured appropriately
- [ ] Log retention period set
- [ ] Health endpoints returning 200
- [ ] Authentication working
- [ ] CORS configured for your domains
- [ ] Monitoring configured (optional: Slack webhooks)

## Next Steps

1. Configure your application to send logs to the deployed worker endpoints
2. Set up monitoring and alerting  
3. Configure log rotation and archival policies
4. Set up backup strategies for D1 databases
5. Monitor performance and adjust rate limits as needed