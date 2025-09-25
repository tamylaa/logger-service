# Environment Configuration Template

This file shows all the environment variables and secrets needed for the Logger Service.

## Required Secrets (set with `npx wrangler secret put`)

### Critical Security Secrets
```bash
# JWT signing secret (REQUIRED)
npx wrangler secret put JWT_SECRET
# Generate with: openssl rand -base64 32

# API key for service authentication (REQUIRED)  
npx wrangler secret put API_KEY
# Generate a strong API key for your applications to use
```

### Service Integration URLs (REQUIRED for full functionality)
```bash
# Your existing data-access service URL
npx wrangler secret put DATA_SERVICE_URL
# Example: https://data-service.tamyla.com/api

# Your authentication service URL  
npx wrangler secret put AUTH_SERVICE_URL
# Example: https://auth-service.tamyla.com/api

# Content skimmer service URL
npx wrangler secret put CONTENT_SKIMMER_URL
# Example: https://content-skimmer.tamyla.com/api
```

### Optional Notification Webhooks
```bash
# General webhook for alerts
npx wrangler secret put WEBHOOK_URL
# Example: https://your-app.com/webhooks/logger-alerts

# Slack webhook for notifications
npx wrangler secret put SLACK_WEBHOOK_URL  
# Example: https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

### Service-to-Service Authentication
```bash
# API key for data service communication
npx wrangler secret put DATA_SERVICE_API_KEY
# The API key your data service expects

# API key for auth service communication  
npx wrangler secret put AUTH_SERVICE_API_KEY
# The API key your auth service expects
```

## Environment Variables (configured in wrangler.toml)

These are already configured but can be adjusted:

### Development Environment
```toml
ENVIRONMENT = "development"
LOG_LEVEL = "debug"
SERVICE_NAME = "logger-service"
MAX_LOG_SIZE = "10485760"  # 10MB
RATE_LIMIT_PER_MINUTE = "1000"
RETENTION_DAYS = "30"
```

### Staging Environment  
```toml
ENVIRONMENT = "staging"
LOG_LEVEL = "info"
SERVICE_NAME = "logger-service-staging"
MAX_LOG_SIZE = "10485760"  # 10MB
RATE_LIMIT_PER_MINUTE = "5000"
RETENTION_DAYS = "90"
```

### Production Environment
```toml
ENVIRONMENT = "production"  
LOG_LEVEL = "info"
SERVICE_NAME = "logger-service-production"
MAX_LOG_SIZE = "10485760"  # 10MB
RATE_LIMIT_PER_MINUTE = "10000"
RETENTION_DAYS = "365"
```

## Setup Scripts

### Development Setup
```bash
#!/bin/bash
echo "Setting up development environment..."

# Generate secure secrets
JWT_SECRET=$(openssl rand -base64 32)
API_KEY=$(openssl rand -hex 16)

# Set secrets
echo $JWT_SECRET | npx wrangler secret put JWT_SECRET
echo $API_KEY | npx wrangler secret put API_KEY

# Set service URLs (update with your actual URLs)
echo "https://data-service-dev.tamyla.com/api" | npx wrangler secret put DATA_SERVICE_URL
echo "https://auth-service-dev.tamyla.com/api" | npx wrangler secret put AUTH_SERVICE_URL

# Set API keys for service communication (update with actual keys)
echo "your-data-service-dev-api-key" | npx wrangler secret put DATA_SERVICE_API_KEY
echo "your-auth-service-dev-api-key" | npx wrangler secret put AUTH_SERVICE_API_KEY

echo "Development environment configured!"
echo "Your API key is: $API_KEY"
echo "Save this for your client applications."
```

### Production Setup
```bash  
#!/bin/bash
echo "Setting up production environment..."

# Generate secure secrets
JWT_SECRET=$(openssl rand -base64 32)
API_KEY=$(openssl rand -hex 20)  # Longer for production

# Set secrets for production
echo $JWT_SECRET | npx wrangler secret put JWT_SECRET --env production
echo $API_KEY | npx wrangler secret put API_KEY --env production

# Set service URLs for production
echo "https://data-service.tamyla.com/api" | npx wrangler secret put DATA_SERVICE_URL --env production
echo "https://auth-service.tamyla.com/api" | npx wrangler secret put AUTH_SERVICE_URL --env production

# Set production API keys
echo "your-production-data-service-api-key" | npx wrangler secret put DATA_SERVICE_API_KEY --env production
echo "your-production-auth-service-api-key" | npx wrangler secret put AUTH_SERVICE_API_KEY --env production

echo "Production environment configured!"
echo "Your production API key is: $API_KEY"
echo "Store this securely and share with authorized applications only."
```

## Validation Commands

### Check Configuration
```bash
# List all secrets
npx wrangler secret list

# List secrets for specific environment
npx wrangler secret list --env production

# Test configuration
npx wrangler dev

# Deploy and test
npx wrangler deploy
curl https://logger-service.YOUR_SUBDOMAIN.workers.dev/health
```

### Verify KV Namespace
```bash  
# List KV namespaces
npx wrangler kv:namespace list

# Test KV access (after deployment)
npx wrangler kv:key put test-key "test-value" --binding LOGS_KV
npx wrangler kv:key get test-key --binding LOGS_KV
npx wrangler kv:key delete test-key --binding LOGS_KV
```

## Security Checklist

- [ ] JWT_SECRET is cryptographically secure (32+ characters)
- [ ] API_KEY is strong and unique per environment  
- [ ] Service URLs use HTTPS only
- [ ] API keys for service communication are environment-specific
- [ ] Secrets are not logged or exposed in code
- [ ] Rate limits are appropriate for expected traffic
- [ ] Webhook URLs are validated and secured

## Troubleshooting

### Common Issues
1. **"JWT_SECRET missing"**: Run secret setup script
2. **"Cannot connect to data service"**: Verify DATA_SERVICE_URL and API key
3. **"KV namespace not found"**: Update wrangler.toml with actual KV IDs  
4. **"Rate limit exceeded"**: Adjust RATE_LIMIT_PER_MINUTE in wrangler.toml

### Debug Commands
```bash
# Check worker logs
npx wrangler tail

# Test locally with secrets
npx wrangler dev --local

# Verify deployment
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://logger-service.YOUR_SUBDOMAIN.workers.dev/health
```