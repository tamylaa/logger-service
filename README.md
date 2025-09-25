# Logger Service

A sophisticated, production-ready logging service built on Cloudflare Workers with smart categorization, intelligent triaging, and comprehensive analytics.

## 🚀 Features

### Core Functionality
- **Smart Log Processing**: Intelligent categorization, enrichment, and pattern detection
- **Multi-tenant Architecture**: User-specific log isolation with permissions
- **Real-time Analytics**: Comprehensive insights, trends, and business intelligence
- **Smart Triaging**: Automated actions based on severity and patterns
- **Cross-service Integration**: Seamless connectivity with existing services

### Advanced Capabilities
- **Pattern Recognition**: AI-powered anomaly detection and security analysis
- **Rate Limiting**: Advanced protection against abuse with sliding windows
- **Authentication**: JWT and API key support with role-based access
- **Webhooks**: Event-driven integrations for real-time notifications
- **Health Monitoring**: Comprehensive system diagnostics and uptime tracking
- **Multi-tenant Architecture**: Domain-specific isolation (logger.tamyla.com, logger.wetechfounders.com)
- **Self-healing System**: Automated recovery, resource scaling, and proactive maintenance
- **Proactive Insights**: ML-inspired analytics for predictive issue detection

### Storage & Performance
- **Dual Storage**: KV for fast access, D1 for complex queries
- **Intelligent Caching**: Multi-layer caching for optimal performance
- **Search & Filtering**: Advanced query capabilities with full-text search
- **Data Retention**: Configurable policies for compliance and cost optimization

## 📋 Prerequisites

- Node.js 18+ 
- Cloudflare account with Workers enabled
- D1 database access
- KV namespace access
- Wrangler CLI installed (`npm install -g wrangler`)

## 🛠 Installation

1. **Clone and install dependencies**
   ```bash
   git clone <repository-url>
   cd logger-service
   npm install
   ```

2. **Configure Cloudflare resources**
   ```bash
   # Login to Cloudflare
   wrangler login

   # Create KV namespace
   wrangler kv:namespace create "LOGS_KV" --preview false
   wrangler kv:namespace create "LOGS_KV" --preview true

   # Create D1 database
   wrangler d1 create logger-db
   ```

3. **Update wrangler.toml with your resource IDs**
   ```toml
   [[kv_namespaces]]
   binding = "LOGS_KV"
   id = "your-kv-namespace-id"
   preview_id = "your-preview-kv-namespace-id"

   [[d1_databases]]
   binding = "LOGS_DB"
   database_name = "logger-db"
   database_id = "your-d1-database-id"
   ```

4. **Initialize D1 database schema**
   ```bash
   wrangler d1 execute logger-db --file=./migrations/schema.sql
   ```

5. **Set environment variables**
   ```bash
   # Set JWT secret for authentication
   wrangler secret put JWT_SECRET

   # Set API keys for service integrations (optional)
   wrangler secret put AUTH_SERVICE_API_KEY
   wrangler secret put DATA_SERVICE_API_KEY
   wrangler secret put CONTENT_SKIMMER_API_KEY
   ```

## 🚀 Deployment

### Development
```bash
npm run dev
# or
wrangler dev
```

### Production
```bash
npm run deploy
# or
wrangler deploy
```

### Testing
```bash
npm test
npm run test:coverage
```

## 🔧 Configuration

The service is configured via environment variables and the `wrangler.toml` file:

### Environment Variables
```bash
# Core Configuration
LOG_LEVEL=info                    # Logging level: debug, info, warn, error
ENVIRONMENT=production           # Environment: development, staging, production

# Authentication
JWT_SECRET=your-secret-key       # JWT signing secret
API_KEY_HEADER=X-API-Key        # API key header name

# Rate Limiting
RATE_LIMIT_ENABLED=true         # Enable rate limiting
RATE_LIMIT_REQUESTS=100         # Requests per window
RATE_LIMIT_WINDOW=3600          # Window in seconds

# Feature Flags
ENABLE_ANALYTICS=true           # Enable analytics endpoints
ENABLE_INTEGRATIONS=true        # Enable service integrations
ENABLE_WEBHOOKS=true           # Enable webhook system
ENABLE_CONTENT_ANALYSIS=true   # Enable content analysis

# Service Integration URLs
AUTH_SERVICE_URL=https://auth.example.com
DATA_SERVICE_URL=https://data.example.com
CONTENT_SKIMMER_URL=https://content.example.com
```

### Configuration Files
- `wrangler.toml` - Cloudflare Workers configuration
- `package.json` - Dependencies and scripts
- `src/config/config.js` - Application configuration logic

## 📚 API Documentation

### Authentication
All endpoints require authentication via JWT token or API key:

```bash
# JWT Authentication
curl -H "Authorization: Bearer <jwt_token>" https://logger-service.example.com/logs

# API Key Authentication  
curl -H "X-API-Key: <api_key>" https://logger-service.example.com/logs
```

### Core Endpoints

#### Submit Log
```bash
POST /logs
Content-Type: application/json

{
  "message": "User login successful",
  "level": "info",
  "component": "auth-service",
  "endpoint": "/api/login",
  "userId": "user123",
  "metadata": {
    "ip": "192.168.1.1",
    "userAgent": "Mozilla/5.0..."
  }
}
```

#### Retrieve Logs
```bash
GET /logs?startTime=2024-01-01T00:00:00Z&endTime=2024-01-02T00:00:00Z&limit=100
```

#### Search Logs
```bash
POST /logs/search
Content-Type: application/json

{
  "query": "error AND payment",
  "filters": {
    "severity": ["error", "critical"],
    "component": ["payment-service"],
    "timeRange": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-02T00:00:00Z"
    }
  },
  "limit": 50
}
```

### Analytics Endpoints

#### Get Analytics Summary
```bash
GET /analytics/summary?timeframe=24h&groupBy=severity&includePatterns=true
```

#### Get Pattern Analysis
```bash
GET /analytics/patterns?timeframe=7d&category=security&severity=high
```

#### Get Trend Analysis
```bash
GET /analytics/trends?timeframe=7d&interval=hour&metrics=count,severity,performance
```

#### Get Proactive Insights
```bash
GET /analytics/insights?timeframe=24h
```

### Domain Management Endpoints

#### Register Domain
```bash
POST /admin/domains
Content-Type: application/json

{
  "domain": "example.com",
  "tenantId": "example-tenant",
  "plan": "standard",
  "contactEmail": "admin@example.com",
  "config": {
    "retentionDays": 30,
    "maxLogsPerDay": 100000,
    "enableAnalytics": true
  }
}
```

#### List Domains
```bash
GET /admin/domains
```

### Self-healing Endpoints

#### Get Self-healing Status
```bash
GET /admin/self-healing
```

#### Execute Healing Action
```bash
POST /admin/self-healing/actions
Content-Type: application/json

{
  "action": "execute",
  "actionId": "restart-service",
  "reason": "Manual intervention"
}
```

### Integration Endpoints

#### Register Service
```bash
POST /integration/services
Content-Type: application/json

{
  "serviceName": "my-service",
  "serviceUrl": "https://my-service.example.com",
  "apiKey": "service-api-key",
  "version": "1.0.0",
  "capabilities": ["logging", "health-check"],
  "healthEndpoint": "/health"
}
```

#### Cross-service Logging
```bash
POST /integration/cross-service
Content-Type: application/json

{
  "sourceService": "auth-service",
  "targetService": "user-service",
  "operation": "user_data_sync",
  "data": {
    "userId": "user123",
    "action": "profile_update"
  },
  "correlationId": "req-456"
}
```

#### Register Webhook
```bash
POST /integration/webhooks
Content-Type: application/json

{
  "webhookId": "alert-webhook-1",
  "url": "https://alerts.example.com/webhook",
  "events": ["critical_error", "security_incident"],
  "secret": "webhook-secret",
  "active": true
}
```

### Health & Monitoring

#### Health Check
```bash
GET /health
```

#### Integration Health
```bash
GET /integration/health
```

#### System Metrics
```bash
GET /metrics
```

## 🏗 Architecture

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Sources   │───▶│  Logger Service │───▶│   Integrations  │
│                 │    │                 │    │                 │
│ • Applications  │    │ • Validation    │    │ • Auth Service  │
│ • Services      │    │ • Processing    │    │ • Data Service  │
│ • Systems       │    │ • Categorization│    │ • Content Skimmer│
└─────────────────┘    │ • Triaging      │    └─────────────────┘
                       │ • Analytics     │
                       └─────────────────┘
                                │
                       ┌─────────────────┐
                       │     Storage     │
                       │                 │
                       │ • KV (Fast)     │
                       │ • D1 (Complex)  │
                       └─────────────────┘
```

### Data Flow

1. **Ingestion**: Logs received via REST API with authentication and rate limiting
2. **Validation**: Schema validation and sanitization
3. **Processing**: Smart categorization, enrichment, and pattern detection
4. **Triaging**: Automated actions based on severity and rules
5. **Storage**: Dual-layer storage with KV and D1 databases
6. **Analytics**: Real-time analysis, trends, and business intelligence
7. **Integration**: Cross-service communication and webhooks

### Key Classes

- **Router**: HTTP request routing and middleware
- **LogHandler**: Core log processing logic
- **LogProcessor**: Smart categorization and enrichment
- **TriagingEngine**: Automated decision making and actions
- **PatternMatcher**: AI-powered pattern recognition
- **AnalyticsHandler**: Business intelligence and reporting
- **IntegrationManager**: Cross-service coordination
- **LogStorage**: Dual-storage management

## 🔍 Monitoring & Observability

### Built-in Monitoring
- **Health Checks**: Comprehensive system diagnostics
- **Performance Metrics**: Request latency, throughput, error rates
- **Storage Monitoring**: KV and D1 health and usage
- **Integration Health**: Service connectivity and response times

### Metrics Available
- Request volume and success rates
- Log processing performance
- Pattern detection accuracy
- Storage utilization
- Integration service health
- User activity patterns

### Alerting
- Critical error thresholds
- Service availability issues  
- Performance degradation
- Security incidents
- Storage capacity warnings

## 🔐 Security Features

### Authentication & Authorization
- JWT token validation
- API key authentication
- Role-based access control (RBAC)
- Multi-tenant isolation

### Data Protection
- Input validation and sanitization
- Sensitive data detection and redaction
- Encryption at rest and in transit
- Access logging and audit trails

### Security Monitoring
- Attack pattern detection
- Anomaly identification
- Suspicious activity alerts
- Security incident classification

## 🚨 Troubleshooting

### Common Issues

**Authentication Failures**
```bash
# Check JWT secret configuration
wrangler secret list

# Verify token format
curl -H "Authorization: Bearer <token>" https://logger-service.example.com/health
```

**Rate Limiting Issues**
```bash
# Check rate limit configuration
# Increase limits in wrangler.toml if needed
```

**Storage Problems**
```bash
# Check KV namespace binding
wrangler kv:namespace list

# Verify D1 database
wrangler d1 list
```

**Integration Failures**
```bash
# Check service health
curl https://logger-service.example.com/integration/health

# Verify service registration
curl https://logger-service.example.com/integration/services
```

### Debug Mode
```bash
# Enable debug logging
wrangler secret put LOG_LEVEL debug

# View logs
wrangler tail
```

### Performance Optimization
- Enable caching for analytics queries
- Optimize KV key structure for access patterns
- Use appropriate D1 indexes
- Configure rate limits based on usage

## 📈 Scaling & Performance

### Horizontal Scaling
- Cloudflare Workers automatically scale
- Multiple regions for global distribution
- Load balancing across worker instances

### Performance Optimizations
- Intelligent caching strategies
- Optimized database queries
- Efficient data structures
- Lazy loading for analytics

### Cost Optimization
- Configurable data retention policies
- Automatic cleanup of old logs
- Efficient storage utilization
- Usage-based scaling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow ESLint configuration
- Write comprehensive tests
- Update documentation
- Ensure backward compatibility

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Wiki](./docs/)
- **Issues**: [GitHub Issues](./issues)
- **Discussions**: [GitHub Discussions](./discussions)

## 🗺 Roadmap

### Upcoming Features
- Machine learning for anomaly detection (enhanced pattern recognition implemented)
- Advanced visualization dashboards
- Real-time streaming analytics
- Enhanced security scanning
- Multi-cloud deployment support
- Advanced self-healing with cloud provider integration
- Custom ML models for domain-specific pattern detection

### Version History
- **v1.0.0**: Initial release with core logging functionality
- **v1.1.0**: Added analytics and pattern recognition
- **v1.2.0**: Integration layer and cross-service support
- **v1.3.0** (planned): ML-powered insights and predictions

---

Built with ❤️ using Cloudflare Workers, designed for scale and reliability.