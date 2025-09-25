# Data Service Integration Plan

Since you have an existing **data-access service**, this document outlines how the logger service will integrate with it and what enhancements might be needed.

## Current Architecture Assumption

```
Logger Service (Cloudflare Worker) 
    ↓ Fast Cache
   KV Store (temporary/fast access)
    ↓ Persistence  
 Data-Access Service (your existing service)
    ↓
  Database (your existing DB)
```

## Integration Points

### 1. Log Storage
**Current Implementation**: Uses both KV and D1
**Proposed Change**: 
- **KV**: Fast access, temporary storage, real-time queries
- **Data Service**: Persistent storage, complex analytics, historical data

### 2. Required Data Service Endpoints

Your data-access service may need these endpoints to support the logger:

#### Core Log Operations
```
POST /api/logs/store
- Store log entries for persistence
- Bulk insert capability for performance

GET /api/logs/search
- Search logs by filters (timestamp, level, service, user, etc.)
- Support pagination and sorting

GET /api/logs/{id}  
- Retrieve specific log entry

DELETE /api/logs/cleanup
- Clean up old logs based on retention policy
```

#### Analytics Support
```
GET /api/logs/analytics/summary
- Get aggregated metrics (count by level, service, time period)

GET /api/logs/analytics/patterns
- Identify recurring log patterns
- Return pattern frequencies and trends

POST /api/logs/analytics/custom
- Custom analytics queries
- Support for complex aggregations
```

#### Pattern Recognition
```
POST /api/logs/patterns/learn
- Submit log patterns for ML/analysis
- Update pattern recognition models

GET /api/logs/patterns/similar
- Find similar log patterns
- Used for triaging and categorization
```

### 3. Data Models

#### Log Entry Structure
```json
{
  "id": "unique-log-id",
  "timestamp": 1695654321000,
  "level": "error|warn|info|debug",
  "message": "Log message",
  "service": "service-name",
  "domain": "tamyla.com",
  "user_id": "user-123",
  "session_id": "session-456", 
  "request_id": "req-789",
  "metadata": {
    "custom": "fields"
  },
  "context": {
    "url": "/api/endpoint",
    "method": "POST",
    "ip": "192.168.1.1"
  },
  "stack_trace": "error stack...",
  "category": "auth|data|api|ui",
  "priority": 1-5
}
```

#### Pattern Structure
```json
{
  "id": "pattern-id",
  "pattern": "regex or text pattern",
  "type": "error|warning|info",
  "frequency": 150,
  "first_seen": 1695654321000,
  "last_seen": 1695744321000,
  "services": ["auth-service", "api-service"],
  "severity": "low|medium|high|critical"
}
```

## Required Enhancements to Data Service

### 1. Bulk Operations Support
```javascript
// Batch insert for performance
POST /api/logs/batch
{
  "logs": [
    { /* log entry 1 */ },
    { /* log entry 2 */ },
    // ... up to 100 entries
  ]
}
```

### 2. Time-Series Queries
```javascript
// Efficient time-range queries
GET /api/logs/search?start_time=X&end_time=Y&service=Z&level=error
```

### 3. Aggregation Support  
```javascript
// Built-in analytics
GET /api/logs/aggregate?
  group_by=service,level&
  time_bucket=1h&
  start_time=X&
  end_time=Y
```

### 4. Pattern Analysis
```javascript
// ML-ready pattern extraction
POST /api/logs/analyze/patterns
{
  "time_range": "24h",
  "services": ["auth-service"],
  "min_frequency": 5
}
```

## Migration Strategy

### Phase 1: KV-Only (Current)
- Deploy logger service with KV storage only
- Implement basic logging functionality
- Use KV for all operations temporarily

### Phase 2: Hybrid Approach  
- Enhance data-access service with required endpoints
- Implement dual storage (KV + Data Service)
- KV for real-time, Data Service for persistence

### Phase 3: Full Integration
- Advanced analytics via Data Service
- Pattern recognition and ML features
- Historical data analysis and reporting

## Configuration Changes Needed

### Logger Service Config
```javascript
// In config.js
integration: {
  dataServiceUrl: process.env.DATA_SERVICE_URL,
  dataServiceApiKey: process.env.DATA_SERVICE_API_KEY,
  persistenceEnabled: true,
  bulkInsertSize: 50,
  flushInterval: 30000, // 30 seconds
}
```

### Environment Variables
```bash
# Required for data service integration
DATA_SERVICE_URL=https://your-data-service.com/api
DATA_SERVICE_API_KEY=your-api-key
DATA_SERVICE_TIMEOUT=5000
```

## Benefits of This Approach

1. **Leverage Existing Infrastructure**: Use your proven data service
2. **Separation of Concerns**: Logger focuses on collection, Data Service on storage
3. **Scalability**: Your data service already handles scale and reliability  
4. **Consistency**: Same data access patterns across all services
5. **Cost Effective**: Avoid D1 costs and complexity

## Next Steps

1. **Review** your current data-access service capabilities
2. **Identify** which endpoints need to be added/enhanced
3. **Plan** the migration from KV-only to hybrid approach
4. **Implement** required data service enhancements
5. **Deploy** logger service in KV-only mode first
6. **Gradually migrate** to full data service integration

## Questions to Consider

- Does your data service support bulk operations?
- What's the current performance for time-series queries?
- Do you have analytics/aggregation capabilities?
- What's the authentication method between services?
- How do you handle data retention and cleanup?