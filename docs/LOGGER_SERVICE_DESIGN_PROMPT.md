# Logger Service Development Prompts

## Design Phase Prompt

**Prompt Title:** Comprehensive Logger Service Architecture Design

**Objective:** Design a scalable, secure, and intelligent logging service for Cloudflare that can categorize logs by multiple dimensions, perform smart triaging, and provide proactive insights while ensuring seamless integration with existing Tamyla services.

**Multi-Impact Considerations:**

1. **Security Impact:**
   - How will you ensure log data privacy and compliance (GDPR, HIPAA)?
   - What authentication mechanisms will prevent unauthorized log submission?
   - How will you handle sensitive data in logs (PII, tokens, credentials)?
   - What encryption strategies will protect data at rest and in transit?

2. **Scalability Impact:**
   - How will the service handle variable log volumes across different customer domains?
   - What storage strategy will support both real-time queries and historical analysis?
   - How will you implement efficient categorization without performance degradation?
   - What caching mechanisms will optimize frequent operations?

3. **Integration Impact:**
   - How will the service integrate with existing auth-service, data-service, and content-skimmer?
   - What APIs will be exposed for log submission and retrieval?
   - How will you ensure consistent data formats across services?
   - What webhook mechanisms will enable cross-service communication?

4. **Intelligence Impact:**
   - How will you implement severity-based triaging and automated responses?
   - What algorithms will categorize logs by environment, source, component, and endpoint?
   - How will you detect patterns and anomalies in log data?
   - What proactive suggestions can be generated from accumulated logs?

5. **Operational Impact:**
   - How will you monitor the logger service's own health and performance?
   - What alerting mechanisms will notify administrators of issues?
   - How will you handle log retention and cleanup?
   - What disaster recovery strategies will ensure data availability?

**Deliverables:**
- Complete architecture diagram with data flows
- API specification for all endpoints
- Database/storage schema design
- Security and compliance documentation
- Performance and scalability benchmarks
- Integration specifications with existing services

**Constraints:**
- Must use Cloudflare Workers for edge computing benefits
- Should reuse existing patterns from Tamyla services
- Must support multi-tenant isolation per customer domain
- Should minimize cold start latency for log ingestion

---

## Design Phase Todo List

1. **Architecture Design**
   - Create system architecture diagram showing all components and data flows
   - Define service boundaries and responsibilities
   - Design multi-tenant isolation strategy per customer domain

2. **API Design**
   - Define REST API endpoints for log ingestion, retrieval, and management
   - Design webhook interfaces for alerts and cross-service communication
   - Create OpenAPI specification for all endpoints

3. **Data Model Design**
   - Design log data schema with all categorization fields
   - Define storage strategy (KV, D1, external) with retention policies
   - Create indexing strategy for efficient querying

4. **Security Design**
   - Implement authentication and authorization mechanisms
   - Design encryption strategy for sensitive log data
   - Create access control policies for different user roles

5. **Integration Design**
   - Map integration points with auth-service, data-service, content-skimmer
   - Design data format standardization across services
   - Plan migration strategy for existing logging

6. **Intelligence Design**
   - Design categorization algorithms for environment, source, component, endpoint
   - Create triaging rules engine for severity-based actions
   - Plan anomaly detection and pattern recognition features

7. **Monitoring Design**
   - Design health check endpoints and metrics collection
   - Create alerting and notification system
   - Plan logging service's own observability

8. **Performance Design**
   - Define performance benchmarks and SLAs
   - Design caching and optimization strategies
   - Plan scalability testing scenarios