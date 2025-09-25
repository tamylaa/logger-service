/**
 * Integration Layer - Connects logger service with existing services
 * Provides API clients and communication protocols for cross-service integration
 */

import { Logger } from '../utils/logger.js';
import { ErrorHandler } from '../utils/errorHandler.js';

/**
 * Base API client for service communication
 */
export class BaseApiClient {
  constructor(baseUrl, config, logger) {
    this.baseUrl = baseUrl;
    this.config = config;
    this.logger = logger;
    this.timeout = config.integration?.timeout || 10000; // 10 seconds
    this.retryAttempts = config.integration?.retryAttempts || 3;
    this.retryDelay = config.integration?.retryDelay || 1000; // 1 second
  }

  /**
   * Make authenticated API request
   */
  async makeRequest(endpoint, options = {}) {
    const {
      method = 'GET',
      headers = {},
      body = null,
      timeout = this.timeout,
      retries = this.retryAttempts,
    } = options;

    const url = `${this.baseUrl}${endpoint}`;
    
    // Add authentication headers
    const authHeaders = await this.getAuthHeaders();
    const requestHeaders = {
      'Content-Type': 'application/json',
      'User-Agent': 'Logger-Service/1.0',
      ...authHeaders,
      ...headers,
    };

    const requestOptions = {
      method,
      headers: requestHeaders,
      body: body ? JSON.stringify(body) : null,
    };

    // Add timeout using AbortController
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      let lastError;
      
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          this.logger.debug('Making API request', {
            url,
            method,
            attempt: attempt + 1,
            maxAttempts: retries + 1,
          });

          const response = await fetch(url, {
            ...requestOptions,
            signal: controller.signal,
          });

          clearTimeout(timeoutId);

          if (!response.ok) {
            const errorData = await this.parseErrorResponse(response);
            throw ErrorHandler.createError(
              'API_ERROR',
              `API request failed: ${response.status} ${response.statusText}`,
              response.status,
              { url, errorData }
            );
          }

          const data = await response.json();
          
          this.logger.debug('API request successful', {
            url,
            status: response.status,
            attempt: attempt + 1,
          });

          return {
            data,
            status: response.status,
            headers: Object.fromEntries(response.headers.entries()),
          };

        } catch (error) {
          lastError = error;
          
          // Don't retry on certain errors
          if (error.status === 401 || error.status === 403 || error.status === 404) {
            throw error;
          }

          // Don't retry on abort (timeout)
          if (error.name === 'AbortError') {
            throw ErrorHandler.createError(
              'TIMEOUT_ERROR',
              'API request timeout',
              408,
              { url, timeout }
            );
          }

          // Wait before retry
          if (attempt < retries) {
            const delay = this.retryDelay * Math.pow(2, attempt); // Exponential backoff
            this.logger.warn('API request failed, retrying', {
              url,
              attempt: attempt + 1,
              error: error.message,
              retryIn: delay,
            });
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      }

      // All retries exhausted
      throw lastError || ErrorHandler.createError(
        'MAX_RETRIES_EXCEEDED',
        'Maximum retry attempts exceeded',
        500,
        { url, attempts: retries + 1 }
      );

    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Parse error response
   */
  async parseErrorResponse(response) {
    try {
      return await response.json();
    } catch {
      return { message: response.statusText || 'Unknown error' };
    }
  }

  /**
   * Get authentication headers (to be implemented by subclasses)
   */
  async getAuthHeaders() {
    return {};
  }

  /**
   * Health check
   */
  async healthCheck() {
    try {
      const response = await this.makeRequest('/health', {
        method: 'GET',
        timeout: 5000,
        retries: 1,
      });
      
      return {
        healthy: true,
        status: response.status,
        data: response.data,
      };
    } catch (error) {
      return {
        healthy: false,
        error: error.message,
        status: error.status || 0,
      };
    }
  }
}

/**
 * Auth Service Client
 */
export class AuthServiceClient extends BaseApiClient {
  constructor(config, logger) {
    super(config.services?.authService?.url || 'http://localhost:3001', config, logger);
    this.apiKey = config.services?.authService?.apiKey;
    this.serviceName = 'auth-service';
  }

  async getAuthHeaders() {
    return this.apiKey ? { 'X-API-Key': this.apiKey } : {};
  }

  /**
   * Validate user token
   */
  async validateToken(token) {
    try {
      const response = await this.makeRequest('/api/auth/validate', {
        method: 'POST',
        body: { token },
      });

      return {
        valid: true,
        user: response.data.user,
        permissions: response.data.permissions,
      };
    } catch (error) {
      this.logger.warn('Token validation failed', { error: error.message });
      return {
        valid: false,
        error: error.message,
      };
    }
  }

  /**
   * Get user permissions
   */
  async getUserPermissions(userId) {
    try {
      const response = await this.makeRequest(`/api/users/${userId}/permissions`);
      return {
        success: true,
        permissions: response.data.permissions,
      };
    } catch (error) {
      this.logger.error('Failed to get user permissions', { userId, error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Create service token
   */
  async createServiceToken(scope = 'logger-service') {
    try {
      const response = await this.makeRequest('/api/auth/service-token', {
        method: 'POST',
        body: { scope, service: 'logger-service' },
      });

      return {
        success: true,
        token: response.data.token,
        expiresAt: response.data.expiresAt,
      };
    } catch (error) {
      this.logger.error('Failed to create service token', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Refresh token
   */
  async refreshToken(refreshToken) {
    try {
      const response = await this.makeRequest('/api/auth/refresh', {
        method: 'POST',
        body: { refreshToken },
      });

      return {
        success: true,
        accessToken: response.data.accessToken,
        refreshToken: response.data.refreshToken,
        expiresAt: response.data.expiresAt,
      };
    } catch (error) {
      this.logger.error('Token refresh failed', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Data Service Client
 */
export class DataServiceClient extends BaseApiClient {
  constructor(config, logger) {
    super(config.services?.dataService?.url || 'http://localhost:3002', config, logger);
    this.apiKey = config.services?.dataService?.apiKey;
    this.serviceName = 'data-service';
  }

  async getAuthHeaders() {
    return this.apiKey ? { 'Authorization': `Bearer ${this.apiKey}` } : {};
  }

  /**
   * Store processed log data
   */
  async storeLogData(logData) {
    try {
      const response = await this.makeRequest('/api/logs/store', {
        method: 'POST',
        body: {
          type: 'log_entry',
          data: logData,
          timestamp: new Date().toISOString(),
          source: 'logger-service',
        },
      });

      return {
        success: true,
        id: response.data.id,
        stored: true,
      };
    } catch (error) {
      this.logger.error('Failed to store log data', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Query historical data
   */
  async queryLogs(query) {
    try {
      const response = await this.makeRequest('/api/logs/query', {
        method: 'POST',
        body: query,
      });

      return {
        success: true,
        results: response.data.results,
        total: response.data.total,
        hasMore: response.data.hasMore,
      };
    } catch (error) {
      this.logger.error('Log query failed', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get aggregated statistics
   */
  async getStatistics(timeframe = '24h', metrics = ['count', 'severity']) {
    try {
      const response = await this.makeRequest('/api/analytics/statistics', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
        },
      });

      return {
        success: true,
        statistics: response.data,
      };
    } catch (error) {
      this.logger.error('Failed to get statistics', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Backup log data
   */
  async backupLogs(criteria) {
    try {
      const response = await this.makeRequest('/api/logs/backup', {
        method: 'POST',
        body: criteria,
      });

      return {
        success: true,
        backupId: response.data.backupId,
        status: response.data.status,
      };
    } catch (error) {
      this.logger.error('Log backup failed', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Content Skimmer Client
 */
export class ContentSkimmerClient extends BaseApiClient {
  constructor(config, logger) {
    super(config.services?.contentSkimmer?.url || 'http://localhost:3003', config, logger);
    this.apiKey = config.services?.contentSkimmer?.apiKey;
    this.serviceName = 'content-skimmer';
  }

  async getAuthHeaders() {
    return this.apiKey ? { 'X-Service-Key': this.apiKey } : {};
  }

  /**
   * Analyze log content for patterns
   */
  async analyzeContent(content, context = {}) {
    try {
      const response = await this.makeRequest('/api/analyze/text', {
        method: 'POST',
        body: {
          content,
          context: {
            source: 'logger-service',
            type: 'log_content',
            ...context,
          },
          analysis: ['sentiment', 'entities', 'categories', 'security'],
        },
      });

      return {
        success: true,
        analysis: response.data.analysis,
        confidence: response.data.confidence,
        categories: response.data.categories,
      };
    } catch (error) {
      this.logger.error('Content analysis failed', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Extract entities from log messages
   */
  async extractEntities(text) {
    try {
      const response = await this.makeRequest('/api/extract/entities', {
        method: 'POST',
        body: { text, source: 'log_message' },
      });

      return {
        success: true,
        entities: response.data.entities,
        confidence: response.data.confidence,
      };
    } catch (error) {
      this.logger.error('Entity extraction failed', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Detect sensitive information
   */
  async detectSensitiveInfo(content) {
    try {
      const response = await this.makeRequest('/api/security/scan', {
        method: 'POST',
        body: {
          content,
          checks: ['pii', 'credentials', 'keys', 'tokens'],
        },
      });

      return {
        success: true,
        findings: response.data.findings,
        riskLevel: response.data.riskLevel,
        recommendations: response.data.recommendations,
      };
    } catch (error) {
      this.logger.error('Sensitive info detection failed', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Categorize log content
   */
  async categorizeContent(content, existingCategory = null) {
    try {
      const response = await this.makeRequest('/api/categorize', {
        method: 'POST',
        body: {
          content,
          existingCategory,
          domain: 'system_logs',
        },
      });

      return {
        success: true,
        category: response.data.category,
        confidence: response.data.confidence,
        alternatives: response.data.alternatives,
      };
    } catch (error) {
      this.logger.error('Content categorization failed', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

/**
 * Integration Manager - Orchestrates service interactions
 */
export class IntegrationManager {
  constructor(config) {
    this.config = config;
    this.logger = new Logger('IntegrationManager');
    
    // Initialize service clients
    this.authService = new AuthServiceClient(config, this.logger);
    this.dataService = new DataServiceClient(config, this.logger);
    this.contentSkimmer = new ContentSkimmerClient(config, this.logger);
    
    // Track service health
    this.serviceHealth = new Map();
    this.healthCheckInterval = config.integration?.healthCheckInterval || 60000; // 1 minute
    
    // Start health monitoring
    this.startHealthMonitoring();
  }

  /**
   * Process log with integrations
   */
  async processLogWithIntegrations(log) {
    const results = {
      original: log,
      enriched: { ...log },
      integrationResults: {},
      errors: [],
    };

    try {
      // Validate authentication if user context exists
      if (log.userId || log.userToken) {
        const authResult = await this.validateUserAuth(log);
        results.integrationResults.auth = authResult;
        
        if (authResult.valid) {
          results.enriched.userInfo = authResult.user;
          results.enriched.permissions = authResult.permissions;
        }
      }

      // Analyze content for additional insights
      if (log.message && this.config.features?.contentAnalysis) {
        const contentResult = await this.analyzeLogContent(log);
        results.integrationResults.content = contentResult;
        
        if (contentResult.success) {
          results.enriched.contentAnalysis = contentResult.analysis;
          results.enriched.extractedEntities = contentResult.entities;
          results.enriched.sensitiveInfo = contentResult.sensitiveInfo;
        }
      }

      // Store in data service for long-term analytics
      if (this.config.features?.dataServiceIntegration) {
        const storeResult = await this.storeLogData(results.enriched);
        results.integrationResults.storage = storeResult;
      }

      this.logger.debug('Log processed with integrations', {
        logId: log.id,
        integrations: Object.keys(results.integrationResults),
      });

    } catch (error) {
      this.logger.error('Integration processing failed', {
        logId: log.id,
        error: error.message,
      });
      results.errors.push({
        service: 'integration',
        error: error.message,
        timestamp: new Date().toISOString(),
      });
    }

    return results;
  }

  /**
   * Validate user authentication
   */
  async validateUserAuth(log) {
    try {
      if (log.userToken) {
        const result = await this.authService.validateToken(log.userToken);
        if (result.valid && log.userId && result.user?.id !== log.userId) {
          return {
            valid: false,
            error: 'Token user ID mismatch',
          };
        }
        return result;
      } else if (log.userId) {
        const permissions = await this.authService.getUserPermissions(log.userId);
        return {
          valid: permissions.success,
          user: { id: log.userId },
          permissions: permissions.permissions,
          error: permissions.error,
        };
      }

      return { valid: true, user: null };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  /**
   * Analyze log content
   */
  async analyzeLogContent(log) {
    const results = {
      success: false,
      analysis: null,
      entities: null,
      sensitiveInfo: null,
    };

    try {
      // Content analysis
      const analysisResult = await this.contentSkimmer.analyzeContent(
        log.message,
        {
          component: log.component,
          severity: log.severity,
          timestamp: log.timestamp,
        }
      );

      if (analysisResult.success) {
        results.analysis = analysisResult.analysis;
        results.success = true;
      }

      // Entity extraction
      const entityResult = await this.contentSkimmer.extractEntities(log.message);
      if (entityResult.success) {
        results.entities = entityResult.entities;
      }

      // Sensitive information detection
      const sensitiveResult = await this.contentSkimmer.detectSensitiveInfo(log.message);
      if (sensitiveResult.success) {
        results.sensitiveInfo = sensitiveResult;
      }

    } catch (error) {
      results.error = error.message;
    }

    return results;
  }

  /**
   * Store log data in data service
   */
  async storeLogData(log) {
    try {
      return await this.dataService.storeLogData({
        ...log,
        integrationTimestamp: new Date().toISOString(),
        source: 'logger-service',
      });
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get service health status
   */
  getServiceHealth() {
    const health = {};
    for (const [service, status] of this.serviceHealth.entries()) {
      health[service] = {
        ...status,
        lastChecked: status.lastChecked?.toISOString(),
      };
    }
    return health;
  }

  /**
   * Start health monitoring
   */
  startHealthMonitoring() {
    // Initial health check
    this.performHealthChecks();
    
    // Schedule periodic health checks
    setInterval(() => {
      this.performHealthChecks();
    }, this.healthCheckInterval);
  }

  /**
   * Perform health checks on all services
   */
  async performHealthChecks() {
    const services = [
      { name: 'auth-service', client: this.authService },
      { name: 'data-service', client: this.dataService },
      { name: 'content-skimmer', client: this.contentSkimmer },
    ];

    for (const service of services) {
      try {
        const health = await service.client.healthCheck();
        this.serviceHealth.set(service.name, {
          ...health,
          lastChecked: new Date(),
          service: service.name,
        });
      } catch (error) {
        this.serviceHealth.set(service.name, {
          healthy: false,
          error: error.message,
          lastChecked: new Date(),
          service: service.name,
        });
      }
    }

    this.logger.debug('Health checks completed', {
      services: Array.from(this.serviceHealth.keys()),
      healthyCount: Array.from(this.serviceHealth.values()).filter(s => s.healthy).length,
    });
  }

  /**
   * Get integration statistics
   */
  getIntegrationStats() {
    const stats = {
      servicesConfigured: 0,
      servicesHealthy: 0,
      lastHealthCheck: null,
      integrationFeatures: {},
    };

    // Count configured services
    if (this.config.services?.authService?.url) stats.servicesConfigured++;
    if (this.config.services?.dataService?.url) stats.servicesConfigured++;
    if (this.config.services?.contentSkimmer?.url) stats.servicesConfigured++;

    // Count healthy services
    let lastCheck = null;
    for (const [name, health] of this.serviceHealth.entries()) {
      if (health.healthy) stats.servicesHealthy++;
      if (!lastCheck || health.lastChecked > lastCheck) {
        lastCheck = health.lastChecked;
      }
    }
    stats.lastHealthCheck = lastCheck?.toISOString();

    // Integration features
    stats.integrationFeatures = {
      authentication: this.config.features?.authentication || false,
      contentAnalysis: this.config.features?.contentAnalysis || false,
      dataServiceIntegration: this.config.features?.dataServiceIntegration || false,
      crossServiceLogging: this.config.features?.crossServiceLogging || false,
    };

    return stats;
  }

  /**
   * Shutdown integrations
   */
  async shutdown() {
    this.logger.info('Shutting down integration manager');
    
    // Clear health check interval
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    // Could perform cleanup tasks here
    this.serviceHealth.clear();
  }
}

/**
 * Integration utilities
 */
export class IntegrationUtils {
  /**
   * Create API client with common configuration
   */
  static createApiClient(serviceName, config, logger) {
    switch (serviceName) {
      case 'auth-service':
        return new AuthServiceClient(config, logger);
      case 'data-service':
        return new DataServiceClient(config, logger);
      case 'content-skimmer':
        return new ContentSkimmerClient(config, logger);
      default:
        throw new Error(`Unknown service: ${serviceName}`);
    }
  }

  /**
   * Validate service configuration
   */
  static validateServiceConfig(config) {
    const errors = [];
    const warnings = [];

    // Check auth service config
    if (config.features?.authentication) {
      if (!config.services?.authService?.url) {
        errors.push('Auth service URL required when authentication is enabled');
      }
      if (!config.services?.authService?.apiKey) {
        warnings.push('Auth service API key not configured');
      }
    }

    // Check data service config
    if (config.features?.dataServiceIntegration) {
      if (!config.services?.dataService?.url) {
        errors.push('Data service URL required when data integration is enabled');
      }
    }

    // Check content skimmer config
    if (config.features?.contentAnalysis) {
      if (!config.services?.contentSkimmer?.url) {
        errors.push('Content skimmer URL required when content analysis is enabled');
      }
    }

    return { errors, warnings, valid: errors.length === 0 };
  }

  /**
   * Generate service health report
   */
  static generateHealthReport(serviceHealth) {
    const report = {
      summary: {
        total: serviceHealth.size,
        healthy: 0,
        unhealthy: 0,
        unknown: 0,
      },
      services: {},
      recommendations: [],
    };

    for (const [name, health] of serviceHealth.entries()) {
      report.services[name] = {
        status: health.healthy ? 'healthy' : 'unhealthy',
        lastChecked: health.lastChecked?.toISOString(),
        error: health.error,
      };

      if (health.healthy) {
        report.summary.healthy++;
      } else {
        report.summary.unhealthy++;
        report.recommendations.push(`Check ${name} service configuration and connectivity`);
      }
    }

    if (report.summary.unhealthy > 0) {
      report.recommendations.push('Consider implementing circuit breaker pattern for failing services');
    }

    return report;
  }
}