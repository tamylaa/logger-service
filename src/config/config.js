/**
 * Configuration management for the Logger Service
 * Handles environment-based settings with validation
 */

export class Config {
  constructor(env) {
    this.env = env;
    this.validateEnvironment();
    this.initializeConfig();
  }

  /**
   * Validate required environment variables
   */
  validateEnvironment() {
    const required = [
      'ENVIRONMENT',
      'SERVICE_NAME',
      'LOG_LEVEL',
    ];

    const missing = required.filter(key => !this.env[key]);
    if (missing.length > 0) {
      throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
  }

  /**
   * Initialize configuration based on environment
   */
  initializeConfig() {
    this.environment = this.env.ENVIRONMENT || 'development';
    this.serviceName = this.env.SERVICE_NAME || 'logger-service';
    this.logLevel = this.env.LOG_LEVEL || 'info';
    
    // Service configuration
    this.service = {
      name: this.serviceName,
      environment: this.environment,
      version: '1.0.0',
      logLevel: this.logLevel,
    };

    // Log processing configuration
    this.logs = {
      maxSize: parseInt(this.env.MAX_LOG_SIZE) || 10485760, // 10MB default
      retentionDays: parseInt(this.env.RETENTION_DAYS) || 30,
      batchSize: parseInt(this.env.BATCH_SIZE) || 100,
      compressionEnabled: this.env.COMPRESSION_ENABLED !== 'false',
    };

    // Rate limiting configuration
    this.rateLimits = {
      perMinute: parseInt(this.env.RATE_LIMIT_PER_MINUTE) || 1000,
      perHour: parseInt(this.env.RATE_LIMIT_PER_HOUR) || 10000,
      perDay: parseInt(this.env.RATE_LIMIT_PER_DAY) || 100000,
      searchPerMinute: parseInt(this.env.SEARCH_RATE_LIMIT_PER_MINUTE) || 100,
    };

    // Security configuration
    this.security = {
      jwtSecret: this.env.JWT_SECRET || 'default-secret-change-in-production',
      apiKey: this.env.API_KEY,
      encryptionKey: this.env.ENCRYPTION_KEY,
      allowedOrigins: this.parseAllowedOrigins(),
      requireAuthentication: this.env.REQUIRE_AUTH !== 'false',
    };

    // Storage configuration
    this.storage = {
      kvTtl: parseInt(this.env.KV_TTL) || 86400, // 24 hours default
      d1BatchSize: parseInt(this.env.D1_BATCH_SIZE) || 50,
      backupEnabled: this.env.BACKUP_ENABLED === 'true',
    };

    // Monitoring configuration
    this.monitoring = {
      metricsEnabled: this.env.METRICS_ENABLED !== 'false',
      alertsEnabled: this.env.ALERTS_ENABLED !== 'false',
      webhookUrl: this.env.WEBHOOK_URL,
      slackWebhookUrl: this.env.SLACK_WEBHOOK_URL,
      emailAlerts: this.env.EMAIL_ALERTS,
    };

    // Triaging configuration
    this.triaging = {
      enableAutoTriaging: this.env.ENABLE_AUTO_TRIAGING !== 'false',
      criticalThreshold: parseInt(this.env.CRITICAL_THRESHOLD) || 10,
      warningThreshold: parseInt(this.env.WARNING_THRESHOLD) || 50,
      patternDetectionEnabled: this.env.PATTERN_DETECTION_ENABLED !== 'false',
      anomalyDetectionEnabled: this.env.ANOMALY_DETECTION_ENABLED !== 'false',
    };

    // Integration configuration
    this.integrations = {
      authServiceUrl: this.env.AUTH_SERVICE_URL,
      dataServiceUrl: this.env.DATA_SERVICE_URL,
      contentSkimmerUrl: this.env.CONTENT_SKIMMER_URL,
      timeout: parseInt(this.env.INTEGRATION_TIMEOUT) || 30000, // 30 seconds
      retries: parseInt(this.env.INTEGRATION_RETRIES) || 3,
    };

    // Analytics configuration
    this.analytics = {
      enableRealTimeAnalytics: this.env.ENABLE_REAL_TIME_ANALYTICS !== 'false',
      aggregationInterval: parseInt(this.env.AGGREGATION_INTERVAL) || 300, // 5 minutes
      trendsRetentionDays: parseInt(this.env.TRENDS_RETENTION_DAYS) || 90,
      reportingEnabled: this.env.REPORTING_ENABLED !== 'false',
    };

    // Performance configuration
    this.performance = {
      maxConcurrentRequests: parseInt(this.env.MAX_CONCURRENT_REQUESTS) || 100,
      timeoutMs: parseInt(this.env.TIMEOUT_MS) || 30000,
      cacheEnabled: this.env.CACHE_ENABLED !== 'false',
      cacheTtl: parseInt(this.env.CACHE_TTL) || 300, // 5 minutes
    };
  }

  /**
   * Parse allowed origins from environment variable
   */
  parseAllowedOrigins() {
    const origins = this.env.ALLOWED_ORIGINS;
    if (!origins) {
      // Default origins based on environment
      switch (this.environment) {
        case 'development':
          return ['http://localhost:3000', 'http://localhost:8000'];
        case 'staging':
          return ['https://staging.tamyla.com'];
        case 'production':
          return ['https://tamyla.com', 'https://wetechfounders.com'];
        default:
          return [];
      }
    }
    return origins.split(',').map(origin => origin.trim());
  }

  /**
   * Get configuration for specific feature
   */
  getFeatureConfig(feature) {
    const configs = {
      logs: this.logs,
      rateLimits: this.rateLimits,
      security: this.security,
      storage: this.storage,
      monitoring: this.monitoring,
      triaging: this.triaging,
      integrations: this.integrations,
      analytics: this.analytics,
      performance: this.performance,
    };

    return configs[feature] || {};
  }

  /**
   * Check if feature is enabled
   */
  isFeatureEnabled(feature) {
    const featureFlags = {
      authentication: this.security.requireAuthentication,
      metrics: this.monitoring.metricsEnabled,
      alerts: this.monitoring.alertsEnabled,
      autoTriaging: this.triaging.enableAutoTriaging,
      patternDetection: this.triaging.patternDetectionEnabled,
      anomalyDetection: this.triaging.anomalyDetectionEnabled,
      realTimeAnalytics: this.analytics.enableRealTimeAnalytics,
      reporting: this.analytics.reportingEnabled,
      cache: this.performance.cacheEnabled,
      backup: this.storage.backupEnabled,
    };

    return featureFlags[feature] ?? false;
  }

  /**
   * Validate configuration values
   */
  validate() {
    const errors = [];

    // Validate log configuration
    if (this.logs.maxSize <= 0) {
      errors.push('MAX_LOG_SIZE must be greater than 0');
    }

    if (this.logs.retentionDays <= 0) {
      errors.push('RETENTION_DAYS must be greater than 0');
    }

    // Validate rate limits
    if (this.rateLimits.perMinute <= 0) {
      errors.push('RATE_LIMIT_PER_MINUTE must be greater than 0');
    }

    // Validate security configuration for production
    if (this.environment === 'production') {
      if (!this.security.jwtSecret || this.security.jwtSecret === 'default-secret-change-in-production') {
        errors.push('JWT_SECRET must be set in production');
      }

      if (!this.security.encryptionKey) {
        errors.push('ENCRYPTION_KEY must be set in production');
      }

      if (!this.security.apiKey) {
        errors.push('API_KEY must be set in production');
      }
    }

    if (errors.length > 0) {
      throw new Error(`Configuration validation errors: ${errors.join(', ')}`);
    }

    return true;
  }

  /**
   * Get database name based on environment
   */
  getDatabaseName(type = 'main') {
    const prefix = `logs-${type}`;
    return `${prefix}-${this.environment}`;
  }

  /**
   * Get KV namespace name based on environment
   */
  getKVNamespace(type = 'main') {
    const prefix = `logs-kv`;
    return `${prefix}-${type}-${this.environment}`;
  }

  /**
   * Get full configuration object for debugging
   */
  toObject() {
    return {
      service: this.service,
      logs: this.logs,
      rateLimits: this.rateLimits,
      security: {
        ...this.security,
        jwtSecret: '[REDACTED]',
        apiKey: '[REDACTED]',
        encryptionKey: '[REDACTED]',
      },
      storage: this.storage,
      monitoring: this.monitoring,
      triaging: this.triaging,
      integrations: this.integrations,
      analytics: this.analytics,
      performance: this.performance,
    };
  }
}