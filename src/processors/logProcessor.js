/**
 * Log Processor - Handles categorization, enrichment, and processing of log entries
 * Implements smart categorization and triaging logic
 */

import { TriagingEngine } from './triagingEngine.js';
import { PatternMatcher } from '../utils/patternMatcher.js';

export class LogProcessor {
  constructor(config) {
    this.config = config;
    this.triagingEngine = new TriagingEngine(config);
    this.patternMatcher = new PatternMatcher(config);
  }

  /**
   * Process a log entry with categorization and enrichment
   */
  async processLog(logPayload, user, context) {
    const { logger, requestId } = context;
    const startTime = Date.now();

    try {
      // Generate unique log ID
      const logId = crypto.randomUUID();
      
      // Start with the validated payload
      let processedLog = {
        id: logId,
        ...logPayload,
        processedAt: new Date().toISOString(),
        processingVersion: '1.0.0',
      };

      // Add user context
      processedLog = this.addUserContext(processedLog, user);

      // Categorize the log entry
      processedLog = await this.categorizeLog(processedLog);

      // Detect patterns and anomalies
      processedLog = await this.detectPatterns(processedLog);

      // Enrich with additional metadata
      processedLog = await this.enrichLog(processedLog, context);

      // Apply triaging rules
      processedLog = await this.applyTriaging(processedLog, context);

      // Calculate processing metrics
      const processingTime = Date.now() - startTime;
      processedLog.processingMetrics = {
        processingTime,
        processingSteps: this.getProcessingSteps(processedLog),
      };

      logger.debug('Log processed successfully', {
        logId,
        requestId,
        processingTime,
        category: processedLog.category,
        severity: processedLog.severity,
      });

      return processedLog;

    } catch (error) {
      logger.error('Log processing failed', {
        requestId,
        error: error.message,
        processingTime: Date.now() - startTime,
      });
      throw error;
    }
  }

  /**
   * Add user context to log entry
   */
  addUserContext(log, user) {
    return {
      ...log,
      userContext: {
        userId: user.id,
        userRole: user.role,
        userDomain: user.domain,
        sessionId: log.sessionId || user.sessionId,
        submittedAt: new Date().toISOString(),
      },
    };
  }

  /**
   * Categorize log entry based on multiple dimensions
   */
  async categorizeLog(log) {
    const categorization = {
      // Primary category based on content analysis
      category: this.determinePrimaryCategory(log),
      
      // Environment categorization
      environment: log.environment || this.detectEnvironment(log),
      
      // Source type categorization
      source: log.source || this.detectSource(log),
      
      // Error type categorization
      errorType: log.errorType || this.detectErrorType(log),
      
      // Component categorization
      component: log.component || this.detectComponent(log),
      
      // Endpoint categorization
      endpoint: log.endpoint || this.detectEndpoint(log),
    };

    return {
      ...log,
      ...categorization,
      categorizationConfidence: this.calculateCategorizationConfidence(categorization),
    };
  }

  /**
   * Determine primary category based on log content
   */
  determinePrimaryCategory(log) {
    const { message, severity, stackTrace, component, endpoint } = log;
    
    // Authentication/Authorization
    if (this.matchesPattern(message, ['auth', 'login', 'permission', 'unauthorized', 'forbidden'])) {
      return 'authentication';
    }
    
    // Database operations
    if (this.matchesPattern(message, ['database', 'sql', 'query', 'connection', 'transaction'])) {
      return 'database';
    }
    
    // API/Network
    if (this.matchesPattern(message, ['api', 'http', 'request', 'response', 'network', 'timeout'])) {
      return 'api';
    }
    
    // Performance
    if (this.matchesPattern(message, ['performance', 'slow', 'memory', 'cpu', 'latency'])) {
      return 'performance';
    }
    
    // Validation
    if (this.matchesPattern(message, ['validation', 'invalid', 'format', 'schema', 'required'])) {
      return 'validation';
    }
    
    // Business Logic
    if (component && this.matchesPattern(component, ['service', 'handler', 'processor', 'manager'])) {
      return 'business';
    }
    
    // Security
    if (this.matchesPattern(message, ['security', 'attack', 'malicious', 'breach', 'suspicious'])) {
      return 'security';
    }
    
    // Infrastructure
    if (this.matchesPattern(message, ['infrastructure', 'deployment', 'config', 'environment'])) {
      return 'infrastructure';
    }
    
    // User Interface
    if (this.matchesPattern(message, ['ui', 'frontend', 'render', 'component', 'view'])) {
      return 'ui';
    }
    
    // Default based on severity
    if (['error', 'fatal'].includes(severity)) {
      return 'error';
    }
    
    return 'general';
  }

  /**
   * Detect environment from log content
   */
  detectEnvironment(log) {
    const { message, endpoint, userAgent } = log;
    
    // Check for explicit environment indicators
    if (this.matchesPattern(message + ' ' + (endpoint || ''), ['localhost', 'dev', 'development'])) {
      return 'development';
    }
    
    if (this.matchesPattern(message + ' ' + (endpoint || ''), ['staging', 'test', 'qa'])) {
      return 'staging';
    }
    
    if (this.matchesPattern(message + ' ' + (endpoint || ''), ['prod', 'production', 'live'])) {
      return 'production';
    }
    
    // Default based on configuration
    return this.config.service.environment;
  }

  /**
   * Detect source type from log content
   */
  detectSource(log) {
    const { message, component, endpoint, stackTrace } = log;
    
    // Frontend/UI indicators
    if (this.matchesPattern(message, ['react', 'vue', 'angular', 'dom', 'browser', 'client'])) {
      return 'ui';
    }
    
    // Backend indicators
    if (this.matchesPattern(message, ['server', 'api', 'database', 'worker', 'service'])) {
      return 'backend';
    }
    
    // Logic/Business layer indicators
    if (component && this.matchesPattern(component, ['processor', 'handler', 'manager', 'validator'])) {
      return 'logic';
    }
    
    // External system indicators
    if (this.matchesPattern(message, ['external', 'third-party', 'webhook', 'integration'])) {
      return 'external';
    }
    
    // Analyze stack trace
    if (stackTrace) {
      if (this.matchesPattern(stackTrace, ['browser', 'dom', 'window'])) {
        return 'ui';
      }
      if (this.matchesPattern(stackTrace, ['server', 'node', 'worker'])) {
        return 'backend';
      }
    }
    
    return 'logic'; // Default
  }

  /**
   * Detect error type from log content
   */
  detectErrorType(log) {
    const { severity, message, stackTrace } = log;
    
    if (severity === 'fatal') {
      return 'exception';
    }
    
    if (severity === 'error') {
      // Check if it's an exception or regular error
      if (stackTrace || this.matchesPattern(message, ['exception', 'thrown', 'unhandled'])) {
        return 'exception';
      }
      return 'error';
    }
    
    if (severity === 'warn') {
      return 'warning';
    }
    
    return 'info';
  }

  /**
   * Detect component from log content
   */
  detectComponent(log) {
    const { message, endpoint, stackTrace } = log;
    
    // Extract component from stack trace
    if (stackTrace) {
      const componentMatch = stackTrace.match(/at\s+(\w+)/);
      if (componentMatch) {
        return componentMatch[1];
      }
    }
    
    // Extract component from endpoint
    if (endpoint) {
      const pathParts = endpoint.split('/').filter(part => part && part !== 'api');
      if (pathParts.length > 0) {
        return pathParts[0];
      }
    }
    
    // Extract component from message
    const componentPatterns = [
      /component[\s:]+(\w+)/i,
      /service[\s:]+(\w+)/i,
      /handler[\s:]+(\w+)/i,
      /(\w+)Service/,
      /(\w+)Handler/,
      /(\w+)Manager/,
    ];
    
    for (const pattern of componentPatterns) {
      const match = message.match(pattern);
      if (match) {
        return match[1];
      }
    }
    
    return 'unknown';
  }

  /**
   * Detect endpoint from log content
   */
  detectEndpoint(log) {
    const { message, endpoint } = log;
    
    if (endpoint) {
      return endpoint;
    }
    
    // Extract endpoint from message
    const endpointPatterns = [
      /(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s]+)/i,
      /endpoint[\s:]+([^\s]+)/i,
      /route[\s:]+([^\s]+)/i,
      /path[\s:]+([^\s]+)/i,
    ];
    
    for (const pattern of endpointPatterns) {
      const match = message.match(pattern);
      if (match) {
        return match[1];
      }
    }
    
    return null;
  }

  /**
   * Detect patterns and anomalies in the log
   */
  async detectPatterns(log) {
    if (!this.config.isFeatureEnabled('patternDetection')) {
      return log;
    }

    try {
      const patterns = await this.patternMatcher.detectPatterns(log);
      
      return {
        ...log,
        patterns: patterns.map(pattern => ({
          type: pattern.type,
          confidence: pattern.confidence,
          description: pattern.description,
          recommendation: pattern.recommendation,
        })),
      };
    } catch (error) {
      // Don't fail the entire processing if pattern detection fails
      return {
        ...log,
        patterns: [],
        patternDetectionError: error.message,
      };
    }
  }

  /**
   * Enrich log with additional metadata
   */
  async enrichLog(log, context) {
    const enrichment = {
      // Geographic information (if IP available)
      geographic: await this.getGeographicInfo(log.ipAddress),
      
      // Device information (if User-Agent available)
      device: this.getDeviceInfo(log.userAgent),
      
      // Context from other systems
      systemContext: await this.getSystemContext(log, context),
      
      // Performance metrics
      performanceContext: this.getPerformanceContext(log),
    };

    return {
      ...log,
      enrichment,
    };
  }

  /**
   * Apply triaging rules to determine actions
   */
  async applyTriaging(log, context) {
    if (!this.config.isFeatureEnabled('autoTriaging')) {
      return log;
    }

    try {
      const triageResult = await this.triagingEngine.triage(log, context);
      
      return {
        ...log,
        triage: triageResult.triage,
        triageActions: triageResult.actions,
        triageRecommendations: triageResult.recommendations,
      };
    } catch (error) {
      // Don't fail processing if triaging fails
      return {
        ...log,
        triageError: error.message,
      };
    }
  }

  /**
   * Helper method to match patterns in text
   */
  matchesPattern(text, patterns) {
    if (!text || typeof text !== 'string') {
      return false;
    }
    
    const lowerText = text.toLowerCase();
    return patterns.some(pattern => lowerText.includes(pattern.toLowerCase()));
  }

  /**
   * Calculate categorization confidence score
   */
  calculateCategorizationConfidence(categorization) {
    let confidence = 0;
    let factors = 0;
    
    // Each explicit categorization increases confidence
    Object.values(categorization).forEach(value => {
      if (value && value !== 'unknown' && value !== 'general') {
        confidence += 0.2;
        factors++;
      }
    });
    
    // More factors = higher confidence
    if (factors > 3) confidence += 0.1;
    if (factors > 5) confidence += 0.1;
    
    return Math.min(confidence, 1.0);
  }

  /**
   * Get geographic information from IP address
   */
  async getGeographicInfo(ipAddress) {
    if (!ipAddress) return null;
    
    // This would integrate with a GeoIP service
    // For now, return basic structure
    return {
      country: 'unknown',
      region: 'unknown',
      city: 'unknown',
    };
  }

  /**
   * Extract device information from User-Agent
   */
  getDeviceInfo(userAgent) {
    if (!userAgent) return null;
    
    return {
      browser: this.extractBrowser(userAgent),
      os: this.extractOS(userAgent),
      device: this.extractDevice(userAgent),
    };
  }

  /**
   * Get system context from other services
   */
  async getSystemContext(log, context) {
    // This would integrate with other services to get additional context
    return {
      systemLoad: 'unknown',
      activeUsers: 'unknown',
      deploymentVersion: this.config.service.version,
    };
  }

  /**
   * Extract performance context
   */
  getPerformanceContext(log) {
    return {
      hasPerformanceData: Boolean(log.duration || log.memoryUsage),
      duration: log.duration,
      memoryUsage: log.memoryUsage,
    };
  }

  /**
   * Extract browser from User-Agent
   */
  extractBrowser(userAgent) {
    const browsers = {
      'Chrome': /Chrome\/(\d+)/,
      'Firefox': /Firefox\/(\d+)/,
      'Safari': /Safari\/(\d+)/,
      'Edge': /Edg\/(\d+)/,
    };
    
    for (const [browser, pattern] of Object.entries(browsers)) {
      const match = userAgent.match(pattern);
      if (match) {
        return `${browser} ${match[1]}`;
      }
    }
    
    return 'unknown';
  }

  /**
   * Extract OS from User-Agent
   */
  extractOS(userAgent) {
    const systems = {
      'Windows': /Windows NT (\d+\.\d+)/,
      'macOS': /Mac OS X (\d+[._]\d+)/,
      'Linux': /Linux/,
      'iOS': /OS (\d+_\d+)/,
      'Android': /Android (\d+\.\d+)/,
    };
    
    for (const [os, pattern] of Object.entries(systems)) {
      const match = userAgent.match(pattern);
      if (match) {
        return match[1] ? `${os} ${match[1]}` : os;
      }
    }
    
    return 'unknown';
  }

  /**
   * Extract device type from User-Agent
   */
  extractDevice(userAgent) {
    if (/Mobile|Android|iPhone|iPad/.test(userAgent)) {
      return 'mobile';
    }
    if (/Tablet|iPad/.test(userAgent)) {
      return 'tablet';
    }
    return 'desktop';
  }

  /**
   * Get processing steps for metrics
   */
  getProcessingSteps(log) {
    const steps = ['validation', 'categorization', 'enrichment'];
    
    if (log.patterns) steps.push('pattern_detection');
    if (log.triage) steps.push('triaging');
    
    return steps;
  }
}