/**
 * Pattern Matcher - Detects patterns and anomalies in log data
 * Implements pattern recognition algorithms for intelligent log analysis
 */

export class PatternMatcher {
  constructor(config) {
    this.config = config;
    this.patterns = this.initializePatterns();
  }

  /**
   * Initialize pattern recognition rules
   */
  initializePatterns() {
    return {
      // Security patterns
      security: [
        {
          name: 'brute_force_attempt',
          type: 'security',
          patterns: [/failed.{0,20}login/i, /authentication.{0,20}failed/i, /invalid.{0,20}credentials/i],
          severity: 'high',
          confidence: 0.8,
          description: 'Potential brute force attack detected',
          recommendation: 'Monitor for repeated failed login attempts and consider implementing account lockout',
        },
        {
          name: 'sql_injection',
          type: 'security',
          patterns: [/union.{0,20}select/i, /drop.{0,20}table/i, /insert.{0,20}into/i, /'.*or.*1.*=.*1/i],
          severity: 'critical',
          confidence: 0.9,
          description: 'SQL injection attempt detected',
          recommendation: 'Implement parameterized queries and input validation',
        },
        {
          name: 'xss_attempt',
          type: 'security',
          patterns: [/<script[^>]*>/i, /javascript:/i, /onload=/i, /onerror=/i],
          severity: 'high',
          confidence: 0.7,
          description: 'Cross-site scripting (XSS) attempt detected',
          recommendation: 'Implement proper input sanitization and content security policy',
        },
      ],

      // Performance patterns
      performance: [
        {
          name: 'slow_query',
          type: 'performance',
          patterns: [/slow.{0,20}query/i, /timeout/i, /performance/i],
          durationThreshold: 5000, // 5 seconds
          severity: 'medium',
          confidence: 0.6,
          description: 'Slow database query detected',
          recommendation: 'Optimize database queries and consider adding indexes',
        },
        {
          name: 'memory_leak',
          type: 'performance',
          patterns: [/out.{0,20}of.{0,20}memory/i, /memory.{0,20}leak/i, /heap.{0,20}overflow/i],
          severity: 'high',
          confidence: 0.8,
          description: 'Potential memory leak detected',
          recommendation: 'Review memory allocation and implement proper cleanup',
        },
        {
          name: 'high_cpu_usage',
          type: 'performance',
          patterns: [/cpu.{0,20}usage/i, /high.{0,20}load/i, /performance.{0,20}degradation/i],
          severity: 'medium',
          confidence: 0.6,
          description: 'High CPU usage detected',
          recommendation: 'Monitor system resources and optimize intensive operations',
        },
      ],

      // Error patterns
      error: [
        {
          name: 'connection_failure',
          type: 'error',
          patterns: [/connection.{0,20}refused/i, /connection.{0,20}timeout/i, /network.{0,20}error/i],
          severity: 'high',
          confidence: 0.8,
          description: 'Network connection failure detected',
          recommendation: 'Check network connectivity and service availability',
        },
        {
          name: 'service_unavailable',
          type: 'error',
          patterns: [/service.{0,20}unavailable/i, /503/i, /502/i, /504/i],
          severity: 'high',
          confidence: 0.9,
          description: 'Service availability issue detected',
          recommendation: 'Check service health and consider implementing circuit breakers',
        },
        {
          name: 'disk_space_issue',
          type: 'error',
          patterns: [/disk.{0,20}full/i, /no.{0,20}space/i, /storage.{0,20}full/i],
          severity: 'critical',
          confidence: 0.9,
          description: 'Disk space issue detected',
          recommendation: 'Free up disk space or increase storage capacity',
        },
      ],

      // Business patterns
      business: [
        {
          name: 'payment_failure',
          type: 'business',
          patterns: [/payment.{0,20}failed/i, /transaction.{0,20}declined/i, /card.{0,20}declined/i],
          severity: 'high',
          confidence: 0.8,
          description: 'Payment processing failure detected',
          recommendation: 'Review payment gateway integration and error handling',
        },
        {
          name: 'user_registration',
          type: 'business',
          patterns: [/user.{0,20}registered/i, /signup.{0,20}completed/i, /account.{0,20}created/i],
          severity: 'info',
          confidence: 0.7,
          description: 'User registration event detected',
          recommendation: 'Track registration metrics for business analytics',
        },
        {
          name: 'data_export',
          type: 'business',
          patterns: [/export.{0,20}completed/i, /data.{0,20}downloaded/i, /backup.{0,20}created/i],
          severity: 'info',
          confidence: 0.6,
          description: 'Data export operation detected',
          recommendation: 'Monitor data export patterns for compliance and security',
        },
      ],

      // API patterns
      api: [
        {
          name: 'rate_limit_exceeded',
          type: 'api',
          patterns: [/rate.{0,20}limit/i, /429/i, /too.{0,20}many.{0,20}requests/i],
          severity: 'medium',
          confidence: 0.8,
          description: 'API rate limit exceeded',
          recommendation: 'Implement proper rate limiting and client-side backoff',
        },
        {
          name: 'authentication_error',
          type: 'api',
          patterns: [/401/i, /unauthorized/i, /invalid.{0,20}token/i, /authentication.{0,20}failed/i],
          severity: 'medium',
          confidence: 0.7,
          description: 'API authentication error detected',
          recommendation: 'Check API credentials and token expiration handling',
        },
        {
          name: 'validation_error',
          type: 'api',
          patterns: [/validation.{0,20}error/i, /400/i, /bad.{0,20}request/i, /invalid.{0,20}input/i],
          severity: 'low',
          confidence: 0.6,
          description: 'API validation error detected',
          recommendation: 'Improve input validation and error messages',
        },
      ],
    };
  }

  /**
   * Detect patterns in a log entry
   */
  async detectPatterns(log) {
    const detectedPatterns = [];
    const { message, severity, duration, category } = log;

    // Check each pattern category
    for (const [categoryName, categoryPatterns] of Object.entries(this.patterns)) {
      for (const pattern of categoryPatterns) {
        const match = this.matchPattern(log, pattern);
        if (match.matched) {
          detectedPatterns.push({
            ...pattern,
            matchDetails: match.details,
            detectedAt: new Date().toISOString(),
          });
        }
      }
    }

    // Check for anomalies
    const anomalies = await this.detectAnomalies(log);
    detectedPatterns.push(...anomalies);

    // Sort by confidence and severity
    return detectedPatterns.sort((a, b) => {
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      const aSeverity = severityOrder[a.severity] || 0;
      const bSeverity = severityOrder[b.severity] || 0;
      
      if (aSeverity !== bSeverity) {
        return bSeverity - aSeverity; // Higher severity first
      }
      
      return b.confidence - a.confidence; // Higher confidence first
    });
  }

  /**
   * Match a specific pattern against log data
   */
  matchPattern(log, pattern) {
    const { message, severity, duration, category, endpoint, component } = log;
    const text = `${message} ${endpoint || ''} ${component || ''}`.toLowerCase();
    
    // Check text patterns
    const textMatches = pattern.patterns.map(regex => {
      const match = text.match(regex);
      return {
        matched: !!match,
        pattern: regex.source,
        matchedText: match?.[0],
      };
    });

    const hasTextMatch = textMatches.some(match => match.matched);
    
    // Check additional conditions
    let additionalConditions = true;
    const conditionDetails = {};

    // Check duration threshold
    if (pattern.durationThreshold && duration) {
      const durationMatch = duration > pattern.durationThreshold;
      conditionDetails.durationCheck = {
        threshold: pattern.durationThreshold,
        actual: duration,
        matched: durationMatch,
      };
      additionalConditions = additionalConditions && durationMatch;
    }

    // Check severity match
    if (pattern.severityMatch) {
      const severityMatch = severity === pattern.severityMatch;
      conditionDetails.severityCheck = {
        expected: pattern.severityMatch,
        actual: severity,
        matched: severityMatch,
      };
      additionalConditions = additionalConditions && severityMatch;
    }

    // Check category match
    if (pattern.categoryMatch) {
      const categoryMatch = category === pattern.categoryMatch;
      conditionDetails.categoryCheck = {
        expected: pattern.categoryMatch,
        actual: category,
        matched: categoryMatch,
      };
      additionalConditions = additionalConditions && categoryMatch;
    }

    const overallMatch = hasTextMatch && additionalConditions;

    return {
      matched: overallMatch,
      details: {
        textMatches: textMatches.filter(match => match.matched),
        conditions: conditionDetails,
        confidence: overallMatch ? pattern.confidence : 0,
      },
    };
  }

  /**
   * Detect anomalies in log data
   */
  async detectAnomalies(log) {
    const anomalies = [];

    // Check for unusual patterns
    const unusualPatterns = this.detectUnusualPatterns(log);
    anomalies.push(...unusualPatterns);

    // Check for frequency anomalies
    const frequencyAnomalies = await this.detectFrequencyAnomalies(log);
    anomalies.push(...frequencyAnomalies);

    // Check for timing anomalies
    const timingAnomalies = this.detectTimingAnomalies(log);
    anomalies.push(...timingAnomalies);

    return anomalies;
  }

  /**
   * Detect unusual patterns in log content
   */
  detectUnusualPatterns(log) {
    const anomalies = [];
    const { message, stackTrace } = log;

    // Check for extremely long messages
    if (message && message.length > 5000) {
      anomalies.push({
        name: 'extremely_long_message',
        type: 'anomaly',
        severity: 'medium',
        confidence: 0.7,
        description: 'Unusually long log message detected',
        recommendation: 'Review message content and consider truncation',
        detectedAt: new Date().toISOString(),
        details: {
          messageLength: message.length,
          threshold: 5000,
        },
      });
    }

    // Check for unusual characters or encoding
    if (message && /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/.test(message)) {
      anomalies.push({
        name: 'unusual_characters',
        type: 'anomaly',
        severity: 'low',
        confidence: 0.6,
        description: 'Unusual characters detected in log message',
        recommendation: 'Check for encoding issues or potential data corruption',
        detectedAt: new Date().toISOString(),
      });
    }

    // Check for suspiciously deep stack traces
    if (stackTrace && stackTrace.split('\n').length > 50) {
      anomalies.push({
        name: 'deep_stack_trace',
        type: 'anomaly',
        severity: 'medium',
        confidence: 0.6,
        description: 'Unusually deep stack trace detected',
        recommendation: 'Investigate potential infinite recursion or complex call chains',
        detectedAt: new Date().toISOString(),
        details: {
          stackDepth: stackTrace.split('\n').length,
          threshold: 50,
        },
      });
    }

    return anomalies;
  }

  /**
   * Detect frequency anomalies (would require historical data)
   */
  async detectFrequencyAnomalies(log) {
    const anomalies = [];

    // This would typically analyze historical patterns
    // For now, we'll implement basic heuristics

    // Check for rapid-fire similar messages (would need state management)
    // This is a simplified implementation
    if (log.component && log.severity === 'error') {
      anomalies.push({
        name: 'potential_error_spike',
        type: 'anomaly',
        severity: 'medium',
        confidence: 0.5,
        description: 'Potential error spike pattern detected',
        recommendation: 'Monitor error frequency for this component',
        detectedAt: new Date().toISOString(),
        details: {
          component: log.component,
          severity: log.severity,
          note: 'This detection requires historical data for accuracy',
        },
      });
    }

    return anomalies;
  }

  /**
   * Detect timing anomalies
   */
  detectTimingAnomalies(log) {
    const anomalies = [];
    const { duration, timestamp } = log;

    // Check for unusually long operations
    if (duration && duration > 30000) { // 30 seconds
      anomalies.push({
        name: 'extremely_long_operation',
        type: 'anomaly',
        severity: 'high',
        confidence: 0.8,
        description: 'Extremely long operation duration detected',
        recommendation: 'Investigate operation performance and consider optimization',
        detectedAt: new Date().toISOString(),
        details: {
          duration,
          threshold: 30000,
        },
      });
    }

    // Check for logs from unusual times (if business hours matter)
    const logTime = new Date(timestamp);
    const hour = logTime.getHours();
    
    if (log.category === 'business' && (hour < 6 || hour > 22)) {
      anomalies.push({
        name: 'unusual_time_activity',
        type: 'anomaly',
        severity: 'low',
        confidence: 0.4,
        description: 'Business activity detected outside normal hours',
        recommendation: 'Review if this activity is expected or investigate for security concerns',
        detectedAt: new Date().toISOString(),
        details: {
          hour,
          timezone: 'UTC',
          normalHours: '06:00 - 22:00',
        },
      });
    }

    return anomalies;
  }

  /**
   * Add custom pattern
   */
  addCustomPattern(category, pattern) {
    if (!this.patterns[category]) {
      this.patterns[category] = [];
    }

    // Validate pattern structure
    const requiredFields = ['name', 'type', 'patterns', 'severity', 'confidence'];
    const missingFields = requiredFields.filter(field => !pattern[field]);
    
    if (missingFields.length > 0) {
      throw new Error(`Missing required fields: ${missingFields.join(', ')}`);
    }

    // Add pattern with metadata
    this.patterns[category].push({
      ...pattern,
      addedAt: new Date().toISOString(),
      custom: true,
    });

    return {
      success: true,
      category,
      patternName: pattern.name,
    };
  }

  /**
   * Remove custom pattern
   */
  removeCustomPattern(category, patternName) {
    if (!this.patterns[category]) {
      return { success: false, error: 'Category not found' };
    }

    const initialLength = this.patterns[category].length;
    this.patterns[category] = this.patterns[category].filter(
      pattern => !(pattern.name === patternName && pattern.custom)
    );

    const removed = this.patterns[category].length < initialLength;

    return {
      success: removed,
      category,
      patternName,
      removed,
    };
  }

  /**
   * Get pattern statistics
   */
  getPatternStats() {
    const stats = {};

    for (const [category, patterns] of Object.entries(this.patterns)) {
      stats[category] = {
        total: patterns.length,
        builtin: patterns.filter(p => !p.custom).length,
        custom: patterns.filter(p => p.custom).length,
        bySeverity: {},
      };

      // Count by severity
      for (const pattern of patterns) {
        const severity = pattern.severity || 'unknown';
        stats[category].bySeverity[severity] = (stats[category].bySeverity[severity] || 0) + 1;
      }
    }

    return stats;
  }

  /**
   * Export patterns configuration
   */
  exportPatterns() {
    return {
      exportedAt: new Date().toISOString(),
      patterns: this.patterns,
      stats: this.getPatternStats(),
    };
  }

  /**
   * Import patterns configuration
   */
  importPatterns(patternsConfig) {
    try {
      // Validate structure
      if (!patternsConfig.patterns || typeof patternsConfig.patterns !== 'object') {
        throw new Error('Invalid patterns configuration');
      }

      // Backup current patterns
      const backup = { ...this.patterns };

      try {
        // Apply new patterns
        this.patterns = { ...patternsConfig.patterns };
        
        return {
          success: true,
          imported: Object.keys(patternsConfig.patterns).length,
          importedAt: new Date().toISOString(),
        };
      } catch (error) {
        // Restore backup on failure
        this.patterns = backup;
        throw error;
      }

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }
}