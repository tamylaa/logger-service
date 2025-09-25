/**
 * Triaging Engine - Implements smart triaging and automated response system
 * Analyzes logs and determines appropriate actions based on severity and patterns
 */

export class TriagingEngine {
  constructor(config) {
    this.config = config;
    this.rules = this.initializeTriagingRules();
  }

  /**
   * Initialize triaging rules based on configuration
   */
  initializeTriagingRules() {
    return {
      // Critical severity rules
      critical: [
        {
          name: 'service_down',
          condition: (log) => this.matchesPatterns(log.message, ['service unavailable', 'connection refused', 'service down']),
          actions: ['immediate_alert', 'escalate_to_oncall', 'create_incident'],
          priority: 1,
        },
        {
          name: 'security_breach',
          condition: (log) => this.matchesPatterns(log.message, ['unauthorized access', 'security breach', 'intrusion detected']),
          actions: ['immediate_alert', 'security_team_notification', 'lockdown_mode'],
          priority: 1,
        },
        {
          name: 'data_loss',
          condition: (log) => this.matchesPatterns(log.message, ['data corruption', 'data loss', 'backup failed']),
          actions: ['immediate_alert', 'backup_verification', 'data_recovery'],
          priority: 1,
        },
      ],

      // Error severity rules
      error: [
        {
          name: 'database_error',
          condition: (log) => log.category === 'database' && log.severity === 'error',
          actions: ['alert_dba', 'check_connections', 'monitor_performance'],
          priority: 2,
        },
        {
          name: 'authentication_failure',
          condition: (log) => log.category === 'authentication' && this.matchesPatterns(log.message, ['login failed', 'authentication error']),
          actions: ['monitor_brute_force', 'user_notification'],
          priority: 2,
        },
        {
          name: 'api_error_spike',
          condition: (log) => log.category === 'api' && log.severity === 'error',
          actions: ['api_health_check', 'performance_monitoring'],
          priority: 2,
          requiresPattern: true, // Needs pattern analysis to detect spikes
        },
      ],

      // Warning severity rules
      warning: [
        {
          name: 'performance_degradation',
          condition: (log) => log.category === 'performance' || (log.duration && log.duration > 5000),
          actions: ['performance_monitoring', 'resource_check'],
          priority: 3,
        },
        {
          name: 'high_memory_usage',
          condition: (log) => log.memoryUsage && log.memoryUsage > 0.8,
          actions: ['memory_monitoring', 'garbage_collection'],
          priority: 3,
        },
      ],

      // Info severity rules
      info: [
        {
          name: 'business_event',
          condition: (log) => log.category === 'business',
          actions: ['analytics_tracking', 'business_metrics'],
          priority: 4,
        },
      ],
    };
  }

  /**
   * Triage a log entry and determine actions
   */
  async triage(log, context) {
    const { logger } = context;
    
    try {
      const triageResult = {
        level: this.determineTriageLevel(log),
        severity: log.severity,
        category: log.category,
        timestamp: new Date().toISOString(),
      };

      // Find matching rules
      const matchingRules = this.findMatchingRules(log);
      
      // Determine actions based on rules
      const actions = await this.determineActions(log, matchingRules, context);
      
      // Generate recommendations
      const recommendations = this.generateRecommendations(log, matchingRules);

      // Execute immediate actions if required
      if (triageResult.level === 'critical') {
        await this.executeImmediateActions(actions, log, context);
      }

      return {
        triage: triageResult,
        actions,
        recommendations,
        matchingRules: matchingRules.map(rule => ({
          name: rule.name,
          priority: rule.priority,
        })),
      };

    } catch (error) {
      logger.error('Triaging failed', {
        logId: log.id,
        error: error.message,
      });
      
      return {
        triage: {
          level: 'unknown',
          error: error.message,
        },
        actions: [],
        recommendations: [],
      };
    }
  }

  /**
   * Determine triage level based on log content and severity
   */
  determineTriageLevel(log) {
    const { severity, category, message } = log;

    // Critical conditions
    if (severity === 'fatal' || severity === 'critical') {
      return 'critical';
    }

    if (this.isCriticalPattern(message, category)) {
      return 'critical';
    }

    // High priority conditions
    if (severity === 'error') {
      if (this.isHighPriorityError(message, category)) {
        return 'high';
      }
      return 'medium';
    }

    // Medium priority conditions
    if (severity === 'warn' || severity === 'warning') {
      return 'medium';
    }

    // Low priority
    return 'low';
  }

  /**
   * Check if message/category indicates critical issue
   */
  isCriticalPattern(message, category) {
    const criticalPatterns = [
      'service down',
      'service unavailable',
      'database unreachable',
      'security breach',
      'data corruption',
      'system failure',
      'out of memory',
      'disk full',
    ];

    const criticalCategories = ['security', 'infrastructure'];

    return this.matchesPatterns(message, criticalPatterns) || 
           criticalCategories.includes(category);
  }

  /**
   * Check if error is high priority
   */
  isHighPriorityError(message, category) {
    const highPriorityPatterns = [
      'timeout',
      'connection failed',
      'authentication error',
      'authorization failed',
      'payment failed',
      'user data',
    ];

    const highPriorityCategories = ['authentication', 'database', 'payment'];

    return this.matchesPatterns(message, highPriorityPatterns) || 
           highPriorityCategories.includes(category);
  }

  /**
   * Find rules that match the current log
   */
  findMatchingRules(log) {
    const matchingRules = [];
    const severityRules = this.rules[log.severity] || [];

    for (const rule of severityRules) {
      if (rule.condition(log)) {
        matchingRules.push(rule);
      }
    }

    // Sort by priority (lower number = higher priority)
    return matchingRules.sort((a, b) => a.priority - b.priority);
  }

  /**
   * Determine actions based on matching rules and context
   */
  async determineActions(log, matchingRules, context) {
    const actions = [];
    const executedActions = new Set();

    for (const rule of matchingRules) {
      for (const actionName of rule.actions) {
        if (!executedActions.has(actionName)) {
          const action = await this.createAction(actionName, log, rule, context);
          if (action) {
            actions.push(action);
            executedActions.add(actionName);
          }
        }
      }
    }

    return actions;
  }

  /**
   * Create an action object
   */
  async createAction(actionName, log, rule, context) {
    const actionConfig = {
      name: actionName,
      logId: log.id,
      rule: rule.name,
      timestamp: new Date().toISOString(),
    };

    switch (actionName) {
      case 'immediate_alert':
        return {
          ...actionConfig,
          type: 'alert',
          channels: ['email', 'slack', 'webhook'],
          message: `Critical issue detected: ${log.message}`,
          severity: 'critical',
          executeImmediately: true,
        };

      case 'escalate_to_oncall':
        return {
          ...actionConfig,
          type: 'escalation',
          target: 'oncall_engineer',
          message: `Escalation required for log ID: ${log.id}`,
          executeImmediately: true,
        };

      case 'create_incident':
        return {
          ...actionConfig,
          type: 'incident',
          title: `Automated incident for ${log.category} issue`,
          description: log.message,
          severity: log.severity,
        };

      case 'alert_dba':
        return {
          ...actionConfig,
          type: 'alert',
          channels: ['email'],
          target: 'database_team',
          message: `Database issue detected: ${log.message}`,
        };

      case 'monitor_brute_force':
        return {
          ...actionConfig,
          type: 'monitoring',
          metric: 'authentication_failures',
          threshold: 10,
          timeWindow: '5m',
        };

      case 'performance_monitoring':
        return {
          ...actionConfig,
          type: 'monitoring',
          metric: 'response_time',
          component: log.component,
          threshold: 'dynamic',
        };

      case 'security_team_notification':
        return {
          ...actionConfig,
          type: 'alert',
          channels: ['email', 'pagerduty'],
          target: 'security_team',
          message: `Security incident detected: ${log.message}`,
          severity: 'critical',
          executeImmediately: true,
        };

      case 'analytics_tracking':
        return {
          ...actionConfig,
          type: 'analytics',
          event: 'business_event',
          properties: {
            category: log.category,
            component: log.component,
          },
        };

      default:
        return {
          ...actionConfig,
          type: 'custom',
          description: `Action ${actionName} not implemented`,
        };
    }
  }

  /**
   * Generate recommendations based on log analysis
   */
  generateRecommendations(log, matchingRules) {
    const recommendations = [];

    // Category-based recommendations
    switch (log.category) {
      case 'database':
        recommendations.push({
          type: 'optimization',
          title: 'Database Performance',
          description: 'Consider adding database indexes or optimizing queries',
          priority: 'medium',
        });
        break;

      case 'authentication':
        recommendations.push({
          type: 'security',
          title: 'Authentication Security',
          description: 'Consider implementing rate limiting and multi-factor authentication',
          priority: 'high',
        });
        break;

      case 'api':
        recommendations.push({
          type: 'performance',
          title: 'API Performance',
          description: 'Consider implementing caching and request optimization',
          priority: 'medium',
        });
        break;
    }

    // Severity-based recommendations
    if (log.severity === 'error' && log.stackTrace) {
      recommendations.push({
        type: 'debugging',
        title: 'Error Investigation',
        description: 'Review stack trace and implement proper error handling',
        priority: 'high',
      });
    }

    // Pattern-based recommendations
    if (log.patterns?.length) {
      for (const pattern of log.patterns) {
        if (pattern.recommendation) {
          recommendations.push({
            type: 'pattern',
            title: `Pattern: ${pattern.type}`,
            description: pattern.recommendation,
            priority: pattern.confidence > 0.8 ? 'high' : 'medium',
          });
        }
      }
    }

    return recommendations;
  }

  /**
   * Execute immediate actions for critical issues
   */
  async executeImmediateActions(actions, log, context) {
    const { logger } = context;

    for (const action of actions) {
      if (action.executeImmediately) {
        try {
          await this.executeAction(action, log, context);
          logger.info('Immediate action executed', {
            actionName: action.name,
            actionType: action.type,
            logId: log.id,
          });
        } catch (error) {
          logger.error('Failed to execute immediate action', {
            actionName: action.name,
            error: error.message,
            logId: log.id,
          });
        }
      }
    }
  }

  /**
   * Execute a specific action
   */
  async executeAction(action, log, context) {
    switch (action.type) {
      case 'alert':
        await this.sendAlert(action, log, context);
        break;

      case 'escalation':
        await this.escalateIssue(action, log, context);
        break;

      case 'incident':
        await this.createIncident(action, log, context);
        break;

      case 'monitoring':
        await this.setupMonitoring(action, log, context);
        break;

      default:
        context.logger.warn('Unknown action type', { actionType: action.type });
    }
  }

  /**
   * Send alert notifications
   */
  async sendAlert(action, log, context) {
    const alertPayload = {
      message: action.message,
      severity: action.severity,
      logId: log.id,
      timestamp: new Date().toISOString(),
    };

    // Send to configured channels
    for (const channel of action.channels || []) {
      try {
        await this.sendToChannel(channel, alertPayload, context);
      } catch (error) {
        context.logger.error(`Failed to send alert to ${channel}`, {
          error: error.message,
          logId: log.id,
        });
      }
    }
  }

  /**
   * Send alert to specific channel
   */
  async sendToChannel(channel, payload, context) {
    switch (channel) {
      case 'slack':
        if (this.config.monitoring.slackWebhookUrl) {
          // Implementation would send to Slack webhook
          context.logger.info('Alert sent to Slack', { logId: payload.logId });
        }
        break;

      case 'webhook':
        if (this.config.monitoring.webhookUrl) {
          // Implementation would send to webhook
          context.logger.info('Alert sent to webhook', { logId: payload.logId });
        }
        break;

      case 'email':
        if (this.config.monitoring.emailAlerts) {
          // Implementation would send email
          context.logger.info('Alert sent via email', { logId: payload.logId });
        }
        break;

      default:
        context.logger.warn('Unknown alert channel', { channel });
    }
  }

  /**
   * Escalate issue to on-call engineer
   */
  async escalateIssue(action, log, context) {
    // Implementation would integrate with PagerDuty or similar service
    context.logger.info('Issue escalated', {
      target: action.target,
      logId: log.id,
    });
  }

  /**
   * Create incident record
   */
  async createIncident(action, log, context) {
    // Implementation would create incident in ticketing system
    context.logger.info('Incident created', {
      title: action.title,
      logId: log.id,
    });
  }

  /**
   * Setup monitoring for specific metrics
   */
  async setupMonitoring(action, log, context) {
    // Implementation would configure monitoring alerts
    context.logger.info('Monitoring configured', {
      metric: action.metric,
      logId: log.id,
    });
  }

  /**
   * Helper method to match patterns in text
   */
  matchesPatterns(text, patterns) {
    if (!text || typeof text !== 'string') {
      return false;
    }
    
    const lowerText = text.toLowerCase();
    return patterns.some(pattern => lowerText.includes(pattern.toLowerCase()));
  }
}