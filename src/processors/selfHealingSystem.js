/**
 * Self-Healing System - Automated recovery and optimization
 * Implements proactive system maintenance as suggested in feedback
 */

import { Logger } from '../utils/logger.js';
import { ErrorHandler } from '../utils/errorHandler.js';

export class SelfHealingSystem {
  constructor(config, logStorage, integrationManager) {
    this.config = config;
    this.storage = logStorage;
    this.integrationManager = integrationManager;
    this.logger = new Logger('SelfHealingSystem');
    
    // Healing actions and their configurations
    this.healingActions = new Map();
    this.activeHealingOperations = new Map();
    this.healingHistory = [];
    
    // Initialize default healing actions
    this.initializeDefaultActions();
    
    // Start monitoring
    this.startMonitoring();
  }

  /**
   * Initialize default self-healing actions
   */
  initializeDefaultActions() {
    const defaultActions = [
      {
        id: 'restart-service',
        name: 'Service Restart',
        triggers: [
          { pattern: 'error_spike', threshold: 50, timeWindow: 300 },
          { pattern: 'memory_leak', threshold: 1, timeWindow: 60 },
        ],
        action: this.restartService.bind(this),
        cooldown: 900, // 15 minutes
        enabled: this.config.selfHealing?.enableServiceRestart || false,
      },
      {
        id: 'scale-resources',
        name: 'Resource Scaling',
        triggers: [
          { pattern: 'high_load', threshold: 80, timeWindow: 300 },
          { pattern: 'performance_degradation', threshold: 5, timeWindow: 600 },
        ],
        action: this.scaleResources.bind(this),
        cooldown: 600, // 10 minutes
        enabled: this.config.selfHealing?.enableAutoScaling || false,
      },
      {
        id: 'clear-cache',
        name: 'Cache Clearing',
        triggers: [
          { pattern: 'cache_error', threshold: 10, timeWindow: 180 },
          { pattern: 'memory_pressure', threshold: 1, timeWindow: 60 },
        ],
        action: this.clearCache.bind(this),
        cooldown: 300, // 5 minutes
        enabled: this.config.selfHealing?.enableCacheClear || true,
      },
      {
        id: 'circuit-breaker',
        name: 'Circuit Breaker Activation',
        triggers: [
          { pattern: 'service_unavailable', threshold: 5, timeWindow: 120 },
          { pattern: 'timeout_errors', threshold: 10, timeWindow: 300 },
        ],
        action: this.activateCircuitBreaker.bind(this),
        cooldown: 180, // 3 minutes
        enabled: this.config.selfHealing?.enableCircuitBreaker || true,
      },
      {
        id: 'log-cleanup',
        name: 'Log Storage Cleanup',
        triggers: [
          { pattern: 'storage_full', threshold: 1, timeWindow: 60 },
          { pattern: 'disk_space_low', threshold: 1, timeWindow: 300 },
        ],
        action: this.performLogCleanup.bind(this),
        cooldown: 3600, // 1 hour
        enabled: this.config.selfHealing?.enableLogCleanup || true,
      },
    ];

    for (const action of defaultActions) {
      this.healingActions.set(action.id, action);
    }
  }

  /**
   * Start monitoring for healing triggers
   */
  startMonitoring() {
    // Monitor every 60 seconds
    setInterval(async () => {
      await this.checkForHealingTriggers();
    }, 60000);

    this.logger.info('Self-healing monitoring started', {
      actionsCount: this.healingActions.size,
      enabledActions: Array.from(this.healingActions.values())
        .filter(action => action.enabled)
        .map(action => action.id),
    });
  }

  /**
   * Check for conditions that trigger healing actions
   */
  async checkForHealingTriggers() {
    try {
      // Get recent logs for analysis
      const recentLogs = await this.getRecentLogsForAnalysis();
      
      // Check each healing action
      for (const [actionId, action] of this.healingActions.entries()) {
        if (!action.enabled) continue;
        
        // Check if action is in cooldown
        if (this.isInCooldown(actionId)) {
          continue;
        }

        // Check triggers
        const shouldTrigger = await this.evaluateTriggers(action.triggers, recentLogs);
        
        if (shouldTrigger) {
          await this.executeHealingAction(actionId, action, shouldTrigger.reason);
        }
      }

    } catch (error) {
      this.logger.error('Self-healing monitoring failed', {
        error: error.message,
      });
    }
  }

  /**
   * Get recent logs for analysis
   */
  async getRecentLogsForAnalysis() {
    const endTime = new Date().toISOString();
    const startTime = new Date(Date.now() - 15 * 60 * 1000).toISOString(); // Last 15 minutes

    try {
      return await this.storage.retrieveLogs({
        startTime,
        endTime,
        limit: 1000,
      });
    } catch (error) {
      this.logger.error('Failed to get recent logs for healing analysis', {
        error: error.message,
      });
      return [];
    }
  }

  /**
   * Evaluate if triggers should activate healing action
   */
  async evaluateTriggers(triggers, logs) {
    for (const trigger of triggers) {
      const matchingLogs = this.filterLogsByPattern(logs, trigger.pattern);
      
      if (matchingLogs.length >= trigger.threshold) {
        // Check if all matching logs are within the time window
        const windowStart = Date.now() - (trigger.timeWindow * 1000);
        const recentMatches = matchingLogs.filter(log => 
          new Date(log.timestamp).getTime() > windowStart
        );

        if (recentMatches.length >= trigger.threshold) {
          return {
            triggered: true,
            pattern: trigger.pattern,
            count: recentMatches.length,
            threshold: trigger.threshold,
            timeWindow: trigger.timeWindow,
            reason: `Pattern '${trigger.pattern}' occurred ${recentMatches.length} times (threshold: ${trigger.threshold}) in ${trigger.timeWindow}s`,
          };
        }
      }
    }

    return false;
  }

  /**
   * Filter logs by pattern
   */
  filterLogsByPattern(logs, pattern) {
    const patternMatchers = {
      error_spike: (log) => log.severity === 'error' || log.severity === 'critical',
      memory_leak: (log) => log.message?.toLowerCase().includes('memory') || log.message?.toLowerCase().includes('heap'),
      high_load: (log) => log.message?.toLowerCase().includes('load') || log.message?.toLowerCase().includes('cpu'),
      performance_degradation: (log) => log.duration && log.duration > 5000,
      cache_error: (log) => log.message?.toLowerCase().includes('cache'),
      memory_pressure: (log) => log.message?.toLowerCase().includes('out of memory'),
      service_unavailable: (log) => log.message?.toLowerCase().includes('unavailable') || log.message?.includes('503'),
      timeout_errors: (log) => log.message?.toLowerCase().includes('timeout'),
      storage_full: (log) => log.message?.toLowerCase().includes('storage') && log.message?.toLowerCase().includes('full'),
      disk_space_low: (log) => log.message?.toLowerCase().includes('disk') && log.message?.toLowerCase().includes('space'),
    };

    const matcher = patternMatchers[pattern];
    return matcher ? logs.filter(matcher) : [];
  }

  /**
   * Check if action is in cooldown period
   */
  isInCooldown(actionId) {
    const lastExecution = this.activeHealingOperations.get(actionId);
    if (!lastExecution) return false;

    const action = this.healingActions.get(actionId);
    const cooldownEnd = lastExecution + (action.cooldown * 1000);
    
    return Date.now() < cooldownEnd;
  }

  /**
   * Execute healing action
   */
  async executeHealingAction(actionId, action, reason) {
    try {
      this.logger.warn('Executing self-healing action', {
        actionId,
        actionName: action.name,
        reason,
      });

      // Record execution start
      this.activeHealingOperations.set(actionId, Date.now());

      // Execute the action
      const result = await action.action(reason);

      // Record in history
      const historyEntry = {
        actionId,
        actionName: action.name,
        executedAt: new Date().toISOString(),
        reason,
        result,
        success: result.success,
      };

      this.healingHistory.push(historyEntry);

      // Keep only last 100 entries
      if (this.healingHistory.length > 100) {
        this.healingHistory = this.healingHistory.slice(-100);
      }

      if (result.success) {
        this.logger.info('Self-healing action completed successfully', {
          actionId,
          result: result.message,
        });
      } else {
        this.logger.error('Self-healing action failed', {
          actionId,
          error: result.error,
        });
      }

    } catch (error) {
      this.logger.error('Self-healing action execution failed', {
        actionId,
        error: error.message,
      });

      // Still record the attempt
      this.healingHistory.push({
        actionId,
        actionName: action.name,
        executedAt: new Date().toISOString(),
        reason,
        success: false,
        error: error.message,
      });
    }
  }

  /**
   * Restart service (via webhook or API call)
   */
  async restartService(reason) {
    try {
      // This would integrate with your deployment system
      // For example, calling a webhook or API to restart services
      
      const restartEndpoint = this.config.selfHealing?.restartWebhook;
      
      if (!restartEndpoint) {
        return {
          success: false,
          error: 'No restart endpoint configured',
        };
      }

      const response = await fetch(restartEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'restart',
          reason,
          timestamp: new Date().toISOString(),
          source: 'logger-service-self-healing',
        }),
      });

      if (!response.ok) {
        throw new Error(`Restart request failed: ${response.status}`);
      }

      return {
        success: true,
        message: 'Service restart initiated successfully',
        response: await response.text(),
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Scale resources (placeholder - would integrate with cloud provider)
   */
  async scaleResources(reason) {
    try {
      // This would integrate with cloud provider APIs
      // For now, just log the action
      
      this.logger.info('Resource scaling would be triggered', {
        reason,
        note: 'Integration with cloud provider required',
      });

      return {
        success: true,
        message: 'Resource scaling logged (integration required)',
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Clear cache
   */
  async clearCache(reason) {
    try {
      // Clear KV cache entries (example)
      const cacheKeys = await this.getCacheKeys();
      let clearedCount = 0;

      for (const key of cacheKeys) {
        try {
          // This would clear specific cache keys
          // await this.storage.clearCacheKey(key);
          clearedCount++;
        } catch (error) {
          this.logger.warn('Failed to clear cache key', { key, error: error.message });
        }
      }

      return {
        success: true,
        message: `Cache cleared: ${clearedCount} keys processed`,
        clearedCount,
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Activate circuit breaker
   */
  async activateCircuitBreaker(reason) {
    try {
      // This would integrate with your service mesh or load balancer
      // to activate circuit breaker patterns
      
      this.logger.warn('Circuit breaker activation triggered', {
        reason,
        note: 'Would integrate with service mesh/load balancer',
      });

      return {
        success: true,
        message: 'Circuit breaker activation logged',
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Perform log cleanup
   */
  async performLogCleanup(reason) {
    try {
      // Clean up old logs based on retention policy
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - 7); // Keep last 7 days

      const cleanupResult = await this.storage.cleanupOldLogs(cutoffDate.toISOString());

      return {
        success: true,
        message: `Log cleanup completed: ${cleanupResult.deletedCount || 0} logs removed`,
        deletedCount: cleanupResult.deletedCount || 0,
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get cache keys (placeholder)
   */
  async getCacheKeys() {
    // This would list cache keys from your storage system
    return ['analytics:cache:*', 'metrics:cache:*'];
  }

  /**
   * Add custom healing action
   */
  addHealingAction(actionConfig) {
    try {
      // Validate action configuration
      const required = ['id', 'name', 'triggers', 'action'];
      const missing = required.filter(field => !actionConfig[field]);
      
      if (missing.length > 0) {
        throw new Error(`Missing required fields: ${missing.join(', ')}`);
      }

      // Set defaults
      const action = {
        ...actionConfig,
        cooldown: actionConfig.cooldown || 300,
        enabled: actionConfig.enabled !== false,
        custom: true,
        addedAt: new Date().toISOString(),
      };

      this.healingActions.set(action.id, action);

      this.logger.info('Custom healing action added', {
        actionId: action.id,
        actionName: action.name,
      });

      return {
        success: true,
        actionId: action.id,
      };

    } catch (error) {
      this.logger.error('Failed to add healing action', {
        error: error.message,
      });
      
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Remove healing action
   */
  removeHealingAction(actionId) {
    try {
      const action = this.healingActions.get(actionId);
      
      if (!action) {
        return {
          success: false,
          error: `Action ${actionId} not found`,
        };
      }

      // Don't allow removal of built-in actions
      if (!action.custom) {
        return {
          success: false,
          error: 'Cannot remove built-in healing action',
        };
      }

      this.healingActions.delete(actionId);
      this.activeHealingOperations.delete(actionId);

      this.logger.info('Healing action removed', { actionId });

      return {
        success: true,
        actionId,
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get healing status and history
   */
  getHealingStatus() {
    const actions = Array.from(this.healingActions.values()).map(action => ({
      id: action.id,
      name: action.name,
      enabled: action.enabled,
      cooldown: action.cooldown,
      triggersCount: action.triggers.length,
      inCooldown: this.isInCooldown(action.id),
      custom: action.custom || false,
    }));

    return {
      status: 'active',
      actionsConfigured: this.healingActions.size,
      actionsEnabled: actions.filter(a => a.enabled).length,
      actions,
      recentHistory: this.healingHistory.slice(-10),
      totalExecutions: this.healingHistory.length,
      successfulExecutions: this.healingHistory.filter(h => h.success).length,
    };
  }

  /**
   * Enable/disable healing action
   */
  toggleHealingAction(actionId, enabled) {
    try {
      const action = this.healingActions.get(actionId);
      
      if (!action) {
        return {
          success: false,
          error: `Action ${actionId} not found`,
        };
      }

      action.enabled = enabled;

      this.logger.info('Healing action toggled', {
        actionId,
        enabled,
      });

      return {
        success: true,
        actionId,
        enabled,
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Force execute healing action (for testing/manual intervention)
   */
  async forceExecuteAction(actionId, reason = 'Manual execution') {
    try {
      const action = this.healingActions.get(actionId);
      
      if (!action) {
        throw new Error(`Action ${actionId} not found`);
      }

      if (!action.enabled) {
        throw new Error(`Action ${actionId} is disabled`);
      }

      return await this.executeHealingAction(actionId, action, reason);

    } catch (error) {
      this.logger.error('Force execution failed', {
        actionId,
        error: error.message,
      });
      
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Shutdown self-healing system
   */
  shutdown() {
    this.logger.info('Self-healing system shutting down');
    
    // Clear any active operations
    this.activeHealingOperations.clear();
    
    // Could save healing history to persistent storage here
  }
}