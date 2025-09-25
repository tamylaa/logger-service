/**
 * Health Handler - Provides health check endpoints and system status
 * Monitors service health, dependencies, and performance metrics
 */

import { ErrorHandler } from '../utils/errorHandler.js';

export class HealthHandler {
  constructor(config, env) {
    this.config = config;
    this.env = env;
    this.startTime = Date.now();
  }

  /**
   * Get comprehensive health status
   */
  async getHealth(request, context) {
    const { logger, requestId } = context;
    
    try {
      const healthChecks = await this.performHealthChecks(context);
      
      // Determine overall health status
      const overallStatus = this.determineOverallStatus(healthChecks);
      
      // Create health response
      const healthResponse = {
        status: overallStatus,
        timestamp: new Date().toISOString(),
        service: {
          name: this.config.service.name,
          version: this.config.service.version,
          environment: this.config.service.environment,
          uptime: this.getUptime(),
        },
        checks: healthChecks,
        metadata: {
          requestId,
          respondedAt: new Date().toISOString(),
        },
      };

      // Log health check
      logger.info('Health check performed', {
        requestId,
        status: overallStatus,
        checksCount: Object.keys(healthChecks).length,
      });

      // Return appropriate status code
      const statusCode = overallStatus === 'healthy' ? 200 : 503;
      
      return new Response(JSON.stringify(healthResponse), {
        status: statusCode,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'X-Health-Status': overallStatus,
        },
      });

    } catch (error) {
      logger.error('Health check failed', {
        requestId,
        error: error.message,
      });

      return ErrorHandler.handleError(error, logger);
    }
  }

  /**
   * Perform all health checks
   */
  async performHealthChecks(context) {
    const checks = {};

    // Run health checks in parallel with timeout
    const checkPromises = [
      this.checkKVStorage(context),
      this.checkD1Database(context),
      this.checkMemory(context),
      this.checkConfiguration(context),
      this.checkDependencies(context),
    ];

    const results = await Promise.allSettled(checkPromises);
    
    // Process results
    const checkNames = ['kv_storage', 'd1_database', 'memory', 'configuration', 'dependencies'];
    
    results.forEach((result, index) => {
      const checkName = checkNames[index];
      
      if (result.status === 'fulfilled') {
        checks[checkName] = result.value;
      } else {
        checks[checkName] = {
          status: 'unhealthy',
          message: result.reason?.message || 'Check failed',
          error: result.reason?.message,
          timestamp: new Date().toISOString(),
        };
      }
    });

    return checks;
  }

  /**
   * Check KV storage health
   */
  async checkKVStorage(context) {
    const startTime = Date.now();
    
    try {
      if (!this.env.LOGS_KV) {
        return {
          status: 'unhealthy',
          message: 'KV storage not configured',
          timestamp: new Date().toISOString(),
        };
      }

      // Test KV operations
      const testKey = `health:kv:${Date.now()}`;
      const testValue = 'health-check';
      
      // Test write
      await this.env.LOGS_KV.put(testKey, testValue, { expirationTtl: 60 });
      
      // Test read
      const readValue = await this.env.LOGS_KV.get(testKey);
      
      // Test delete
      await this.env.LOGS_KV.delete(testKey);
      
      const responseTime = Date.now() - startTime;
      
      if (readValue === testValue) {
        return {
          status: 'healthy',
          message: 'KV storage operational',
          responseTime,
          timestamp: new Date().toISOString(),
          details: {
            operations: ['put', 'get', 'delete'],
            testPassed: true,
          },
        };
      } else {
        return {
          status: 'unhealthy',
          message: 'KV storage read/write test failed',
          responseTime,
          timestamp: new Date().toISOString(),
        };
      }

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'KV storage error',
        error: error.message,
        responseTime: Date.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Check D1 database health
   */
  async checkD1Database(context) {
    const startTime = Date.now();
    
    try {
      if (!this.env.LOGS_DB) {
        return {
          status: 'unhealthy',
          message: 'D1 database not configured',
          timestamp: new Date().toISOString(),
        };
      }

      // Test database connection with a simple query
      const result = await this.env.LOGS_DB.prepare('SELECT 1 as test').first();
      
      const responseTime = Date.now() - startTime;
      
      if (result && result.test === 1) {
        return {
          status: 'healthy',
          message: 'D1 database operational',
          responseTime,
          timestamp: new Date().toISOString(),
          details: {
            testQuery: 'SELECT 1',
            testPassed: true,
          },
        };
      } else {
        return {
          status: 'unhealthy',
          message: 'D1 database test query failed',
          responseTime,
          timestamp: new Date().toISOString(),
        };
      }

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'D1 database error',
        error: error.message,
        responseTime: Date.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Check memory usage (limited in Workers)
   */
  async checkMemory(context) {
    try {
      // Cloudflare Workers have memory limits but don't expose usage directly
      // We can do a basic memory stress test
      const testArray = new Array(1000).fill('test');
      const memoryTestPassed = testArray.length === 1000;
      
      return {
        status: 'healthy',
        message: 'Memory check passed',
        timestamp: new Date().toISOString(),
        details: {
          memoryLimit: '128MB', // Cloudflare Workers limit
          testPassed: memoryTestPassed,
          note: 'Detailed memory metrics not available in Workers',
        },
      };

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Memory check failed',
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Check configuration health
   */
  async checkConfiguration(context) {
    try {
      // Validate configuration
      const validationResult = this.config.validate();
      
      return {
        status: 'healthy',
        message: 'Configuration valid',
        timestamp: new Date().toISOString(),
        details: {
          environment: this.config.service.environment,
          featuresEnabled: this.getEnabledFeatures(),
          configValid: validationResult,
        },
      };

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Configuration validation failed',
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Check external dependencies
   */
  async checkDependencies(context) {
    try {
      const dependencies = {
        cloudflare: 'operational', // Assumed since we're running
      };

      // Check external service URLs if configured
      if (this.config.integrations.authServiceUrl) {
        dependencies.authService = await this.checkExternalService(
          this.config.integrations.authServiceUrl + '/health',
          context
        );
      }

      if (this.config.integrations.dataServiceUrl) {
        dependencies.dataService = await this.checkExternalService(
          this.config.integrations.dataServiceUrl + '/health',
          context
        );
      }

      const allHealthy = Object.values(dependencies).every(status => 
        status === 'operational' || status === 'healthy'
      );

      return {
        status: allHealthy ? 'healthy' : 'degraded',
        message: allHealthy ? 'All dependencies operational' : 'Some dependencies degraded',
        timestamp: new Date().toISOString(),
        details: dependencies,
      };

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Dependency check failed',
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Check external service health
   */
  async checkExternalService(url, context, timeout = 5000) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);
      
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': `${this.config.service.name}/health-check`,
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        return 'operational';
      } else {
        return 'degraded';
      }

    } catch (error) {
      if (error.name === 'AbortError') {
        return 'timeout';
      }
      return 'error';
    }
  }

  /**
   * Determine overall system health status
   */
  determineOverallStatus(checks) {
    const statuses = Object.values(checks).map(check => check.status);
    
    // If any check is unhealthy, system is unhealthy
    if (statuses.includes('unhealthy')) {
      return 'unhealthy';
    }
    
    // If any check is degraded, system is degraded
    if (statuses.includes('degraded')) {
      return 'degraded';
    }
    
    // All checks healthy
    return 'healthy';
  }

  /**
   * Get service uptime
   */
  getUptime() {
    const uptimeMs = Date.now() - this.startTime;
    return {
      milliseconds: uptimeMs,
      seconds: Math.floor(uptimeMs / 1000),
      human: this.formatUptime(uptimeMs),
    };
  }

  /**
   * Format uptime in human readable format
   */
  formatUptime(milliseconds) {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) {
      return `${days}d ${hours % 24}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Get list of enabled features
   */
  getEnabledFeatures() {
    const features = [
      'authentication',
      'metrics',
      'alerts',
      'autoTriaging',
      'patternDetection',
      'anomalyDetection',
      'realTimeAnalytics',
      'reporting',
      'cache',
      'backup',
    ];

    return features.filter(feature => this.config.isFeatureEnabled(feature));
  }

  /**
   * Get detailed health information (admin only)
   */
  async getDetailedHealth(request, context, user) {
    // Check admin permissions
    if (user.role !== 'admin') {
      return ErrorHandler.authorizationError('Admin access required');
    }

    try {
      const basicHealth = await this.getHealth(request, context);
      const basicData = await basicHealth.json();

      // Add detailed diagnostic information
      const detailedInfo = {
        ...basicData,
        diagnostics: {
          configuration: this.config.toObject(),
          runtime: {
            userAgent: request.headers.get('User-Agent'),
            cfRay: request.headers.get('CF-Ray'),
            cfIpCountry: request.headers.get('CF-IPCountry'),
          },
          limits: {
            rateLimits: this.config.rateLimits,
            logLimits: this.config.logs,
          },
          integrations: this.config.integrations,
        },
      };

      return ErrorHandler.success(detailedInfo);

    } catch (error) {
      context.logger.error('Detailed health check failed', {
        error: error.message,
        userId: user.id,
      });
      throw error;
    }
  }

  /**
   * Get simple readiness probe
   */
  async getReadiness(request, context) {
    try {
      // Quick checks for readiness
      const ready = !!(this.env.LOGS_KV && this.env.LOGS_DB);
      
      const response = {
        ready,
        timestamp: new Date().toISOString(),
      };

      return new Response(JSON.stringify(response), {
        status: ready ? 200 : 503,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
        },
      });

    } catch (error) {
      return new Response(JSON.stringify({
        ready: false,
        error: error.message,
        timestamp: new Date().toISOString(),
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  /**
   * Get simple liveness probe
   */
  async getLiveness(request, context) {
    // Basic liveness - if we can respond, we're alive
    return new Response(JSON.stringify({
      alive: true,
      timestamp: new Date().toISOString(),
      uptime: this.getUptime(),
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache',
      },
    });
  }
}