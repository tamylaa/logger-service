/**
 * Integration Handler - Manages cross-service integration endpoints
 * Provides API endpoints for service registration, communication, and coordination
 */

import { Logger } from '../utils/logger.js';
import { ErrorHandler } from '../utils/errorHandler.js';
import { IntegrationManager } from './serviceClients.js';

export class IntegrationHandler {
  constructor(config, logStorage, metrics) {
    this.config = config;
    this.storage = logStorage;
    this.metrics = metrics;
    this.logger = new Logger('IntegrationHandler');
    
    // Initialize integration manager
    this.integrationManager = new IntegrationManager(config);
    
    // Service registry for dynamic service discovery
    this.serviceRegistry = new Map();
    
    // Integration webhooks
    this.webhooks = new Map();
  }

  /**
   * Handle service registration
   */
  async registerService(request, env, ctx) {
    try {
      const body = await request.json();
      const { 
        serviceName, 
        serviceUrl, 
        apiKey, 
        version, 
        capabilities = [],
        healthEndpoint = '/health' 
      } = body;

      // Validate required fields
      if (!serviceName || !serviceUrl) {
        throw ErrorHandler.createError(
          'INVALID_REQUEST',
          'Service name and URL are required',
          400
        );
      }

      // Validate admin access
      if (!ctx.user?.isAdmin) {
        throw ErrorHandler.createError(
          'FORBIDDEN',
          'Admin access required for service registration',
          403
        );
      }

      // Register service
      const registration = {
        serviceName,
        serviceUrl,
        apiKey,
        version,
        capabilities,
        healthEndpoint,
        registeredAt: new Date().toISOString(),
        registeredBy: ctx.user.id,
        status: 'registered',
      };

      this.serviceRegistry.set(serviceName, registration);

      // Test connectivity
      const healthCheck = await this.testServiceConnectivity(serviceName, registration);
      registration.lastHealthCheck = healthCheck;
      registration.status = healthCheck.healthy ? 'active' : 'unreachable';

      this.logger.info('Service registered successfully', {
        serviceName,
        serviceUrl,
        version,
        capabilities,
        healthy: healthCheck.healthy,
      });

      return new Response(JSON.stringify({
        success: true,
        registration,
        message: `Service ${serviceName} registered successfully`,
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Service registration failed', { error: error.message });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Handle service deregistration
   */
  async deregisterService(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const serviceName = url.pathname.split('/').pop();

      if (!ctx.user?.isAdmin) {
        throw ErrorHandler.createError('FORBIDDEN', 'Admin access required', 403);
      }

      if (!this.serviceRegistry.has(serviceName)) {
        throw ErrorHandler.createError(
          'NOT_FOUND',
          `Service ${serviceName} not found`,
          404
        );
      }

      const registration = this.serviceRegistry.get(serviceName);
      this.serviceRegistry.delete(serviceName);

      this.logger.info('Service deregistered', {
        serviceName,
        deregisteredBy: ctx.user.id,
      });

      return new Response(JSON.stringify({
        success: true,
        message: `Service ${serviceName} deregistered successfully`,
        registration,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Service deregistration failed', { error: error.message });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * List registered services
   */
  async listServices(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const includeHealth = url.searchParams.get('includeHealth') === 'true';

      const services = {};
      
      for (const [name, registration] of this.serviceRegistry.entries()) {
        services[name] = {
          ...registration,
          apiKey: undefined, // Don't expose API keys
        };

        // Include health check if requested
        if (includeHealth) {
          const health = await this.testServiceConnectivity(name, registration);
          services[name].currentHealth = health;
        }
      }

      return new Response(JSON.stringify({
        success: true,
        services,
        count: this.serviceRegistry.size,
        integrationStats: this.integrationManager.getIntegrationStats(),
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Failed to list services', { error: error.message });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Handle cross-service logging
   */
  async handleCrossServiceLog(request, env, ctx) {
    try {
      const body = await request.json();
      const {
        sourceService,
        targetService,
        operation,
        data,
        correlationId,
      } = body;

      // Validate source service
      if (!this.serviceRegistry.has(sourceService)) {
        throw ErrorHandler.createError(
          'INVALID_SERVICE',
          `Unknown source service: ${sourceService}`,
          400
        );
      }

      // Create cross-service log entry
      const logEntry = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        level: 'info',
        message: `Cross-service operation: ${operation}`,
        category: 'integration',
        component: 'cross-service',
        sourceService,
        targetService,
        operation,
        data: this.sanitizeLogData(data),
        correlationId,
        userId: ctx.user?.id,
      };

      // Store the log
      await this.storage.storeLog(logEntry);

      // Process with integrations if enabled
      if (this.config.features?.crossServiceIntegration) {
        const integrationResult = await this.integrationManager.processLogWithIntegrations(logEntry);
        logEntry.integrationResult = integrationResult.integrationResults;
      }

      this.metrics.recordCrossServiceLog(sourceService, targetService, operation);

      return new Response(JSON.stringify({
        success: true,
        logId: logEntry.id,
        message: 'Cross-service log recorded successfully',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Cross-service logging failed', { error: error.message });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Handle webhook registration
   */
  async registerWebhook(request, env, ctx) {
    try {
      const body = await request.json();
      const {
        webhookId,
        url,
        events = [],
        secret,
        active = true,
      } = body;

      if (!ctx.user?.isAdmin) {
        throw ErrorHandler.createError('FORBIDDEN', 'Admin access required', 403);
      }

      if (!webhookId || !url) {
        throw ErrorHandler.createError(
          'INVALID_REQUEST',
          'Webhook ID and URL are required',
          400
        );
      }

      const webhook = {
        id: webhookId,
        url,
        events,
        secret,
        active,
        createdAt: new Date().toISOString(),
        createdBy: ctx.user.id,
        lastTriggered: null,
        totalTriggers: 0,
      };

      this.webhooks.set(webhookId, webhook);

      this.logger.info('Webhook registered', {
        webhookId,
        url,
        events,
        createdBy: ctx.user.id,
      });

      return new Response(JSON.stringify({
        success: true,
        webhook: {
          ...webhook,
          secret: undefined, // Don't expose secret
        },
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Webhook registration failed', { error: error.message });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Trigger webhooks for events
   */
  async triggerWebhooks(event, data) {
    const triggeredWebhooks = [];

    for (const [id, webhook] of this.webhooks.entries()) {
      if (!webhook.active || !webhook.events.includes(event)) {
        continue;
      }

      try {
        await this.callWebhook(webhook, event, data);
        
        webhook.lastTriggered = new Date().toISOString();
        webhook.totalTriggers++;
        
        triggeredWebhooks.push(id);
        
        this.logger.debug('Webhook triggered successfully', {
          webhookId: id,
          event,
          url: webhook.url,
        });

      } catch (error) {
        this.logger.error('Webhook trigger failed', {
          webhookId: id,
          event,
          error: error.message,
        });
      }
    }

    return triggeredWebhooks;
  }

  /**
   * Call individual webhook
   */
  async callWebhook(webhook, event, data) {
    const payload = {
      event,
      timestamp: new Date().toISOString(),
      data,
      source: 'logger-service',
    };

    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': 'Logger-Service-Webhook/1.0',
    };

    // Add signature if secret is provided
    if (webhook.secret) {
      const signature = await this.generateWebhookSignature(
        JSON.stringify(payload),
        webhook.secret
      );
      headers['X-Signature-SHA256'] = signature;
    }

    const response = await fetch(webhook.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Webhook call failed: ${response.status} ${response.statusText}`);
    }

    return response;
  }

  /**
   * Generate webhook signature
   */
  async generateWebhookSignature(payload, secret) {
    const encoder = new TextEncoder();
    const data = encoder.encode(payload);
    const key = encoder.encode(secret);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
    const hashArray = Array.from(new Uint8Array(signature));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return `sha256=${hashHex}`;
  }

  /**
   * Test service connectivity
   */
  async testServiceConnectivity(serviceName, registration) {
    try {
      const healthUrl = `${registration.serviceUrl}${registration.healthEndpoint}`;
      const headers = {};
      
      if (registration.apiKey) {
        headers['Authorization'] = `Bearer ${registration.apiKey}`;
      }

      const response = await fetch(healthUrl, {
        method: 'GET',
        headers,
        signal: AbortSignal.timeout(5000), // 5 second timeout
      });

      const responseData = response.ok ? await response.json() : null;

      return {
        healthy: response.ok,
        status: response.status,
        responseTime: Date.now(), // Would need actual timing
        data: responseData,
        timestamp: new Date().toISOString(),
      };

    } catch (error) {
      return {
        healthy: false,
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Sanitize log data for cross-service communication
   */
  sanitizeLogData(data) {
    if (!data || typeof data !== 'object') {
      return data;
    }

    const sanitized = { ...data };
    
    // Remove sensitive fields
    const sensitiveFields = ['password', 'token', 'secret', 'key', 'credential'];
    
    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    }

    // Recursively sanitize nested objects
    for (const [key, value] of Object.entries(sanitized)) {
      if (value && typeof value === 'object') {
        sanitized[key] = this.sanitizeLogData(value);
      }
    }

    return sanitized;
  }

  /**
   * Get integration metrics
   */
  async getIntegrationMetrics(request, env, ctx) {
    try {
      if (!ctx.user?.isAdmin) {
        throw ErrorHandler.createError('FORBIDDEN', 'Admin access required', 403);
      }

      const metrics = {
        serviceRegistry: {
          totalServices: this.serviceRegistry.size,
          activeServices: 0,
          unhealthyServices: 0,
        },
        webhooks: {
          totalWebhooks: this.webhooks.size,
          activeWebhooks: 0,
          totalTriggers: 0,
        },
        integration: this.integrationManager.getIntegrationStats(),
        serviceHealth: this.integrationManager.getServiceHealth(),
      };

      // Calculate service health metrics
      for (const registration of this.serviceRegistry.values()) {
        if (registration.status === 'active') {
          metrics.serviceRegistry.activeServices++;
        } else if (registration.status === 'unreachable') {
          metrics.serviceRegistry.unhealthyServices++;
        }
      }

      // Calculate webhook metrics
      for (const webhook of this.webhooks.values()) {
        if (webhook.active) {
          metrics.webhooks.activeWebhooks++;
        }
        metrics.webhooks.totalTriggers += webhook.totalTriggers;
      }

      return new Response(JSON.stringify(metrics), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Failed to get integration metrics', { error: error.message });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Health check endpoint
   */
  async getIntegrationHealth(request, env, ctx) {
    try {
      const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        services: this.integrationManager.getServiceHealth(),
        integrationManager: {
          running: true,
          servicesMonitored: this.serviceRegistry.size,
        },
        webhooks: {
          registered: this.webhooks.size,
          active: Array.from(this.webhooks.values()).filter(w => w.active).length,
        },
      };

      // Determine overall health status
      const unhealthyServices = Object.values(health.services)
        .filter(service => !service.healthy).length;
      
      if (unhealthyServices > 0) {
        health.status = unhealthyServices > Object.keys(health.services).length / 2 
          ? 'unhealthy' 
          : 'degraded';
        health.issues = `${unhealthyServices} service(s) unhealthy`;
      }

      const status = health.status === 'healthy' ? 200 : 503;

      return new Response(JSON.stringify(health), {
        status,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      this.logger.error('Integration health check failed', { error: error.message });
      return new Response(JSON.stringify({
        status: 'error',
        error: error.message,
        timestamp: new Date().toISOString(),
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  /**
   * Shutdown handler
   */
  async shutdown() {
    this.logger.info('Shutting down integration handler');
    
    if (this.integrationManager) {
      await this.integrationManager.shutdown();
    }
    
    this.serviceRegistry.clear();
    this.webhooks.clear();
  }
}