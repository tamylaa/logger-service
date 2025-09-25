/**
 * Router for handling HTTP requests to different endpoints
 * Implements RESTful API for log management
 */

import { LogHandler } from '../handlers/logHandler.js';
import { HealthHandler } from '../handlers/healthHandler.js';
import { AnalyticsHandler } from '../handlers/analyticsHandler.js';
import { IntegrationHandler } from '../handlers/integrationHandler.js';
import { RateLimiter } from '../middleware/rateLimiter.js';
import { AuthMiddleware } from '../middleware/auth.js';
import { CorsMiddleware } from '../middleware/cors.js';
import { ErrorHandler } from '../utils/errorHandler.js';
import { DomainManager } from '../utils/domainManager.js';
import { AdvancedAnalyticsEngine } from '../processors/advancedAnalytics.js';
import { SelfHealingSystem } from '../processors/selfHealingSystem.js';

export class Router {
  constructor(config, env, logStorage, metrics) {
    this.config = config;
    this.env = env;
    this.rateLimiter = new RateLimiter(config, env.LOGS_KV);
    this.authMiddleware = new AuthMiddleware(config);
    this.corsMiddleware = new CorsMiddleware(config);
    
    // Initialize enhanced systems
    this.domainManager = new DomainManager(config);
    this.advancedAnalytics = new AdvancedAnalyticsEngine(logStorage, config);
    this.selfHealing = new SelfHealingSystem(config, logStorage, null);
    
    // Initialize handlers
    this.logHandler = new LogHandler(logStorage, config, metrics);
    this.healthHandler = new HealthHandler(config, logStorage, metrics);
    this.analyticsHandler = new AnalyticsHandler(logStorage, config, metrics);
    this.integrationHandler = new IntegrationHandler(config, logStorage, metrics);
  }

  /**
   * Handle incoming HTTP requests
   */
  async handle(request, context) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Apply CORS middleware
    const corsResponse = await this.corsMiddleware.handle(request);
    if (corsResponse) {
      return corsResponse;
    }

    // Extract domain context for multi-tenant support
    try {
      const domainContext = await this.domainManager.extractDomainContext(request);
      context.domain = domainContext;
    } catch (error) {
      // Log domain extraction error but continue with default context
      context.logger.warn('Domain context extraction failed', { error: error.message });
    }

    // Route to appropriate handler
    try {
      if (path === '/health' && method === 'GET') {
        return await this.handleHealth(request, context);
      }

      if (path === '/logs' && method === 'POST') {
        return await this.handleLogSubmission(request, context);
      }

      if (path === '/logs' && method === 'GET') {
        return await this.handleLogRetrieval(request, context);
      }

      if (path === '/logs/search' && method === 'POST') {
        return await this.handleLogSearch(request, context);
      }

      if (path === '/analytics/summary' && method === 'GET') {
        return await this.handleAnalyticsSummary(request, context);
      }

      if (path === '/analytics/patterns' && method === 'GET') {
        return await this.handleAnalyticsPatterns(request, context);
      }

      if (path === '/analytics/trends' && method === 'GET') {
        return await this.handleAnalyticsTrends(request, context);
      }

      if (path === '/metrics' && method === 'GET') {
        return await this.handleMetrics(request, context);
      }

      // Integration endpoints
      if (path === '/integration/services' && method === 'POST') {
        return await this.handleServiceRegistration(request, context);
      }

      if (path.startsWith('/integration/services/') && method === 'DELETE') {
        return await this.handleServiceDeregistration(request, context);
      }

      if (path === '/integration/services' && method === 'GET') {
        return await this.handleServiceList(request, context);
      }

      if (path === '/integration/cross-service' && method === 'POST') {
        return await this.handleCrossServiceLog(request, context);
      }

      if (path === '/integration/webhooks' && method === 'POST') {
        return await this.handleWebhookRegistration(request, context);
      }

      if (path === '/integration/metrics' && method === 'GET') {
        return await this.handleIntegrationMetrics(request, context);
      }

      if (path === '/integration/health' && method === 'GET') {
        return await this.handleIntegrationHealth(request, context);
      }

      // Enhanced analytics endpoints
      if (path === '/analytics/insights' && method === 'GET') {
        return await this.handleProactiveInsights(request, context);
      }

      // Domain management endpoints
      if (path === '/admin/domains' && method === 'POST') {
        return await this.handleDomainRegistration(request, context);
      }

      if (path === '/admin/domains' && method === 'GET') {
        return await this.handleDomainList(request, context);
      }

      // Self-healing endpoints
      if (path === '/admin/self-healing' && method === 'GET') {
        return await this.handleSelfHealingStatus(request, context);
      }

      if (path === '/admin/self-healing/actions' && method === 'POST') {
        return await this.handleSelfHealingAction(request, context);
      }

      // 404 for unknown routes
      return ErrorHandler.notFound(`Endpoint not found: ${method} ${path}`);

    } catch (error) {
      context.logger.error('Router error', {
        path,
        method,
        error: error.message,
        requestId: context.requestId,
      });
      throw error;
    }
  }

  /**
   * Handle health check requests
   */
  async handleHealth(request, context) {
    return await this.healthHandler.getHealth(request, this.env, context);
  }

  /**
   * Handle log submission with rate limiting and authentication
   */
  async handleLogSubmission(request, context) {
    // Apply rate limiting
    const rateLimitResult = await this.rateLimiter.checkLimit(request, context);
    if (!rateLimitResult.allowed) {
      return ErrorHandler.rateLimitExceeded(rateLimitResult);
    }

    // Apply authentication
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    // Handle log submission
    context.user = authResult.user;
    return await this.logHandler.submitLog(request, this.env, context);
  }

  /**
   * Handle log retrieval with authentication
   */
  async handleLogRetrieval(request, context) {
    // Apply authentication
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    // Handle log retrieval
    context.user = authResult.user;
    return await this.logHandler.retrieveLogs(request, this.env, context);
  }

  /**
   * Handle log search with authentication
   */
  async handleLogSearch(request, context) {
    // Apply rate limiting for search operations
    const rateLimitResult = await this.rateLimiter.checkLimit(request, context, 'search');
    if (!rateLimitResult.allowed) {
      return ErrorHandler.rateLimitExceeded(rateLimitResult);
    }

    // Apply authentication
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    // Handle log search
    context.user = authResult.user;
    return await this.logHandler.searchLogs(request, this.env, context);
  }

  /**
   * Handle analytics summary requests
   */
  async handleAnalyticsSummary(request, context) {
    // Apply authentication
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    // Handle analytics
    context.user = authResult.user;
    return await this.analyticsHandler.getAnalytics(request, this.env, context);
  }

  /**
   * Handle analytics patterns requests
   */
  async handleAnalyticsPatterns(request, context) {
    // Apply authentication
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    // Handle pattern analysis
    context.user = authResult.user;
    return await this.analyticsHandler.getPatterns(request, this.env, context);
  }

  /**
   * Handle analytics trends requests
   */
  async handleAnalyticsTrends(request, context) {
    // Apply authentication
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    // Handle trend analysis
    context.user = authResult.user;
    return await this.analyticsHandler.getTrends(request, this.env, context);
  }

  /**
   * Handle metrics requests
   */
  async handleMetrics(request, context) {
    // Apply authentication
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    // Return metrics
    const metrics = await context.metrics.getMetrics();
    return new Response(JSON.stringify(metrics), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Integration endpoints

  /**
   * Handle service registration
   */
  async handleServiceRegistration(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    context.user = authResult.user;
    return await this.integrationHandler.registerService(request, this.env, context);
  }

  /**
   * Handle service deregistration
   */
  async handleServiceDeregistration(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    context.user = authResult.user;
    return await this.integrationHandler.deregisterService(request, this.env, context);
  }

  /**
   * Handle service list
   */
  async handleServiceList(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    context.user = authResult.user;
    return await this.integrationHandler.listServices(request, this.env, context);
  }

  /**
   * Handle cross-service logging
   */
  async handleCrossServiceLog(request, context) {
    // Apply rate limiting
    const rateLimitResult = await this.rateLimiter.checkLimit(request, context);
    if (!rateLimitResult.allowed) {
      return ErrorHandler.rateLimitExceeded(rateLimitResult);
    }

    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    context.user = authResult.user;
    return await this.integrationHandler.handleCrossServiceLog(request, this.env, context);
  }

  /**
   * Handle webhook registration
   */
  async handleWebhookRegistration(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    context.user = authResult.user;
    return await this.integrationHandler.registerWebhook(request, this.env, context);
  }

  /**
   * Handle integration metrics
   */
  async handleIntegrationMetrics(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    context.user = authResult.user;
    return await this.integrationHandler.getIntegrationMetrics(request, this.env, context);
  }

  /**
   * Handle integration health
   */
  async handleIntegrationHealth(request, context) {
    return await this.integrationHandler.getIntegrationHealth(request, this.env, context);
  }

  // Enhanced Analytics endpoints

  /**
   * Handle proactive insights request
   */
  async handleProactiveInsights(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success) {
      return ErrorHandler.unauthorized(authResult.error);
    }

    try {
      const url = new URL(request.url);
      const timeframe = url.searchParams.get('timeframe') || '24h';
      const domain = context.domain?.domain || 'default';

      // Calculate time range
      const timeRange = this.calculateTimeRange(timeframe);

      // Generate insights
      const insights = await this.advancedAnalytics.generateProactiveInsights(timeRange, domain);

      return new Response(JSON.stringify(insights, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      context.logger.error('Failed to generate proactive insights', {
        error: error.message,
      });
      throw ErrorHandler.handleError(error);
    }
  }

  // Domain Management endpoints

  /**
   * Handle domain registration
   */
  async handleDomainRegistration(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success || !authResult.user?.isAdmin) {
      return ErrorHandler.unauthorized('Admin access required');
    }

    try {
      const domainData = await request.json();
      const result = await this.domainManager.registerDomain(domainData);

      return new Response(JSON.stringify(result), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      context.logger.error('Domain registration failed', {
        error: error.message,
      });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Handle domain list request
   */
  async handleDomainList(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success || !authResult.user?.isAdmin) {
      return ErrorHandler.unauthorized('Admin access required');
    }

    try {
      const domains = this.domainManager.getAllDomains();
      const stats = this.domainManager.getDomainStats();

      return new Response(JSON.stringify({
        domains,
        stats,
        timestamp: new Date().toISOString(),
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      context.logger.error('Failed to list domains', {
        error: error.message,
      });
      throw ErrorHandler.handleError(error);
    }
  }

  // Self-healing endpoints

  /**
   * Handle self-healing status request
   */
  async handleSelfHealingStatus(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success || !authResult.user?.isAdmin) {
      return ErrorHandler.unauthorized('Admin access required');
    }

    try {
      const status = this.selfHealing.getHealingStatus();

      return new Response(JSON.stringify(status), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      context.logger.error('Failed to get self-healing status', {
        error: error.message,
      });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Handle self-healing action request
   */
  async handleSelfHealingAction(request, context) {
    const authResult = await this.authMiddleware.authenticate(request, context);
    if (!authResult.success || !authResult.user?.isAdmin) {
      return ErrorHandler.unauthorized('Admin access required');
    }

    try {
      const body = await request.json();
      const { action, actionId, ...params } = body;

      let result;
      switch (action) {
        case 'execute':
          result = await this.selfHealing.forceExecuteAction(actionId, 'Manual execution');
          break;
        case 'toggle':
          result = this.selfHealing.toggleHealingAction(actionId, params.enabled);
          break;
        case 'add':
          result = this.selfHealing.addHealingAction(params.actionConfig);
          break;
        case 'remove':
          result = this.selfHealing.removeHealingAction(actionId);
          break;
        default:
          throw new Error(`Unknown action: ${action}`);
      }

      return new Response(JSON.stringify(result), {
        status: result.success ? 200 : 400,
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (error) {
      context.logger.error('Self-healing action failed', {
        error: error.message,
      });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Calculate time range from timeframe string
   */
  calculateTimeRange(timeframe) {
    const now = new Date();
    let start;

    switch (timeframe) {
      case '1h':
        start = new Date(now.getTime() - 60 * 60 * 1000);
        break;
      case '6h':
        start = new Date(now.getTime() - 6 * 60 * 60 * 1000);
        break;
      case '24h':
      case '1d':
        start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }

    return {
      start: start.toISOString(),
      end: now.toISOString(),
    };
  }
}