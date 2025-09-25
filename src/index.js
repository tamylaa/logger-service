/**
 * Main entry point for the Logger Service Cloudflare Worker
 * Handles log ingestion, categorization, and smart triaging
 */

import { Router } from './worker/router.js';
import { Config } from './config/config.js';
import { Logger } from './utils/logger.js';
import { ErrorHandler } from './utils/errorHandler.js';
import { Metrics } from './monitoring/metrics.js';
import { LogStorage } from './storage/logStorage.js';

// Global error handling
addEventListener('unhandledrejection', event => {
  Logger.error('Unhandled promise rejection:', event.reason);
  event.preventDefault();
});

/**
 * Main fetch handler for the Cloudflare Worker
 */
export default {
  async fetch(request, env, ctx) {
    const startTime = Date.now();
    const config = new Config(env);
    const logger = new Logger(config);
    const metrics = new Metrics(config, env.LOGS_KV);
    const logStorage = new LogStorage(env.LOGS_KV, env.LOGS_DB);
    const router = new Router(config, env, logStorage, metrics);

    try {
      // Initialize request context
      const requestId = crypto.randomUUID();
      const context = {
        requestId,
        startTime,
        config,
        logger,
        metrics,
        env,
        ctx,
      };

      // Log incoming request
      logger.info('Incoming request', {
        requestId,
        method: request.method,
        url: request.url,
        userAgent: request.headers.get('User-Agent'),
      });

      // Route the request
      const response = await router.handle(request, context);

      // Log successful response
      const duration = Date.now() - startTime;
      logger.info('Request completed', {
        requestId,
        status: response.status,
        duration,
      });

      // Record metrics
      await metrics.recordRequest(request.method, response.status, duration);

      return response;

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Request failed', {
        error: error.message,
        stack: error.stack,
        duration,
      });

      // Record error metrics
      await metrics.recordError(error);

      // Return error response
      return ErrorHandler.handleError(error, logger);
    }
  },

  /**
   * Scheduled event handler for background tasks
   */
  async scheduled(event, env, ctx) {
    const config = new Config(env);
    const logger = new Logger(config);

    try {
      logger.info('Scheduled task started', { cron: event.cron });

      // Run background tasks based on schedule
      if (event.cron === '0 0 * * *') { // Daily at midnight
        await this.runDailyMaintenance(env, logger);
      } else if (event.cron === '*/5 * * * *') { // Every 5 minutes
        await this.runHealthChecks(env, logger);
      }

      logger.info('Scheduled task completed');
    } catch (error) {
      logger.error('Scheduled task failed', {
        error: error.message,
        stack: error.stack,
      });
      throw error;
    }
  },

  /**
   * Daily maintenance tasks
   */
  async runDailyMaintenance(env, logger) {
    const config = new Config(env);
    
    // Clean up old logs
    logger.info('Starting daily maintenance');
    
    // TODO: Implement log cleanup based on retention policy
    // TODO: Generate daily analytics reports
    // TODO: Perform health checks on storage systems
  },

  /**
   * Regular health checks
   */
  async runHealthChecks(env, logger) {
    // TODO: Check KV and D1 database connectivity
    // TODO: Monitor memory usage and performance
    // TODO: Validate service dependencies
  },
};