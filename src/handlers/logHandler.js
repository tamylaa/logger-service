/**
 * Log Handler - Processes log submission, retrieval, and search requests
 * Implements the core logging functionality with categorization and processing
 */

import { LogProcessor } from '../processors/logProcessor.js';
import { LogStorage } from '../storage/logStorage.js';
import { LogValidator } from '../utils/logValidator.js';
import { ErrorHandler } from '../utils/errorHandler.js';

export class LogHandler {
  constructor(config, env) {
    this.config = config;
    this.env = env;
    this.processor = new LogProcessor(config);
    this.storage = new LogStorage(config, env);
    this.validator = new LogValidator(config);
  }

  /**
   * Submit a new log entry
   */
  async submitLog(request, context, user) {
    const { logger, requestId } = context;
    
    try {
      // Parse request body
      const body = await this.parseRequestBody(request);
      
      // Validate log payload
      const validationResult = this.validator.validateLogPayload(body);
      if (!validationResult.valid) {
        throw ErrorHandler.validationError(
          'Invalid log payload',
          validationResult.errors
        );
      }

      // Process and enrich log entry
      const processedLog = await this.processor.processLog(body, user, context);
      
      // Store the log entry
      const storageResult = await this.storage.storeLog(processedLog);
      
      // Log the successful submission
      logger.audit('log_submitted', user.id, processedLog.id, {
        requestId,
        logId: processedLog.id,
        severity: processedLog.severity,
        category: processedLog.category,
        source: processedLog.source,
      });

      // Return success response with log ID
      return ErrorHandler.success({
        logId: processedLog.id,
        message: 'Log submitted successfully',
        category: processedLog.category,
        severity: processedLog.severity,
        triageActions: processedLog.triageActions || [],
      }, 201);

    } catch (error) {
      logger.error('Log submission failed', {
        requestId,
        error: error.message,
        userId: user?.id,
      });
      throw error;
    }
  }

  /**
   * Retrieve logs based on query parameters
   */
  async retrieveLogs(request, context, user) {
    const { logger, requestId } = context;
    
    try {
      const url = new URL(request.url);
      const queryParams = this.parseQueryParams(url.searchParams);
      
      // Validate query parameters
      const validationResult = this.validator.validateQueryParams(queryParams);
      if (!validationResult.valid) {
        throw ErrorHandler.validationError(
          'Invalid query parameters',
          validationResult.errors
        );
      }

      // Check user permissions for the requested data
      const permissionResult = await this.checkRetrievalPermissions(user, queryParams);
      if (!permissionResult.allowed) {
        throw ErrorHandler.authorizationError(permissionResult.reason);
      }

      // Retrieve logs from storage
      const logsResult = await this.storage.retrieveLogs(queryParams, user);

      // Log the retrieval
      logger.audit('logs_retrieved', user.id, 'logs_collection', {
        requestId,
        count: logsResult.data.length,
        filters: queryParams,
      });

      // Return paginated response
      return ErrorHandler.successWithPagination(
        logsResult.data,
        logsResult.pagination
      );

    } catch (error) {
      logger.error('Log retrieval failed', {
        requestId,
        error: error.message,
        userId: user?.id,
      });
      throw error;
    }
  }

  /**
   * Search logs with advanced filters
   */
  async searchLogs(request, context, user) {
    const { logger, requestId } = context;
    
    try {
      // Parse search request body
      const searchCriteria = await this.parseRequestBody(request);
      
      // Validate search criteria
      const validationResult = this.validator.validateSearchCriteria(searchCriteria);
      if (!validationResult.valid) {
        throw ErrorHandler.validationError(
          'Invalid search criteria',
          validationResult.errors
        );
      }

      // Check user permissions for search
      const permissionResult = await this.checkSearchPermissions(user, searchCriteria);
      if (!permissionResult.allowed) {
        throw ErrorHandler.authorizationError(permissionResult.reason);
      }

      // Perform the search
      const searchResult = await this.storage.searchLogs(searchCriteria, user);

      // Log the search operation
      logger.audit('logs_searched', user.id, 'logs_collection', {
        requestId,
        resultCount: searchResult.data.length,
        criteria: searchCriteria,
      });

      // Return search results with metadata
      return ErrorHandler.successWithPagination(
        searchResult.data,
        {
          ...searchResult.pagination,
          searchMeta: {
            executionTime: searchResult.executionTime,
            totalMatches: searchResult.totalMatches,
            facets: searchResult.facets,
          },
        }
      );

    } catch (error) {
      logger.error('Log search failed', {
        requestId,
        error: error.message,
        userId: user?.id,
      });
      throw error;
    }
  }

  /**
   * Parse request body with size limits
   */
  async parseRequestBody(request) {
    const contentType = request.headers.get('Content-Type') || '';
    
    if (!contentType.includes('application/json')) {
      throw ErrorHandler.validationError('Content-Type must be application/json');
    }

    const contentLength = request.headers.get('Content-Length');
    if (contentLength && parseInt(contentLength) > this.config.logs.maxSize) {
      throw ErrorHandler.payloadTooLargeError(
        `Payload size ${contentLength} exceeds maximum ${this.config.logs.maxSize}`
      );
    }

    try {
      const body = await request.json();
      return body;
    } catch (error) {
      throw ErrorHandler.validationError('Invalid JSON payload');
    }
  }

  /**
   * Parse query parameters for log retrieval
   */
  parseQueryParams(searchParams) {
    return {
      // Pagination
      page: parseInt(searchParams.get('page')) || 1,
      limit: Math.min(parseInt(searchParams.get('limit')) || 50, 1000),
      
      // Filtering
      severity: searchParams.get('severity'),
      category: searchParams.get('category'),
      source: searchParams.get('source'),
      component: searchParams.get('component'),
      endpoint: searchParams.get('endpoint'),
      environment: searchParams.get('environment'),
      
      // Time range
      startTime: searchParams.get('startTime'),
      endTime: searchParams.get('endTime'),
      
      // Sorting
      sortBy: searchParams.get('sortBy') || 'timestamp',
      sortOrder: searchParams.get('sortOrder') || 'desc',
      
      // Additional filters
      userId: searchParams.get('userId'),
      sessionId: searchParams.get('sessionId'),
      tags: searchParams.getAll('tags'),
    };
  }

  /**
   * Check user permissions for log retrieval
   */
  async checkRetrievalPermissions(user, queryParams) {
    // Admin users can access all logs
    if (user.role === 'admin') {
      return { allowed: true };
    }

    // Regular users can only access their own logs
    if (queryParams.userId && queryParams.userId !== user.id) {
      return {
        allowed: false,
        reason: 'Cannot access logs for other users',
      };
    }

    // Check domain-specific permissions
    if (queryParams.domain && !user.domains?.includes(queryParams.domain)) {
      return {
        allowed: false,
        reason: 'No permission to access logs for this domain',
      };
    }

    return { allowed: true };
  }

  /**
   * Check user permissions for log search
   */
  async checkSearchPermissions(user, searchCriteria) {
    // Admin users can search all logs
    if (user.role === 'admin') {
      return { allowed: true };
    }

    // Limit search scope for non-admin users
    if (searchCriteria.global && user.role !== 'admin') {
      return {
        allowed: false,
        reason: 'Global search requires admin privileges',
      };
    }

    // Check domain restrictions
    if (searchCriteria.domains) {
      const unauthorizedDomains = searchCriteria.domains.filter(
        domain => !user.domains?.includes(domain)
      );
      
      if (unauthorizedDomains.length > 0) {
        return {
          allowed: false,
          reason: `No permission to search logs for domains: ${unauthorizedDomains.join(', ')}`,
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Get log statistics and summary
   */
  async getLogSummary(request, context, user) {
    const { logger, requestId } = context;
    
    try {
      const url = new URL(request.url);
      const timeRange = {
        startTime: url.searchParams.get('startTime'),
        endTime: url.searchParams.get('endTime'),
      };

      // Get summary from storage
      const summary = await this.storage.getLogSummary(timeRange, user);

      // Log the summary request
      logger.audit('log_summary_requested', user.id, 'logs_collection', {
        requestId,
        timeRange,
      });

      return ErrorHandler.success(summary);

    } catch (error) {
      logger.error('Log summary failed', {
        requestId,
        error: error.message,
        userId: user?.id,
      });
      throw error;
    }
  }
}