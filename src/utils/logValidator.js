/**
 * Log Validator - Validates log payloads and query parameters
 * Ensures data integrity and security for log operations
 */

import Joi from 'joi';

export class LogValidator {
  constructor(config) {
    this.config = config;
    this.initializeSchemas();
  }

  /**
   * Initialize validation schemas
   */
  initializeSchemas() {
    // Log payload schema
    this.logPayloadSchema = Joi.object({
      // Required fields
      message: Joi.string().required().max(10000).trim(),
      severity: Joi.string().valid('debug', 'info', 'warn', 'error', 'fatal').required(),
      timestamp: Joi.string().isoDate().optional().default(() => new Date().toISOString()),
      
      // Categorization fields
      environment: Joi.string().valid('development', 'staging', 'production').optional(),
      source: Joi.string().valid('ui', 'logic', 'backend', 'external').optional(),
      component: Joi.string().max(100).alphanum().optional(),
      endpoint: Joi.string().max(500).optional(),
      
      // Error details
      errorType: Joi.string().valid('error', 'exception', 'warning', 'info').optional(),
      errorCode: Joi.string().max(50).alphanum().optional(),
      stackTrace: Joi.string().max(50000).optional(),
      
      // Context information
      userId: Joi.string().max(100).optional(),
      sessionId: Joi.string().max(100).optional(),
      requestId: Joi.string().max(100).optional(),
      userAgent: Joi.string().max(500).optional(),
      ipAddress: Joi.string().ip({ version: ['ipv4', 'ipv6'] }).optional(),
      
      // Additional metadata
      metadata: Joi.object().max(50).optional(),
      tags: Joi.array().items(Joi.string().max(50)).max(20).optional(),
      
      // Performance data
      duration: Joi.number().positive().optional(),
      memoryUsage: Joi.number().positive().optional(),
      
      // Business context
      feature: Joi.string().max(100).optional(),
      workflow: Joi.string().max(100).optional(),
      version: Joi.string().max(50).optional(),
    });

    // Query parameters schema
    this.queryParamsSchema = Joi.object({
      page: Joi.number().integer().min(1).max(10000).default(1),
      limit: Joi.number().integer().min(1).max(1000).default(50),
      
      severity: Joi.string().valid('debug', 'info', 'warn', 'error', 'fatal').optional(),
      category: Joi.string().max(100).optional(),
      source: Joi.string().valid('ui', 'logic', 'backend', 'external').optional(),
      component: Joi.string().max(100).optional(),
      endpoint: Joi.string().max(500).optional(),
      environment: Joi.string().valid('development', 'staging', 'production').optional(),
      
      startTime: Joi.string().isoDate().optional(),
      endTime: Joi.string().isoDate().optional(),
      
      sortBy: Joi.string().valid('timestamp', 'severity', 'component', 'endpoint').default('timestamp'),
      sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
      
      userId: Joi.string().max(100).optional(),
      sessionId: Joi.string().max(100).optional(),
      tags: Joi.array().items(Joi.string().max(50)).max(10).optional(),
    });

    // Search criteria schema
    this.searchCriteriaSchema = Joi.object({
      // Basic search
      query: Joi.string().max(1000).optional(),
      
      // Advanced filters
      filters: Joi.object({
        severity: Joi.array().items(Joi.string().valid('debug', 'info', 'warn', 'error', 'fatal')).optional(),
        source: Joi.array().items(Joi.string().valid('ui', 'logic', 'backend', 'external')).optional(),
        environment: Joi.array().items(Joi.string().valid('development', 'staging', 'production')).optional(),
        component: Joi.array().items(Joi.string().max(100)).optional(),
        endpoint: Joi.array().items(Joi.string().max(500)).optional(),
        errorCode: Joi.array().items(Joi.string().max(50)).optional(),
        userId: Joi.array().items(Joi.string().max(100)).optional(),
        tags: Joi.array().items(Joi.string().max(50)).optional(),
      }).optional(),
      
      // Time range
      timeRange: Joi.object({
        startTime: Joi.string().isoDate().required(),
        endTime: Joi.string().isoDate().required(),
      }).optional(),
      
      // Sorting and pagination
      sort: Joi.object({
        field: Joi.string().valid('timestamp', 'severity', 'component', 'endpoint').default('timestamp'),
        order: Joi.string().valid('asc', 'desc').default('desc'),
      }).optional(),
      
      pagination: Joi.object({
        page: Joi.number().integer().min(1).max(10000).default(1),
        limit: Joi.number().integer().min(1).max(1000).default(50),
      }).optional(),
      
      // Advanced options
      facets: Joi.array().items(
        Joi.string().valid('severity', 'source', 'environment', 'component', 'endpoint')
      ).optional(),
      
      highlight: Joi.boolean().default(false),
      includeContext: Joi.boolean().default(false),
      
      // Scope control
      global: Joi.boolean().default(false),
      domains: Joi.array().items(Joi.string().max(100)).optional(),
    });
  }

  /**
   * Validate log payload
   */
  validateLogPayload(payload) {
    try {
      const { error, value } = this.logPayloadSchema.validate(payload, {
        abortEarly: false,
        stripUnknown: true,
        convert: true,
      });

      if (error) {
        return {
          valid: false,
          errors: error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message,
            value: detail.context?.value,
          })),
        };
      }

      // Additional business logic validation
      const businessValidation = this.validateBusinessRules(value);
      if (!businessValidation.valid) {
        return businessValidation;
      }

      return {
        valid: true,
        data: value,
      };

    } catch (error) {
      return {
        valid: false,
        errors: [{ message: 'Validation failed', error: error.message }],
      };
    }
  }

  /**
   * Validate query parameters
   */
  validateQueryParams(params) {
    try {
      const { error, value } = this.queryParamsSchema.validate(params, {
        abortEarly: false,
        stripUnknown: true,
        convert: true,
      });

      if (error) {
        return {
          valid: false,
          errors: error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message,
            value: detail.context?.value,
          })),
        };
      }

      // Validate time range if provided
      if (value.startTime && value.endTime) {
        const start = new Date(value.startTime);
        const end = new Date(value.endTime);
        
        if (start >= end) {
          return {
            valid: false,
            errors: [{ message: 'startTime must be before endTime' }],
          };
        }

        // Check time range doesn't exceed maximum
        const maxRange = 90 * 24 * 60 * 60 * 1000; // 90 days
        if (end - start > maxRange) {
          return {
            valid: false,
            errors: [{ message: 'Time range cannot exceed 90 days' }],
          };
        }
      }

      return {
        valid: true,
        data: value,
      };

    } catch (error) {
      return {
        valid: false,
        errors: [{ message: 'Validation failed', error: error.message }],
      };
    }
  }

  /**
   * Validate search criteria
   */
  validateSearchCriteria(criteria) {
    try {
      const { error, value } = this.searchCriteriaSchema.validate(criteria, {
        abortEarly: false,
        stripUnknown: true,
        convert: true,
      });

      if (error) {
        return {
          valid: false,
          errors: error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message,
            value: detail.context?.value,
          })),
        };
      }

      // Validate search complexity
      const complexityValidation = this.validateSearchComplexity(value);
      if (!complexityValidation.valid) {
        return complexityValidation;
      }

      return {
        valid: true,
        data: value,
      };

    } catch (error) {
      return {
        valid: false,
        errors: [{ message: 'Validation failed', error: error.message }],
      };
    }
  }

  /**
   * Validate business rules for log payloads
   */
  validateBusinessRules(payload) {
    const errors = [];

    // Critical and error logs should have more context
    if (['error', 'fatal'].includes(payload.severity)) {
      if (!payload.stackTrace && !payload.errorCode) {
        errors.push({
          field: 'errorContext',
          message: 'Error and fatal logs should include stackTrace or errorCode',
        });
      }
    }

    // Production logs should not contain sensitive information in message
    if (payload.environment === 'production') {
      const sensitivePatterns = [
        /password/i,
        /token/i,
        /secret/i,
        /key/i,
        /credential/i,
        /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, // Credit card pattern
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email pattern
      ];

      for (const pattern of sensitivePatterns) {
        if (pattern.test(payload.message)) {
          errors.push({
            field: 'message',
            message: 'Message should not contain sensitive information in production',
          });
          break;
        }
      }
    }

    // Check message size for performance
    if (payload.message.length > 5000) {
      errors.push({
        field: 'message',
        message: 'Message is too long for optimal performance',
      });
    }

    // Validate metadata size
    if (payload.metadata) {
      const metadataSize = JSON.stringify(payload.metadata).length;
      if (metadataSize > 10000) {
        errors.push({
          field: 'metadata',
          message: 'Metadata size exceeds limit',
        });
      }
    }

    return errors.length > 0 
      ? { valid: false, errors }
      : { valid: true };
  }

  /**
   * Validate search complexity to prevent performance issues
   */
  validateSearchComplexity(criteria) {
    const errors = [];

    // Check number of filters
    const filterCount = criteria.filters ? 
      Object.keys(criteria.filters).length : 0;
    
    if (filterCount > 10) {
      errors.push({
        field: 'filters',
        message: 'Too many filters specified (maximum 10)',
      });
    }

    // Check facet count
    if (criteria.facets && criteria.facets.length > 5) {
      errors.push({
        field: 'facets',
        message: 'Too many facets requested (maximum 5)',
      });
    }

    // Check query length
    if (criteria.query && criteria.query.length > 1000) {
      errors.push({
        field: 'query',
        message: 'Search query is too long (maximum 1000 characters)',
      });
    }

    // Check pagination limits
    if (criteria.pagination) {
      const { page, limit } = criteria.pagination;
      if (page * limit > 100000) {
        errors.push({
          field: 'pagination',
          message: 'Cannot retrieve more than 100,000 results',
        });
      }
    }

    return errors.length > 0 
      ? { valid: false, errors }
      : { valid: true };
  }

  /**
   * Sanitize log message to remove potentially harmful content
   */
  sanitizeMessage(message) {
    // Remove potential script tags
    let sanitized = message.replace(/<script[^>]*>.*?<\/script>/gi, '[SCRIPT_REMOVED]');
    
    // Remove other potentially harmful HTML
    sanitized = sanitized.replace(/<[^>]*>/g, '');
    
    // Trim whitespace
    sanitized = sanitized.trim();
    
    // Limit length
    if (sanitized.length > 10000) {
      sanitized = sanitized.substring(0, 10000) + '... [TRUNCATED]';
    }
    
    return sanitized;
  }

  /**
   * Validate and sanitize metadata object
   */
  sanitizeMetadata(metadata) {
    if (!metadata || typeof metadata !== 'object') {
      return {};
    }

    const sanitized = {};
    const maxKeys = 50;
    let keyCount = 0;

    for (const [key, value] of Object.entries(metadata)) {
      if (keyCount >= maxKeys) break;
      
      // Validate key
      if (typeof key === 'string' && key.length <= 100) {
        // Sanitize value based on type
        if (typeof value === 'string') {
          sanitized[key] = value.substring(0, 1000);
        } else if (typeof value === 'number' || typeof value === 'boolean') {
          sanitized[key] = value;
        } else if (value === null) {
          sanitized[key] = null;
        }
        // Skip complex objects and functions
      }
      
      keyCount++;
    }

    return sanitized;
  }
}