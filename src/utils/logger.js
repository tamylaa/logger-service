/**
 * Logger utility for structured logging
 * Provides different log levels and structured output
 */

export class Logger {
  constructor(config) {
    this.config = config;
    this.logLevel = this.getLogLevelNumber(config.service.logLevel);
    this.serviceName = config.service.name;
    this.environment = config.service.environment;
  }

  /**
   * Convert log level string to number for comparison
   */
  getLogLevelNumber(level) {
    const levels = {
      'debug': 10,
      'info': 20,
      'warn': 30,
      'error': 40,
      'fatal': 50,
    };
    return levels[level.toLowerCase()] || 20;
  }

  /**
   * Check if a log level should be output
   */
  shouldLog(level) {
    return this.getLogLevelNumber(level) >= this.logLevel;
  }

  /**
   * Format log message with metadata
   */
  formatLog(level, message, meta = {}) {
    return {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      service: this.serviceName,
      environment: this.environment,
      message,
      ...meta,
    };
  }

  /**
   * Output log to console (Cloudflare Workers logging)
   */
  output(logEntry) {
    const logString = JSON.stringify(logEntry);
    
    switch (logEntry.level) {
      case 'DEBUG':
        console.debug(logString);
        break;
      case 'INFO':
        console.info(logString);
        break;
      case 'WARN':
        console.warn(logString);
        break;
      case 'ERROR':
      case 'FATAL':
        console.error(logString);
        break;
      default:
        console.log(logString);
    }
  }

  /**
   * Debug level logging
   */
  debug(message, meta = {}) {
    if (this.shouldLog('debug')) {
      const logEntry = this.formatLog('debug', message, meta);
      this.output(logEntry);
      return logEntry;
    }
  }

  /**
   * Info level logging
   */
  info(message, meta = {}) {
    if (this.shouldLog('info')) {
      const logEntry = this.formatLog('info', message, meta);
      this.output(logEntry);
      return logEntry;
    }
  }

  /**
   * Warning level logging
   */
  warn(message, meta = {}) {
    if (this.shouldLog('warn')) {
      const logEntry = this.formatLog('warn', message, meta);
      this.output(logEntry);
      return logEntry;
    }
  }

  /**
   * Error level logging
   */
  error(message, meta = {}) {
    if (this.shouldLog('error')) {
      const logEntry = this.formatLog('error', message, meta);
      this.output(logEntry);
      return logEntry;
    }
  }

  /**
   * Fatal level logging
   */
  fatal(message, meta = {}) {
    if (this.shouldLog('fatal')) {
      const logEntry = this.formatLog('fatal', message, meta);
      this.output(logEntry);
      return logEntry;
    }
  }

  /**
   * Log with custom level
   */
  log(level, message, meta = {}) {
    if (this.shouldLog(level)) {
      const logEntry = this.formatLog(level, message, meta);
      this.output(logEntry);
      return logEntry;
    }
  }

  /**
   * Log performance metrics
   */
  performance(operation, duration, meta = {}) {
    this.info(`Performance: ${operation}`, {
      operation,
      duration,
      durationMs: `${duration}ms`,
      ...meta,
    });
  }

  /**
   * Log HTTP requests
   */
  request(method, url, status, duration, meta = {}) {
    const level = status >= 400 ? 'error' : 'info';
    this.log(level, `${method} ${url} - ${status}`, {
      type: 'http_request',
      method,
      url,
      status,
      duration,
      ...meta,
    });
  }

  /**
   * Log database operations
   */
  database(operation, table, duration, meta = {}) {
    this.debug(`Database: ${operation}`, {
      type: 'database',
      operation,
      table,
      duration,
      ...meta,
    });
  }

  /**
   * Log security events
   */
  security(event, level = 'warn', meta = {}) {
    this.log(level, `Security: ${event}`, {
      type: 'security',
      event,
      ...meta,
    });
  }

  /**
   * Log business events
   */
  business(event, meta = {}) {
    this.info(`Business: ${event}`, {
      type: 'business',
      event,
      ...meta,
    });
  }

  /**
   * Log audit events
   */
  audit(action, user, resource, meta = {}) {
    this.info(`Audit: ${action}`, {
      type: 'audit',
      action,
      user,
      resource,
      ...meta,
    });
  }

  /**
   * Create a child logger with additional context
   */
  child(context = {}) {
    return {
      debug: (message, meta = {}) => this.debug(message, { ...context, ...meta }),
      info: (message, meta = {}) => this.info(message, { ...context, ...meta }),
      warn: (message, meta = {}) => this.warn(message, { ...context, ...meta }),
      error: (message, meta = {}) => this.error(message, { ...context, ...meta }),
      fatal: (message, meta = {}) => this.fatal(message, { ...context, ...meta }),
      log: (level, message, meta = {}) => this.log(level, message, { ...context, ...meta }),
      performance: (operation, duration, meta = {}) => this.performance(operation, duration, { ...context, ...meta }),
      request: (method, url, status, duration, meta = {}) => this.request(method, url, status, duration, { ...context, ...meta }),
      database: (operation, table, duration, meta = {}) => this.database(operation, table, duration, { ...context, ...meta }),
      security: (event, level, meta = {}) => this.security(event, level, { ...context, ...meta }),
      business: (event, meta = {}) => this.business(event, { ...context, ...meta }),
      audit: (action, user, resource, meta = {}) => this.audit(action, user, resource, { ...context, ...meta }),
    };
  }

  /**
   * Measure execution time of a function
   */
  async measure(name, fn, meta = {}) {
    const startTime = Date.now();
    try {
      const result = await fn();
      const duration = Date.now() - startTime;
      this.performance(name, duration, meta);
      return result;
    } catch (error) {
      const duration = Date.now() - startTime;
      this.error(`${name} failed`, {
        duration,
        error: error.message,
        ...meta,
      });
      throw error;
    }
  }
}