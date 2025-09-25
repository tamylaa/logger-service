/**
 * Centralized error handling utility
 * Provides consistent error responses and logging
 */

export class ErrorHandler {
  /**
   * Handle general errors and return appropriate HTTP response
   */
  static handleError(error, logger) {
    const errorId = crypto.randomUUID();
    
    // Log the error for debugging
    logger?.error('Error occurred', {
      errorId,
      message: error.message,
      stack: error.stack,
      name: error.name,
    });

    // Determine appropriate HTTP status and message
    let status = 500;
    let message = 'Internal server error';
    let code = 'INTERNAL_ERROR';

    if (error.name === 'ValidationError') {
      status = 400;
      message = error.message;
      code = 'VALIDATION_ERROR';
    } else if (error.name === 'AuthenticationError') {
      status = 401;
      message = 'Authentication required';
      code = 'AUTHENTICATION_ERROR';
    } else if (error.name === 'AuthorizationError') {
      status = 403;
      message = 'Insufficient permissions';
      code = 'AUTHORIZATION_ERROR';
    } else if (error.name === 'NotFoundError') {
      status = 404;
      message = error.message || 'Resource not found';
      code = 'NOT_FOUND';
    } else if (error.name === 'RateLimitError') {
      status = 429;
      message = 'Rate limit exceeded';
      code = 'RATE_LIMIT_EXCEEDED';
    } else if (error.name === 'PayloadTooLargeError') {
      status = 413;
      message = 'Payload too large';
      code = 'PAYLOAD_TOO_LARGE';
    }

    return new Response(JSON.stringify({
      success: false,
      error: {
        code,
        message,
        errorId,
        timestamp: new Date().toISOString(),
      }
    }), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'X-Error-ID': errorId,
      },
    });
  }

  /**
   * Create a validation error
   */
  static validationError(message, details = null) {
    const error = new Error(message);
    error.name = 'ValidationError';
    error.details = details;
    return error;
  }

  /**
   * Create an authentication error
   */
  static authenticationError(message = 'Authentication required') {
    const error = new Error(message);
    error.name = 'AuthenticationError';
    return error;
  }

  /**
   * Create an authorization error
   */
  static authorizationError(message = 'Insufficient permissions') {
    const error = new Error(message);
    error.name = 'AuthorizationError';
    return error;
  }

  /**
   * Create a not found error
   */
  static notFoundError(message = 'Resource not found') {
    const error = new Error(message);
    error.name = 'NotFoundError';
    return error;
  }

  /**
   * Create a rate limit error
   */
  static rateLimitError(message = 'Rate limit exceeded') {
    const error = new Error(message);
    error.name = 'RateLimitError';
    return error;
  }

  /**
   * Create a payload too large error
   */
  static payloadTooLargeError(message = 'Payload too large') {
    const error = new Error(message);
    error.name = 'PayloadTooLargeError';
    return error;
  }

  /**
   * Return a 404 response
   */
  static notFound(message = 'Endpoint not found') {
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: 'NOT_FOUND',
        message,
        timestamp: new Date().toISOString(),
      }
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Return a rate limit exceeded response
   */
  static rateLimitExceeded(rateLimitResult) {
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Rate limit exceeded',
        retryAfter: rateLimitResult.retryAfter,
        limit: rateLimitResult.limit,
        remaining: rateLimitResult.remaining,
        timestamp: new Date().toISOString(),
      }
    }), {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(rateLimitResult.retryAfter),
        'X-RateLimit-Limit': String(rateLimitResult.limit),
        'X-RateLimit-Remaining': String(rateLimitResult.remaining),
        'X-RateLimit-Reset': String(rateLimitResult.resetTime),
      },
    });
  }

  /**
   * Return an unauthorized response
   */
  static unauthorized(message = 'Authentication required') {
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message,
        timestamp: new Date().toISOString(),
      }
    }), {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer',
      },
    });
  }

  /**
   * Return a success response
   */
  static success(data, status = 200) {
    return new Response(JSON.stringify({
      success: true,
      data,
      timestamp: new Date().toISOString(),
    }), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Return a paginated success response
   */
  static successWithPagination(data, pagination, status = 200) {
    return new Response(JSON.stringify({
      success: true,
      data,
      pagination,
      timestamp: new Date().toISOString(),
    }), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}