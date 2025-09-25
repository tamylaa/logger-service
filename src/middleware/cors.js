/**
 * CORS Middleware - Handles Cross-Origin Resource Sharing
 * Configures appropriate CORS headers based on environment and security settings
 */

export class CorsMiddleware {
  constructor(config) {
    this.config = config;
    this.allowedOrigins = config.security.allowedOrigins;
    this.environment = config.service.environment;
  }

  /**
   * Handle CORS for incoming request
   */
  async handle(request) {
    const origin = request.headers.get('Origin');
    const method = request.method;

    // Handle preflight OPTIONS requests
    if (method === 'OPTIONS') {
      return this.handlePreflight(request, origin);
    }

    // For other requests, just validate origin
    if (!this.isOriginAllowed(origin)) {
      return this.createCorsErrorResponse(origin);
    }

    // Return null to continue processing
    return null;
  }

  /**
   * Handle CORS preflight request
   */
  handlePreflight(request, origin) {
    const requestMethod = request.headers.get('Access-Control-Request-Method');
    const requestHeaders = request.headers.get('Access-Control-Request-Headers');

    // Check if origin is allowed
    if (!this.isOriginAllowed(origin)) {
      return this.createCorsErrorResponse(origin);
    }

    // Check if method is allowed
    const allowedMethods = this.getAllowedMethods();
    if (requestMethod && !allowedMethods.includes(requestMethod)) {
      return new Response(null, {
        status: 405,
        statusText: 'Method Not Allowed',
        headers: {
          'Access-Control-Allow-Origin': origin,
          'Vary': 'Origin',
        },
      });
    }

    // Return preflight response
    const headers = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': allowedMethods.join(', '),
      'Access-Control-Allow-Headers': this.getAllowedHeaders(requestHeaders),
      'Access-Control-Max-Age': '86400', // 24 hours
      'Vary': 'Origin',
    };

    // Add credentials support if needed
    if (this.shouldAllowCredentials(origin)) {
      headers['Access-Control-Allow-Credentials'] = 'true';
    }

    return new Response(null, {
      status: 204,
      headers,
    });
  }

  /**
   * Check if origin is allowed
   */
  isOriginAllowed(origin) {
    // Allow requests with no origin (same-origin, curl, etc.)
    if (!origin) {
      return true;
    }

    // Development mode - be more permissive
    if (this.environment === 'development') {
      // Allow localhost origins
      if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
        return true;
      }
    }

    // Check against configured allowed origins
    if (this.allowedOrigins.includes('*')) {
      return true;
    }

    if (this.allowedOrigins.includes(origin)) {
      return true;
    }

    // Check for wildcard subdomain matches
    for (const allowedOrigin of this.allowedOrigins) {
      if (this.matchesWildcard(origin, allowedOrigin)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if origin matches wildcard pattern
   */
  matchesWildcard(origin, pattern) {
    if (!pattern.includes('*')) {
      return false;
    }

    // Convert wildcard pattern to regex
    const regexPattern = pattern
      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&') // Escape special regex chars
      .replace(/\\\*/g, '.*'); // Convert * to .*

    const regex = new RegExp(`^${regexPattern}$`, 'i');
    return regex.test(origin);
  }

  /**
   * Get allowed HTTP methods
   */
  getAllowedMethods() {
    return ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
  }

  /**
   * Get allowed headers
   */
  getAllowedHeaders(requestHeaders) {
    const defaultHeaders = [
      'Accept',
      'Accept-Language',
      'Content-Language',
      'Content-Type',
      'Authorization',
      'X-API-Key',
      'X-Requested-With',
      'X-Request-ID',
    ];

    // Add any additional requested headers that are safe
    const safeAdditionalHeaders = [];
    if (requestHeaders) {
      const requested = requestHeaders.split(',').map(h => h.trim());
      for (const header of requested) {
        if (this.isSafeHeader(header) && !defaultHeaders.includes(header)) {
          safeAdditionalHeaders.push(header);
        }
      }
    }

    return [...defaultHeaders, ...safeAdditionalHeaders].join(', ');
  }

  /**
   * Check if header is safe to allow
   */
  isSafeHeader(header) {
    const headerLower = header.toLowerCase();
    
    // Block potentially dangerous headers
    const dangerousHeaders = [
      'cookie',
      'set-cookie',
      'host',
      'origin',
      'referer',
      'user-agent',
    ];

    if (dangerousHeaders.includes(headerLower)) {
      return false;
    }

    // Allow custom application headers
    if (headerLower.startsWith('x-')) {
      return true;
    }

    // Allow standard headers
    const safeHeaders = [
      'cache-control',
      'content-disposition',
      'content-encoding',
      'content-length',
      'content-range',
      'content-type',
      'date',
      'etag',
      'expires',
      'last-modified',
      'location',
      'range',
      'retry-after',
      'server',
      'transfer-encoding',
      'vary',
      'www-authenticate',
    ];

    return safeHeaders.includes(headerLower);
  }

  /**
   * Check if credentials should be allowed for origin
   */
  shouldAllowCredentials(origin) {
    // Only allow credentials for specific trusted origins
    // Never allow credentials with wildcard origins
    if (!origin || this.allowedOrigins.includes('*')) {
      return false;
    }

    // Check if origin is in trusted list
    const trustedOrigins = this.getTrustedOrigins();
    return trustedOrigins.includes(origin);
  }

  /**
   * Get trusted origins that can use credentials
   */
  getTrustedOrigins() {
    // Filter out wildcard origins for credential support
    return this.allowedOrigins.filter(origin => !origin.includes('*'));
  }

  /**
   * Create CORS error response
   */
  createCorsErrorResponse(origin) {
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: 'CORS_ERROR',
        message: 'Origin not allowed by CORS policy',
        origin,
        allowedOrigins: this.environment === 'development' ? this.allowedOrigins : undefined,
      },
    }), {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        'Vary': 'Origin',
      },
    });
  }

  /**
   * Add CORS headers to response
   */
  addCorsHeaders(response, request) {
    const origin = request.headers.get('Origin');
    
    if (!this.isOriginAllowed(origin)) {
      return response;
    }

    const headers = new Headers(response.headers);
    
    // Add basic CORS headers
    if (origin) {
      headers.set('Access-Control-Allow-Origin', origin);
    }
    
    headers.set('Vary', 'Origin');

    // Add credentials header if appropriate
    if (this.shouldAllowCredentials(origin)) {
      headers.set('Access-Control-Allow-Credentials', 'true');
    }

    // Add exposed headers for client access
    const exposedHeaders = this.getExposedHeaders();
    if (exposedHeaders.length > 0) {
      headers.set('Access-Control-Expose-Headers', exposedHeaders.join(', '));
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  /**
   * Get headers that should be exposed to client
   */
  getExposedHeaders() {
    return [
      'X-Request-ID',
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
      'X-Response-Time',
      'X-Error-ID',
    ];
  }

  /**
   * Validate CORS configuration
   */
  validateConfiguration() {
    const errors = [];

    // Check for wildcard with credentials
    if (this.allowedOrigins.includes('*') && this.getTrustedOrigins().length > 0) {
      errors.push('Cannot use wildcard origin (*) with credential support');
    }

    // Check for empty origins in production
    if (this.environment === 'production' && this.allowedOrigins.length === 0) {
      errors.push('No allowed origins configured for production environment');
    }

    // Check for localhost in production
    if (this.environment === 'production') {
      const hasLocalhost = this.allowedOrigins.some(origin => 
        origin.includes('localhost') || origin.includes('127.0.0.1')
      );
      
      if (hasLocalhost) {
        errors.push('Localhost origins should not be allowed in production');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Get CORS configuration summary
   */
  getConfiguration() {
    return {
      environment: this.environment,
      allowedOrigins: this.allowedOrigins,
      allowedMethods: this.getAllowedMethods(),
      trustedOrigins: this.getTrustedOrigins(),
      credentialsSupported: this.getTrustedOrigins().length > 0,
      exposedHeaders: this.getExposedHeaders(),
    };
  }
}