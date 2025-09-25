/**
 * Authentication Middleware - Handles JWT validation and user authentication
 * Integrates with existing auth-service for user verification
 */

export class AuthMiddleware {
  constructor(config) {
    this.config = config;
    this.requireAuth = config.security.requireAuthentication;
    this.jwtSecret = config.security.jwtSecret;
    this.apiKey = config.security.apiKey;
  }

  /**
   * Authenticate incoming request
   */
  async authenticate(request, context) {
    if (!this.requireAuth) {
      return {
        success: true,
        user: { id: 'anonymous', role: 'user', domains: [] },
      };
    }

    try {
      const authHeader = request.headers.get('Authorization');
      const apiKeyHeader = request.headers.get('X-API-Key');

      // Try API Key authentication first
      if (apiKeyHeader) {
        return await this.authenticateWithApiKey(apiKeyHeader, context);
      }

      // Try JWT authentication
      if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        return await this.authenticateWithJWT(token, context);
      }

      // No authentication provided
      return {
        success: false,
        error: 'Authentication required',
        code: 'NO_AUTH',
      };

    } catch (error) {
      context.logger?.error('Authentication error', {
        error: error.message,
        requestId: context.requestId,
      });

      return {
        success: false,
        error: 'Authentication failed',
        code: 'AUTH_ERROR',
      };
    }
  }

  /**
   * Authenticate using API Key
   */
  async authenticateWithApiKey(apiKey, context) {
    // Validate API key format
    if (!apiKey || apiKey.length < 32) {
      return {
        success: false,
        error: 'Invalid API key format',
        code: 'INVALID_API_KEY',
      };
    }

    // Check against configured API key
    if (this.apiKey && apiKey === this.apiKey) {
      return {
        success: true,
        user: {
          id: 'api_user',
          type: 'api',
          role: 'admin',
          domains: ['*'],
          authenticatedAt: new Date().toISOString(),
          method: 'api_key',
        },
      };
    }

    // In production, this would validate against a database or external service
    const user = await this.validateApiKeyWithService(apiKey, context);
    
    if (user) {
      return {
        success: true,
        user: {
          ...user,
          authenticatedAt: new Date().toISOString(),
          method: 'api_key',
        },
      };
    }

    return {
      success: false,
      error: 'Invalid API key',
      code: 'INVALID_API_KEY',
    };
  }

  /**
   * Authenticate using JWT token
   */
  async authenticateWithJWT(token, context) {
    try {
      // Validate JWT format
      const parts = token.split('.');
      if (parts.length !== 3) {
        return {
          success: false,
          error: 'Invalid JWT format',
          code: 'INVALID_JWT_FORMAT',
        };
      }

      // Decode and verify JWT
      const payload = await this.verifyJWT(token);
      
      if (!payload) {
        return {
          success: false,
          error: 'Invalid or expired token',
          code: 'INVALID_JWT',
        };
      }

      // Extract user information from JWT payload
      const user = this.extractUserFromJWT(payload);
      
      // Validate user permissions
      const permissionResult = await this.validateUserPermissions(user, context);
      if (!permissionResult.valid) {
        return {
          success: false,
          error: permissionResult.error,
          code: 'INSUFFICIENT_PERMISSIONS',
        };
      }

      return {
        success: true,
        user: {
          ...user,
          authenticatedAt: new Date().toISOString(),
          method: 'jwt',
        },
      };

    } catch (error) {
      context.logger?.error('JWT authentication failed', {
        error: error.message,
        requestId: context.requestId,
      });

      return {
        success: false,
        error: 'JWT verification failed',
        code: 'JWT_VERIFICATION_FAILED',
      };
    }
  }

  /**
   * Verify JWT token signature and expiration
   */
  async verifyJWT(token) {
    try {
      // This is a simplified JWT verification
      // In production, use a proper JWT library like jose
      
      const [header, payload, signature] = token.split('.');
      
      // Decode payload
      const decodedPayload = JSON.parse(atob(payload));
      
      // Check expiration
      if (decodedPayload.exp && decodedPayload.exp < Date.now() / 1000) {
        throw new Error('Token expired');
      }

      // Verify signature (simplified)
      const expectedSignature = await this.generateSignature(header + '.' + payload);
      if (signature !== expectedSignature) {
        throw new Error('Invalid signature');
      }

      return decodedPayload;

    } catch (error) {
      return null;
    }
  }

  /**
   * Generate JWT signature (simplified implementation)
   */
  async generateSignature(data) {
    // This is a simplified signature generation
    // In production, use proper HMAC-SHA256 or RSA signing
    
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.jwtSecret);
    const messageData = encoder.encode(data);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
    const signatureArray = new Uint8Array(signature);
    
    return btoa(String.fromCharCode(...signatureArray))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Extract user information from JWT payload
   */
  extractUserFromJWT(payload) {
    return {
      id: payload.sub || payload.user_id,
      email: payload.email,
      role: payload.role || 'user',
      domains: payload.domains || [],
      permissions: payload.permissions || [],
      organizationId: payload.org_id,
      sessionId: payload.session_id,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
    };
  }

  /**
   * Validate user permissions for logging service
   */
  async validateUserPermissions(user, context) {
    // Check if user has basic logging permissions
    const requiredPermissions = ['logs:read', 'logs:write'];
    
    if (user.role === 'admin') {
      return { valid: true };
    }

    // Check specific permissions
    const hasRequiredPermissions = requiredPermissions.some(permission =>
      user.permissions?.includes(permission)
    );

    if (!hasRequiredPermissions) {
      return {
        valid: false,
        error: 'Insufficient permissions for logging service',
      };
    }

    // Check domain access
    const url = new URL(context.request?.url || '');
    const requestDomain = this.extractDomainFromRequest(url);
    
    if (requestDomain && user.domains?.length && !user.domains.includes(requestDomain) && !user.domains.includes('*')) {
      return {
        valid: false,
        error: 'No access to requested domain',
      };
    }

    return { valid: true };
  }

  /**
   * Extract domain from request URL
   */
  extractDomainFromRequest(url) {
    // Extract domain from subdomain (e.g., logger.tamyla.com -> tamyla.com)
    const hostname = url.hostname;
    const parts = hostname.split('.');
    
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    
    return hostname;
  }

  /**
   * Validate API key with external service
   */
  async validateApiKeyWithService(apiKey, context) {
    try {
      // This would integrate with the auth-service or database
      // For now, return a mock user for valid-looking API keys
      
      if (apiKey.startsWith('sk_') && apiKey.length >= 40) {
        return {
          id: `api_user_${apiKey.substring(-8)}`,
          type: 'api',
          role: 'user',
          domains: ['tamyla.com'], // Would be retrieved from service
          permissions: ['logs:read', 'logs:write'],
        };
      }

      return null;

    } catch (error) {
      context.logger?.error('API key validation failed', {
        error: error.message,
        requestId: context.requestId,
      });
      return null;
    }
  }

  /**
   * Create authentication context for request
   */
  createAuthContext(user, request) {
    return {
      user,
      authenticated: true,
      timestamp: new Date().toISOString(),
      ipAddress: this.extractIPAddress(request),
      userAgent: request.headers.get('User-Agent'),
    };
  }

  /**
   * Extract IP address from request
   */
  extractIPAddress(request) {
    // Check common headers for real IP address
    const headers = [
      'CF-Connecting-IP', // Cloudflare
      'X-Forwarded-For',
      'X-Real-IP',
      'X-Client-IP',
    ];

    for (const header of headers) {
      const value = request.headers.get(header);
      if (value) {
        // Take first IP if comma-separated list
        return value.split(',')[0].trim();
      }
    }

    return 'unknown';
  }

  /**
   * Generate new API key
   */
  async generateApiKey(userId, permissions = []) {
    const prefix = 'sk_';
    const timestamp = Date.now().toString(36);
    const randomBytes = crypto.getRandomValues(new Uint8Array(24));
    const randomString = Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('');
    
    return `${prefix}${timestamp}_${randomString}`;
  }

  /**
   * Revoke API key
   */
  async revokeApiKey(apiKey, context) {
    // Implementation would mark API key as revoked in storage
    context.logger?.audit('api_key_revoked', 'system', apiKey, {
      revokedAt: new Date().toISOString(),
    });
    
    return { success: true };
  }

  /**
   * Refresh JWT token
   */
  async refreshToken(refreshToken, context) {
    try {
      // Validate refresh token
      const payload = await this.verifyJWT(refreshToken);
      
      if (!payload || payload.type !== 'refresh') {
        return {
          success: false,
          error: 'Invalid refresh token',
        };
      }

      // Generate new access token
      const newToken = await this.generateJWT({
        sub: payload.sub,
        email: payload.email,
        role: payload.role,
        domains: payload.domains,
        permissions: payload.permissions,
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      });

      return {
        success: true,
        accessToken: newToken,
      };

    } catch (error) {
      return {
        success: false,
        error: 'Token refresh failed',
      };
    }
  }

  /**
   * Generate JWT token (simplified)
   */
  async generateJWT(payload) {
    const header = {
      alg: 'HS256',
      typ: 'JWT',
    };

    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
    
    const signature = await this.generateSignature(encodedHeader + '.' + encodedPayload);
    
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }
}