/**
 * Rate Limiter - Implements rate limiting to prevent abuse and ensure fair usage
 * Uses Cloudflare KV for distributed rate limiting across edge locations
 */

export class RateLimiter {
  constructor(config, kvStore) {
    this.config = config;
    this.kv = kvStore;
    this.limits = config.rateLimits;
  }

  /**
   * Check rate limit for a request
   */
  async checkLimit(request, context, operation = 'default') {
    try {
      const clientId = this.getClientIdentifier(request, context);
      const limitsConfig = this.getLimitsForOperation(operation);
      
      // Check each time window
      const results = await Promise.all([
        this.checkTimeWindow(clientId, 'minute', limitsConfig.perMinute),
        this.checkTimeWindow(clientId, 'hour', limitsConfig.perHour || limitsConfig.perMinute * 60),
        this.checkTimeWindow(clientId, 'day', limitsConfig.perDay || limitsConfig.perMinute * 1440),
      ]);

      // Find the most restrictive limit
      const restrictiveResult = results.find(result => !result.allowed);
      
      if (restrictiveResult) {
        // Log rate limit violation
        context.logger?.warn('Rate limit exceeded', {
          clientId,
          operation,
          window: restrictiveResult.window,
          current: restrictiveResult.current,
          limit: restrictiveResult.limit,
          requestId: context.requestId,
        });

        return restrictiveResult;
      }

      // All limits passed, increment counters
      await this.incrementCounters(clientId, results);

      return {
        allowed: true,
        remaining: Math.min(...results.map(r => r.remaining)),
        limit: limitsConfig.perMinute,
        resetTime: Math.min(...results.map(r => r.resetTime)),
      };

    } catch (error) {
      context.logger?.error('Rate limiting error', {
        error: error.message,
        requestId: context.requestId,
      });

      // Fail open - allow request if rate limiting fails
      return {
        allowed: true,
        error: error.message,
      };
    }
  }

  /**
   * Get client identifier for rate limiting
   */
  getClientIdentifier(request, context) {
    // Use authenticated user ID if available
    if (context.user?.id) {
      return `user:${context.user.id}`;
    }

    // Use API key if available
    const apiKey = request.headers.get('X-API-Key');
    if (apiKey) {
      return `apikey:${this.hashApiKey(apiKey)}`;
    }

    // Fall back to IP address
    const ipAddress = this.extractIPAddress(request);
    return `ip:${ipAddress}`;
  }

  /**
   * Get rate limits configuration for operation type
   */
  getLimitsForOperation(operation) {
    switch (operation) {
      case 'search':
        return {
          perMinute: this.limits.searchPerMinute || 100,
          perHour: (this.limits.searchPerMinute || 100) * 60,
          perDay: (this.limits.searchPerMinute || 100) * 1440,
        };

      case 'upload':
        return {
          perMinute: Math.floor(this.limits.perMinute * 0.5), // 50% of normal limit
          perHour: this.limits.perHour,
          perDay: this.limits.perDay,
        };

      case 'analytics':
        return {
          perMinute: Math.floor(this.limits.perMinute * 0.2), // 20% of normal limit
          perHour: this.limits.perHour,
          perDay: this.limits.perDay,
        };

      default:
        return {
          perMinute: this.limits.perMinute,
          perHour: this.limits.perHour,
          perDay: this.limits.perDay,
        };
    }
  }

  /**
   * Check rate limit for a specific time window
   */
  async checkTimeWindow(clientId, window, limit) {
    const windowKey = this.getWindowKey(clientId, window);
    const windowStart = this.getWindowStart(window);
    const windowEnd = windowStart + this.getWindowDuration(window);

    try {
      // Get current count
      const countData = await this.kv.get(windowKey);
      const current = countData ? JSON.parse(countData) : { count: 0, windowStart };

      // Check if we're in the same window
      if (current.windowStart !== windowStart) {
        // New window, reset count
        current.count = 0;
        current.windowStart = windowStart;
      }

      const remaining = Math.max(0, limit - current.count);
      const allowed = current.count < limit;

      return {
        allowed,
        current: current.count,
        remaining,
        limit,
        window,
        resetTime: windowEnd,
        windowKey,
        windowStart,
      };

    } catch (error) {
      // If we can't check limits, allow the request
      return {
        allowed: true,
        current: 0,
        remaining: limit,
        limit,
        window,
        resetTime: windowEnd,
        error: error.message,
      };
    }
  }

  /**
   * Increment counters for all time windows
   */
  async incrementCounters(clientId, results) {
    const updates = results.map(result => {
      const newCount = result.current + 1;
      const data = JSON.stringify({
        count: newCount,
        windowStart: result.windowStart,
        lastUpdate: Date.now(),
      });

      return this.kv.put(result.windowKey, data, {
        expirationTtl: this.getWindowDuration(result.window) / 1000 + 60, // Add 1 minute buffer
      });
    });

    await Promise.all(updates);
  }

  /**
   * Get KV key for rate limit window
   */
  getWindowKey(clientId, window) {
    const windowStart = this.getWindowStart(window);
    return `ratelimit:${clientId}:${window}:${windowStart}`;
  }

  /**
   * Get window start timestamp
   */
  getWindowStart(window) {
    const now = Date.now();
    
    switch (window) {
      case 'minute':
        return Math.floor(now / 60000) * 60000; // Round down to minute
      case 'hour':
        return Math.floor(now / 3600000) * 3600000; // Round down to hour
      case 'day':
        return Math.floor(now / 86400000) * 86400000; // Round down to day
      default:
        return now;
    }
  }

  /**
   * Get window duration in milliseconds
   */
  getWindowDuration(window) {
    switch (window) {
      case 'minute':
        return 60 * 1000;
      case 'hour':
        return 60 * 60 * 1000;
      case 'day':
        return 24 * 60 * 60 * 1000;
      default:
        return 60 * 1000;
    }
  }

  /**
   * Extract IP address from request
   */
  extractIPAddress(request) {
    // Check Cloudflare and common proxy headers
    const headers = [
      'CF-Connecting-IP',
      'X-Forwarded-For',
      'X-Real-IP',
      'X-Client-IP',
    ];

    for (const header of headers) {
      const value = request.headers.get(header);
      if (value) {
        return value.split(',')[0].trim();
      }
    }

    return 'unknown';
  }

  /**
   * Hash API key for storage
   */
  hashApiKey(apiKey) {
    // Create a simple hash of the API key for storage
    // In production, use a more robust hashing function
    let hash = 0;
    for (let i = 0; i < apiKey.length; i++) {
      const char = apiKey.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }

  /**
   * Get rate limit status for client
   */
  async getStatus(request, context) {
    const clientId = this.getClientIdentifier(request, context);
    
    const statuses = await Promise.all([
      this.checkTimeWindow(clientId, 'minute', this.limits.perMinute),
      this.checkTimeWindow(clientId, 'hour', this.limits.perHour),
      this.checkTimeWindow(clientId, 'day', this.limits.perDay),
    ]);

    return {
      clientId,
      windows: statuses.map(status => ({
        window: status.window,
        current: status.current,
        limit: status.limit,
        remaining: status.remaining,
        resetTime: status.resetTime,
      })),
    };
  }

  /**
   * Reset rate limits for a client (admin function)
   */
  async resetLimits(clientId, window = null) {
    try {
      const windows = window ? [window] : ['minute', 'hour', 'day'];
      
      const deletePromises = windows.map(w => {
        const key = this.getWindowKey(clientId, w);
        return this.kv.delete(key);
      });

      await Promise.all(deletePromises);
      
      return {
        success: true,
        clientId,
        resetWindows: windows,
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get rate limit metrics
   */
  async getMetrics() {
    try {
      // This would require listing KV keys, which is limited
      // In practice, you'd store aggregate metrics separately
      
      return {
        message: 'Rate limit metrics collection not implemented',
        note: 'Metrics would be collected via separate aggregation process',
      };

    } catch (error) {
      return {
        error: error.message,
      };
    }
  }

  /**
   * Configure custom rate limits for specific clients
   */
  async setCustomLimits(clientId, limits) {
    try {
      const customLimitsKey = `ratelimit:config:${clientId}`;
      await this.kv.put(customLimitsKey, JSON.stringify(limits), {
        expirationTtl: 86400 * 30, // 30 days
      });

      return {
        success: true,
        clientId,
        limits,
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get custom limits for client
   */
  async getCustomLimits(clientId) {
    try {
      const customLimitsKey = `ratelimit:config:${clientId}`;
      const limitsData = await this.kv.get(customLimitsKey);
      
      if (limitsData) {
        return JSON.parse(limitsData);
      }

      return null;

    } catch (error) {
      return null;
    }
  }

  /**
   * Check if client is in allowlist (bypass rate limits)
   */
  async isAllowlisted(clientId) {
    try {
      const allowlistKey = `ratelimit:allowlist:${clientId}`;
      const allowlistData = await this.kv.get(allowlistKey);
      
      return !!allowlistData;

    } catch (error) {
      return false;
    }
  }

  /**
   * Add client to allowlist
   */
  async addToAllowlist(clientId, reason = '', duration = null) {
    try {
      const allowlistKey = `ratelimit:allowlist:${clientId}`;
      const data = {
        reason,
        addedAt: new Date().toISOString(),
        expiresAt: duration ? new Date(Date.now() + duration).toISOString() : null,
      };

      const options = {};
      if (duration) {
        options.expirationTtl = Math.floor(duration / 1000);
      }

      await this.kv.put(allowlistKey, JSON.stringify(data), options);

      return {
        success: true,
        clientId,
        reason,
        duration,
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Remove client from allowlist
   */
  async removeFromAllowlist(clientId) {
    try {
      const allowlistKey = `ratelimit:allowlist:${clientId}`;
      await this.kv.delete(allowlistKey);

      return {
        success: true,
        clientId,
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }
}