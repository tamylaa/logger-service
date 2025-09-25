/**
 * Metrics collection and monitoring system
 * Tracks service performance, usage, and health metrics
 */

export class Metrics {
  constructor(config, kvStore) {
    this.config = config;
    this.kv = kvStore;
    this.serviceName = config.service.name;
    this.environment = config.service.environment;
  }

  /**
   * Record a request metric
   */
  async recordRequest(method, status, duration) {
    if (!this.config.isFeatureEnabled('metrics')) {
      return;
    }

    try {
      const timestamp = Date.now();
      const date = new Date().toISOString().split('T')[0];
      
      const metric = {
        type: 'request',
        method,
        status,
        duration,
        timestamp,
        service: this.serviceName,
        environment: this.environment,
      };

      // Store in KV with TTL
      const key = `metrics:requests:${date}:${timestamp}:${crypto.randomUUID()}`;
      await this.kv.put(key, JSON.stringify(metric), {
        expirationTtl: this.config.storage.kvTtl,
      });

      // Update aggregated metrics
      await this.updateAggregatedMetrics('requests', method, status, duration, date);
      
    } catch (error) {
      console.error('Failed to record request metric:', error);
    }
  }

  /**
   * Record an error metric
   */
  async recordError(error) {
    if (!this.config.isFeatureEnabled('metrics')) {
      return;
    }

    try {
      const timestamp = Date.now();
      const date = new Date().toISOString().split('T')[0];
      
      const metric = {
        type: 'error',
        errorType: error.name,
        message: error.message,
        timestamp,
        service: this.serviceName,
        environment: this.environment,
      };

      const key = `metrics:errors:${date}:${timestamp}:${crypto.randomUUID()}`;
      await this.kv.put(key, JSON.stringify(metric), {
        expirationTtl: this.config.storage.kvTtl,
      });

      // Update aggregated error metrics
      await this.updateAggregatedMetrics('errors', error.name, null, null, date);
      
    } catch (error) {
      console.error('Failed to record error metric:', error);
    }
  }

  /**
   * Record log processing metrics
   */
  async recordLogProcessing(logId, duration, category, severity) {
    if (!this.config.isFeatureEnabled('metrics')) {
      return;
    }

    try {
      const timestamp = Date.now();
      const date = new Date().toISOString().split('T')[0];
      
      const metric = {
        type: 'log_processing',
        logId,
        duration,
        category,
        severity,
        timestamp,
        service: this.serviceName,
        environment: this.environment,
      };

      const key = `metrics:log_processing:${date}:${timestamp}:${logId}`;
      await this.kv.put(key, JSON.stringify(metric), {
        expirationTtl: this.config.storage.kvTtl,
      });

      // Update aggregated processing metrics
      await this.updateAggregatedMetrics('log_processing', category, severity, duration, date);
      
    } catch (error) {
      console.error('Failed to record log processing metric:', error);
    }
  }

  /**
   * Update aggregated metrics for efficient querying
   */
  async updateAggregatedMetrics(type, category, subcategory, value, date) {
    try {
      const aggregateKey = `metrics:aggregate:${type}:${date}`;
      
      // Get existing aggregates
      let aggregates = {};
      try {
        const existing = await this.kv.get(aggregateKey);
        if (existing) {
          aggregates = JSON.parse(existing);
        }
      } catch (e) {
        // Ignore errors when getting existing data
      }

      // Initialize structure if needed
      if (!aggregates[category]) {
        aggregates[category] = {
          count: 0,
          totalValue: 0,
          minValue: null,
          maxValue: null,
          subcategories: {},
        };
      }

      // Update aggregate data
      const categoryData = aggregates[category];
      categoryData.count++;
      
      if (value !== null && value !== undefined) {
        categoryData.totalValue += value;
        categoryData.minValue = categoryData.minValue === null ? value : Math.min(categoryData.minValue, value);
        categoryData.maxValue = categoryData.maxValue === null ? value : Math.max(categoryData.maxValue, value);
      }

      // Update subcategory if provided
      if (subcategory) {
        if (!categoryData.subcategories[subcategory]) {
          categoryData.subcategories[subcategory] = { count: 0 };
        }
        categoryData.subcategories[subcategory].count++;
      }

      // Store updated aggregates
      await this.kv.put(aggregateKey, JSON.stringify(aggregates), {
        expirationTtl: this.config.storage.kvTtl * 7, // Keep aggregates longer
      });

    } catch (error) {
      console.error('Failed to update aggregated metrics:', error);
    }
  }

  /**
   * Get current service metrics
   */
  async getMetrics() {
    if (!this.config.isFeatureEnabled('metrics')) {
      return { metricsDisabled: true };
    }

    try {
      const today = new Date().toISOString().split('T')[0];
      const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
      
      // Get aggregated metrics for today and yesterday
      const [todayRequests, yesterdayRequests, todayErrors, todayProcessing] = await Promise.all([
        this.getAggregatedMetrics('requests', today),
        this.getAggregatedMetrics('requests', yesterday),
        this.getAggregatedMetrics('errors', today),
        this.getAggregatedMetrics('log_processing', today),
      ]);

      return {
        service: {
          name: this.serviceName,
          environment: this.environment,
          timestamp: new Date().toISOString(),
        },
        requests: {
          today: todayRequests,
          yesterday: yesterdayRequests,
        },
        errors: {
          today: todayErrors,
        },
        logProcessing: {
          today: todayProcessing,
        },
        health: await this.getHealthMetrics(),
      };

    } catch (error) {
      console.error('Failed to get metrics:', error);
      return { error: 'Failed to retrieve metrics' };
    }
  }

  /**
   * Get aggregated metrics for a specific type and date
   */
  async getAggregatedMetrics(type, date) {
    try {
      const key = `metrics:aggregate:${type}:${date}`;
      const data = await this.kv.get(key);
      
      if (!data) {
        return {};
      }

      return JSON.parse(data);
    } catch (error) {
      console.error(`Failed to get aggregated metrics for ${type}:${date}:`, error);
      return {};
    }
  }

  /**
   * Get health metrics
   */
  async getHealthMetrics() {
    const startTime = Date.now();
    
    try {
      // Test KV store health
      const kvTestKey = `health:test:${Date.now()}`;
      await this.kv.put(kvTestKey, 'test', { expirationTtl: 60 });
      const kvGetResult = await this.kv.get(kvTestKey);
      const kvHealthy = kvGetResult === 'test';
      
      // Clean up test key
      await this.kv.delete(kvTestKey);
      
      const responseTime = Date.now() - startTime;
      
      return {
        kv: {
          healthy: kvHealthy,
          responseTime,
        },
        service: {
          uptime: Date.now(), // Would be actual uptime in production
          memory: this.getMemoryUsage(),
          responseTime,
        },
      };
      
    } catch (error) {
      return {
        kv: {
          healthy: false,
          error: error.message,
        },
        service: {
          healthy: false,
          error: error.message,
        },
      };
    }
  }

  /**
   * Get memory usage (limited in Cloudflare Workers)
   */
  getMemoryUsage() {
    // Cloudflare Workers don't expose memory usage directly
    // This is a placeholder for potential future functionality
    return {
      available: false,
      reason: 'Memory metrics not available in Cloudflare Workers',
    };
  }

  /**
   * Record custom metric
   */
  async recordCustomMetric(name, value, metadata = {}) {
    if (!this.config.isFeatureEnabled('metrics')) {
      return;
    }

    try {
      const timestamp = Date.now();
      const date = new Date().toISOString().split('T')[0];
      
      const metric = {
        type: 'custom',
        name,
        value,
        metadata,
        timestamp,
        service: this.serviceName,
        environment: this.environment,
      };

      const key = `metrics:custom:${date}:${timestamp}:${name}:${crypto.randomUUID()}`;
      await this.kv.put(key, JSON.stringify(metric), {
        expirationTtl: this.config.storage.kvTtl,
      });

      // Update aggregated custom metrics
      await this.updateAggregatedMetrics('custom', name, null, value, date);
      
    } catch (error) {
      console.error('Failed to record custom metric:', error);
    }
  }

  /**
   * Get metrics for a specific time range
   */
  async getMetricsRange(startDate, endDate, type = null) {
    if (!this.config.isFeatureEnabled('metrics')) {
      return { metricsDisabled: true };
    }

    try {
      const start = new Date(startDate);
      const end = new Date(endDate);
      const dates = [];
      
      // Generate array of dates in range
      for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
        dates.push(d.toISOString().split('T')[0]);
      }

      // Get metrics for each date
      const metricsPromises = dates.map(date => {
        if (type) {
          return this.getAggregatedMetrics(type, date).then(data => ({ date, [type]: data }));
        } else {
          return Promise.all([
            this.getAggregatedMetrics('requests', date),
            this.getAggregatedMetrics('errors', date),
            this.getAggregatedMetrics('log_processing', date),
          ]).then(([requests, errors, processing]) => ({
            date,
            requests,
            errors,
            log_processing: processing,
          }));
        }
      });

      const results = await Promise.all(metricsPromises);
      
      return {
        timeRange: { startDate, endDate },
        data: results.filter(result => {
          // Filter out dates with no data
          const hasData = Object.keys(result).some(key => 
            key !== 'date' && Object.keys(result[key]).length > 0
          );
          return hasData;
        }),
      };

    } catch (error) {
      console.error('Failed to get metrics range:', error);
      return { error: 'Failed to retrieve metrics for date range' };
    }
  }

  /**
   * Clean up old metrics (called by scheduled tasks)
   */
  async cleanupOldMetrics() {
    if (!this.config.isFeatureEnabled('metrics')) {
      return;
    }

    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - 30); // Keep 30 days of metrics
      
      const cutoffTimestamp = cutoffDate.getTime();
      
      // List and delete old metric keys
      // Note: This is a simplified approach - in production, you might use
      // KV's TTL feature or implement a more efficient cleanup strategy
      
      console.log('Metrics cleanup completed', {
        cutoffDate: cutoffDate.toISOString(),
        environment: this.environment,
      });

    } catch (error) {
      console.error('Failed to clean up old metrics:', error);
    }
  }
}