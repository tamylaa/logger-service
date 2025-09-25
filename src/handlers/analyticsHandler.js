/**
 * Analytics Handler - Provides log analytics, summaries, and business intelligence
 * Implements advanced analytics for log data analysis and reporting
 */

import { Logger } from '../utils/logger.js';
import { ErrorHandler } from '../utils/errorHandler.js';

export class AnalyticsHandler {
  constructor(logStorage, config, metrics) {
    this.storage = logStorage;
    this.config = config;
    this.metrics = metrics;
    this.logger = new Logger('AnalyticsHandler');
    this.cache = new Map(); // Simple in-memory cache
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Get log analytics summary
   */
  async getAnalytics(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const params = Object.fromEntries(url.searchParams.entries());
      
      // Parse query parameters
      const {
        timeframe = '24h',
        groupBy = 'severity',
        includePatterns = 'true',
        includeMetrics = 'true',
        userId = null,
      } = params;

      // Validate access permissions
      const user = ctx.user;
      if (!user || (!user.isAdmin && userId !== user.id)) {
        throw ErrorHandler.createError(
          'FORBIDDEN',
          'Access denied to analytics data',
          403
        );
      }

      // Check cache first
      const cacheKey = this.generateCacheKey('analytics', { timeframe, groupBy, userId });
      const cached = this.getCached(cacheKey);
      if (cached) {
        this.logger.info('Analytics served from cache', { cacheKey });
        return this.createResponse(cached);
      }

      // Calculate time range
      const timeRange = this.calculateTimeRange(timeframe);
      
      // Get analytics data
      const analytics = await this.generateAnalytics({
        timeRange,
        groupBy,
        includePatterns: includePatterns === 'true',
        includeMetrics: includeMetrics === 'true',
        userId,
      });

      // Cache the results
      this.setCached(cacheKey, analytics);

      this.metrics.recordAnalyticsQuery(timeframe, groupBy);
      this.logger.info('Analytics generated successfully', {
        timeframe,
        groupBy,
        recordCount: analytics.summary.totalLogs,
      });

      return this.createResponse(analytics);

    } catch (error) {
      this.logger.error('Failed to get analytics', { error: error.message });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Get log patterns analysis
   */
  async getPatterns(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const params = Object.fromEntries(url.searchParams.entries());
      
      const {
        timeframe = '24h',
        category = 'all',
        severity = 'all',
        limit = '50',
        userId = null,
      } = params;

      // Validate access
      const user = ctx.user;
      if (!user || (!user.isAdmin && userId !== user.id)) {
        throw ErrorHandler.createError('FORBIDDEN', 'Access denied', 403);
      }

      const cacheKey = this.generateCacheKey('patterns', { timeframe, category, severity, userId });
      const cached = this.getCached(cacheKey);
      if (cached) {
        return this.createResponse(cached);
      }

      const timeRange = this.calculateTimeRange(timeframe);
      const patterns = await this.analyzePatterns({
        timeRange,
        category,
        severity,
        limit: parseInt(limit),
        userId,
      });

      this.setCached(cacheKey, patterns);
      
      return this.createResponse(patterns);

    } catch (error) {
      this.logger.error('Failed to get patterns', { error: error.message });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Get trend analysis
   */
  async getTrends(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const params = Object.fromEntries(url.searchParams.entries());
      
      const {
        timeframe = '7d',
        interval = 'hour',
        metrics = 'count,severity,performance',
        userId = null,
      } = params;

      const user = ctx.user;
      if (!user || (!user.isAdmin && userId !== user.id)) {
        throw ErrorHandler.createError('FORBIDDEN', 'Access denied', 403);
      }

      const cacheKey = this.generateCacheKey('trends', { timeframe, interval, metrics, userId });
      const cached = this.getCached(cacheKey);
      if (cached) {
        return this.createResponse(cached);
      }

      const timeRange = this.calculateTimeRange(timeframe);
      const trends = await this.analyzeTrends({
        timeRange,
        interval,
        metrics: metrics.split(','),
        userId,
      });

      this.setCached(cacheKey, trends);
      
      return this.createResponse(trends);

    } catch (error) {
      this.logger.error('Failed to get trends', { error: error.message });
      throw ErrorHandler.handleError(error);
    }
  }

  /**
   * Generate comprehensive analytics
   */
  async generateAnalytics(options) {
    const { timeRange, groupBy, includePatterns, includeMetrics, userId } = options;

    // Get logs for the specified time range
    const logs = await this.storage.retrieveLogs({
      startTime: timeRange.start,
      endTime: timeRange.end,
      userId,
      limit: 10000, // Reasonable limit for analytics
    });

    // Generate summary statistics
    const summary = this.generateSummary(logs);
    
    // Group data according to groupBy parameter
    const groupedData = this.groupLogs(logs, groupBy);
    
    // Generate distribution analysis
    const distributions = this.analyzeDistributions(logs);
    
    // Performance metrics
    const performance = this.analyzePerformance(logs);
    
    // Error analysis
    const errors = this.analyzeErrors(logs);

    const analytics = {
      summary,
      groupedData,
      distributions,
      performance,
      errors,
      timeRange,
      generatedAt: new Date().toISOString(),
    };

    // Add patterns if requested
    if (includePatterns) {
      analytics.patterns = await this.analyzePatterns({
        timeRange,
        logs,
        limit: 20,
        userId,
      });
    }

    // Add system metrics if requested
    if (includeMetrics && userId === null) { // Only for admin users
      analytics.systemMetrics = await this.getSystemMetrics(timeRange);
    }

    return analytics;
  }

  /**
   * Generate summary statistics
   */
  generateSummary(logs) {
    const summary = {
      totalLogs: logs.length,
      timeRange: {
        oldest: logs.length > 0 ? Math.min(...logs.map(log => new Date(log.timestamp).getTime())) : null,
        newest: logs.length > 0 ? Math.max(...logs.map(log => new Date(log.timestamp).getTime())) : null,
      },
      severityBreakdown: {},
      categoryBreakdown: {},
      uniqueComponents: new Set(),
      uniqueEndpoints: new Set(),
      averageLogSize: 0,
    };

    let totalSize = 0;

    for (const log of logs) {
      // Count by severity
      const severity = log.severity || 'unknown';
      summary.severityBreakdown[severity] = (summary.severityBreakdown[severity] || 0) + 1;

      // Count by category
      const category = log.category || 'uncategorized';
      summary.categoryBreakdown[category] = (summary.categoryBreakdown[category] || 0) + 1;

      // Track unique components and endpoints
      if (log.component) summary.uniqueComponents.add(log.component);
      if (log.endpoint) summary.uniqueEndpoints.add(log.endpoint);

      // Calculate log size
      totalSize += JSON.stringify(log).length;
    }

    summary.uniqueComponents = summary.uniqueComponents.size;
    summary.uniqueEndpoints = summary.uniqueEndpoints.size;
    summary.averageLogSize = logs.length > 0 ? Math.round(totalSize / logs.length) : 0;

    return summary;
  }

  /**
   * Group logs by specified criteria
   */
  groupLogs(logs, groupBy) {
    const groups = {};

    for (const log of logs) {
      let key;
      
      switch (groupBy) {
        case 'severity':
          key = log.severity || 'unknown';
          break;
        case 'category':
          key = log.category || 'uncategorized';
          break;
        case 'component':
          key = log.component || 'unknown';
          break;
        case 'endpoint':
          key = log.endpoint || 'unknown';
          break;
        case 'hour':
          key = new Date(log.timestamp).getHours().toString().padStart(2, '0');
          break;
        case 'day':
          key = new Date(log.timestamp).toISOString().split('T')[0];
          break;
        default:
          key = 'all';
      }

      if (!groups[key]) {
        groups[key] = {
          count: 0,
          logs: [],
          firstSeen: log.timestamp,
          lastSeen: log.timestamp,
        };
      }

      groups[key].count++;
      groups[key].logs.push(log);
      
      // Update time boundaries
      if (new Date(log.timestamp) < new Date(groups[key].firstSeen)) {
        groups[key].firstSeen = log.timestamp;
      }
      if (new Date(log.timestamp) > new Date(groups[key].lastSeen)) {
        groups[key].lastSeen = log.timestamp;
      }
    }

    // Sort groups by count (descending)
    return Object.fromEntries(
      Object.entries(groups).sort((a, b) => b[1].count - a[1].count)
    );
  }

  /**
   * Analyze distributions
   */
  analyzeDistributions(logs) {
    return {
      severityDistribution: this.calculateDistribution(logs, 'severity'),
      categoryDistribution: this.calculateDistribution(logs, 'category'),
      componentDistribution: this.calculateDistribution(logs, 'component'),
      timeDistribution: this.calculateTimeDistribution(logs),
      durationDistribution: this.calculateDurationDistribution(logs),
    };
  }

  /**
   * Calculate distribution for a field
   */
  calculateDistribution(logs, field) {
    const counts = {};
    const total = logs.length;

    for (const log of logs) {
      const value = log[field] || 'unknown';
      counts[value] = (counts[value] || 0) + 1;
    }

    // Calculate percentages
    const distribution = {};
    for (const [value, count] of Object.entries(counts)) {
      distribution[value] = {
        count,
        percentage: total > 0 ? ((count / total) * 100).toFixed(2) : 0,
      };
    }

    return distribution;
  }

  /**
   * Calculate time distribution (hourly)
   */
  calculateTimeDistribution(logs) {
    const hourCounts = new Array(24).fill(0);

    for (const log of logs) {
      const hour = new Date(log.timestamp).getHours();
      hourCounts[hour]++;
    }

    return hourCounts.map((count, hour) => ({
      hour: hour.toString().padStart(2, '0'),
      count,
      percentage: logs.length > 0 ? ((count / logs.length) * 100).toFixed(2) : 0,
    }));
  }

  /**
   * Calculate duration distribution
   */
  calculateDurationDistribution(logs) {
    const durations = logs
      .filter(log => log.duration && typeof log.duration === 'number')
      .map(log => log.duration);

    if (durations.length === 0) {
      return {
        count: 0,
        average: 0,
        median: 0,
        percentiles: {},
      };
    }

    durations.sort((a, b) => a - b);

    return {
      count: durations.length,
      average: durations.reduce((sum, d) => sum + d, 0) / durations.length,
      median: this.calculatePercentile(durations, 50),
      min: durations[0],
      max: durations[durations.length - 1],
      percentiles: {
        p50: this.calculatePercentile(durations, 50),
        p90: this.calculatePercentile(durations, 90),
        p95: this.calculatePercentile(durations, 95),
        p99: this.calculatePercentile(durations, 99),
      },
    };
  }

  /**
   * Calculate percentile
   */
  calculatePercentile(sortedArray, percentile) {
    const index = (percentile / 100) * (sortedArray.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    
    if (lower === upper) {
      return sortedArray[lower];
    }
    
    return sortedArray[lower] + (sortedArray[upper] - sortedArray[lower]) * (index - lower);
  }

  /**
   * Analyze performance metrics
   */
  analyzePerformance(logs) {
    const performanceLogs = logs.filter(log => 
      log.duration || 
      log.category === 'performance' ||
      log.message?.toLowerCase().includes('performance')
    );

    const durations = performanceLogs
      .map(log => log.duration)
      .filter(d => d && typeof d === 'number');

    const slowQueries = performanceLogs.filter(log => 
      log.duration && log.duration > 1000
    );

    const memoryIssues = performanceLogs.filter(log =>
      log.message?.toLowerCase().includes('memory') ||
      log.message?.toLowerCase().includes('heap')
    );

    return {
      totalPerformanceLogs: performanceLogs.length,
      averageDuration: durations.length > 0 ? durations.reduce((sum, d) => sum + d, 0) / durations.length : 0,
      slowQueries: {
        count: slowQueries.length,
        examples: slowQueries.slice(0, 5).map(log => ({
          timestamp: log.timestamp,
          duration: log.duration,
          endpoint: log.endpoint,
          component: log.component,
        })),
      },
      memoryIssues: {
        count: memoryIssues.length,
        examples: memoryIssues.slice(0, 3).map(log => ({
          timestamp: log.timestamp,
          message: log.message?.substring(0, 100),
          component: log.component,
        })),
      },
    };
  }

  /**
   * Analyze errors
   */
  analyzeErrors(logs) {
    const errorLogs = logs.filter(log => 
      log.severity === 'error' || 
      log.severity === 'critical' ||
      log.category === 'error'
    );

    // Group errors by message pattern
    const errorPatterns = {};
    for (const log of errorLogs) {
      // Simple pattern extraction - first 50 characters
      const pattern = log.message?.substring(0, 50) || 'Unknown error';
      if (!errorPatterns[pattern]) {
        errorPatterns[pattern] = {
          count: 0,
          firstSeen: log.timestamp,
          lastSeen: log.timestamp,
          examples: [],
        };
      }
      
      errorPatterns[pattern].count++;
      errorPatterns[pattern].lastSeen = log.timestamp;
      
      if (errorPatterns[pattern].examples.length < 3) {
        errorPatterns[pattern].examples.push({
          timestamp: log.timestamp,
          component: log.component,
          endpoint: log.endpoint,
        });
      }
    }

    // Sort patterns by frequency
    const sortedPatterns = Object.entries(errorPatterns)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 10); // Top 10 patterns

    return {
      totalErrors: errorLogs.length,
      errorRate: logs.length > 0 ? ((errorLogs.length / logs.length) * 100).toFixed(2) : 0,
      topErrorPatterns: Object.fromEntries(sortedPatterns),
      recentErrors: errorLogs
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 10)
        .map(log => ({
          timestamp: log.timestamp,
          severity: log.severity,
          message: log.message?.substring(0, 100),
          component: log.component,
          endpoint: log.endpoint,
        })),
    };
  }

  /**
   * Analyze patterns in logs
   */
  async analyzePatterns(options) {
    const { timeRange, logs, limit = 20, userId } = options;
    
    // Use provided logs or fetch them
    const logData = logs || await this.storage.retrieveLogs({
      startTime: timeRange?.start,
      endTime: timeRange?.end,
      userId,
      limit: 5000,
    });

    // This would typically integrate with the PatternMatcher
    // For now, we'll do basic pattern analysis
    
    const patterns = {
      repeatingMessages: this.findRepeatingMessages(logData, limit),
      errorSpikes: this.detectErrorSpikes(logData),
      unusualActivity: this.detectUnusualActivity(logData),
      performancePatterns: this.analyzePerformancePatterns(logData),
    };

    return patterns;
  }

  /**
   * Find repeating message patterns
   */
  findRepeatingMessages(logs, limit) {
    const messagePatterns = {};
    
    for (const log of logs) {
      // Extract pattern from message (first 100 chars, normalized)
      const pattern = log.message
        ?.toLowerCase()
        .replace(/\d+/g, 'N') // Replace numbers with N
        .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, 'UUID') // Replace UUIDs
        .substring(0, 100);

      if (!pattern) continue;

      if (!messagePatterns[pattern]) {
        messagePatterns[pattern] = {
          count: 0,
          firstSeen: log.timestamp,
          lastSeen: log.timestamp,
          severity: log.severity,
          components: new Set(),
        };
      }

      messagePatterns[pattern].count++;
      messagePatterns[pattern].lastSeen = log.timestamp;
      messagePatterns[pattern].components.add(log.component || 'unknown');
    }

    // Filter and sort
    return Object.entries(messagePatterns)
      .filter(([pattern, data]) => data.count >= 3) // At least 3 occurrences
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, limit)
      .map(([pattern, data]) => ({
        pattern,
        count: data.count,
        firstSeen: data.firstSeen,
        lastSeen: data.lastSeen,
        severity: data.severity,
        components: Array.from(data.components),
      }));
  }

  /**
   * Detect error spikes
   */
  detectErrorSpikes(logs) {
    const errorsByHour = {};
    
    const errorLogs = logs.filter(log => 
      log.severity === 'error' || log.severity === 'critical'
    );

    for (const log of errorLogs) {
      const hour = new Date(log.timestamp).toISOString().slice(0, 13); // YYYY-MM-DDTHH
      errorsByHour[hour] = (errorsByHour[hour] || 0) + 1;
    }

    const hours = Object.keys(errorsByHour).sort();
    const errorCounts = hours.map(hour => errorsByHour[hour]);
    
    if (errorCounts.length < 2) return [];

    // Simple spike detection - count > 2 * average
    const average = errorCounts.reduce((sum, count) => sum + count, 0) / errorCounts.length;
    const threshold = Math.max(average * 2, 5); // At least 5 errors

    const spikes = [];
    for (let i = 0; i < hours.length; i++) {
      if (errorCounts[i] > threshold) {
        spikes.push({
          hour: hours[i],
          errorCount: errorCounts[i],
          threshold: Math.round(threshold),
          severity: errorCounts[i] > threshold * 2 ? 'high' : 'medium',
        });
      }
    }

    return spikes;
  }

  /**
   * Detect unusual activity patterns
   */
  detectUnusualActivity(logs) {
    const unusual = [];

    // Activity outside business hours
    const businessHourActivity = logs.filter(log => {
      const hour = new Date(log.timestamp).getHours();
      return hour < 6 || hour > 22; // Outside 6 AM - 10 PM
    });

    if (businessHourActivity.length > 0) {
      unusual.push({
        type: 'off_hours_activity',
        count: businessHourActivity.length,
        percentage: ((businessHourActivity.length / logs.length) * 100).toFixed(2),
        description: 'Significant activity detected outside business hours',
      });
    }

    // High volume from single component
    const componentCounts = {};
    for (const log of logs) {
      const component = log.component || 'unknown';
      componentCounts[component] = (componentCounts[component] || 0) + 1;
    }

    const totalLogs = logs.length;
    for (const [component, count] of Object.entries(componentCounts)) {
      const percentage = (count / totalLogs) * 100;
      if (percentage > 50 && count > 10) {
        unusual.push({
          type: 'component_dominance',
          component,
          count,
          percentage: percentage.toFixed(2),
          description: `Component ${component} generated unusually high volume of logs`,
        });
      }
    }

    return unusual;
  }

  /**
   * Analyze performance patterns
   */
  analyzePerformancePatterns(logs) {
    const performanceLogs = logs.filter(log => log.duration);
    
    if (performanceLogs.length === 0) {
      return { message: 'No performance data available' };
    }

    // Analyze by endpoint
    const endpointPerformance = {};
    for (const log of performanceLogs) {
      const endpoint = log.endpoint || 'unknown';
      if (!endpointPerformance[endpoint]) {
        endpointPerformance[endpoint] = [];
      }
      endpointPerformance[endpoint].push(log.duration);
    }

    const patterns = {};
    for (const [endpoint, durations] of Object.entries(endpointPerformance)) {
      durations.sort((a, b) => a - b);
      
      patterns[endpoint] = {
        count: durations.length,
        average: durations.reduce((sum, d) => sum + d, 0) / durations.length,
        median: this.calculatePercentile(durations, 50),
        p95: this.calculatePercentile(durations, 95),
        slowest: durations[durations.length - 1],
      };
    }

    return patterns;
  }

  /**
   * Analyze trends over time
   */
  async analyzeTrends(options) {
    const { timeRange, interval, metrics, userId } = options;

    // Get logs for the time range
    const logs = await this.storage.retrieveLogs({
      startTime: timeRange.start,
      endTime: timeRange.end,
      userId,
      limit: 10000,
    });

    // Generate time buckets
    const buckets = this.generateTimeBuckets(timeRange, interval);
    
    // Analyze each metric
    const trends = {};
    for (const metric of metrics) {
      trends[metric] = this.calculateMetricTrend(logs, buckets, metric);
    }

    return {
      timeRange,
      interval,
      buckets: buckets.map(b => b.label),
      trends,
      generatedAt: new Date().toISOString(),
    };
  }

  /**
   * Generate time buckets for trend analysis
   */
  generateTimeBuckets(timeRange, interval) {
    const buckets = [];
    const start = new Date(timeRange.start);
    const end = new Date(timeRange.end);
    
    let current = new Date(start);
    let bucketDuration;
    
    switch (interval) {
      case 'minute':
        bucketDuration = 60 * 1000;
        break;
      case 'hour':
        bucketDuration = 60 * 60 * 1000;
        break;
      case 'day':
        bucketDuration = 24 * 60 * 60 * 1000;
        break;
      default:
        bucketDuration = 60 * 60 * 1000; // Default to hour
    }

    while (current < end) {
      const bucketEnd = new Date(current.getTime() + bucketDuration);
      buckets.push({
        start: new Date(current),
        end: bucketEnd > end ? end : bucketEnd,
        label: current.toISOString(),
      });
      current = bucketEnd;
    }

    return buckets;
  }

  /**
   * Calculate metric trend for time buckets
   */
  calculateMetricTrend(logs, buckets, metric) {
    const trendData = [];

    for (const bucket of buckets) {
      const bucketLogs = logs.filter(log => {
        const logTime = new Date(log.timestamp);
        return logTime >= bucket.start && logTime < bucket.end;
      });

      let value;
      switch (metric) {
        case 'count':
          value = bucketLogs.length;
          break;
        case 'severity':
          value = this.calculateSeverityScore(bucketLogs);
          break;
        case 'performance':
          value = this.calculateAveragePerformance(bucketLogs);
          break;
        case 'errors':
          value = bucketLogs.filter(log => 
            log.severity === 'error' || log.severity === 'critical'
          ).length;
          break;
        default:
          value = bucketLogs.length;
      }

      trendData.push({
        timestamp: bucket.start.toISOString(),
        value,
        count: bucketLogs.length,
      });
    }

    return trendData;
  }

  /**
   * Calculate severity score (weighted average)
   */
  calculateSeverityScore(logs) {
    if (logs.length === 0) return 0;

    const severityWeights = {
      critical: 5,
      high: 4,
      error: 4,
      warn: 3,
      warning: 3,
      info: 2,
      debug: 1,
    };

    let totalScore = 0;
    for (const log of logs) {
      const weight = severityWeights[log.severity?.toLowerCase()] || 2;
      totalScore += weight;
    }

    return totalScore / logs.length;
  }

  /**
   * Calculate average performance
   */
  calculateAveragePerformance(logs) {
    const durations = logs
      .map(log => log.duration)
      .filter(d => d && typeof d === 'number');

    if (durations.length === 0) return 0;

    return durations.reduce((sum, d) => sum + d, 0) / durations.length;
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
        start = new Date(now.getTime() - 24 * 60 * 60 * 1000); // Default 24h
    }

    return {
      start: start.toISOString(),
      end: now.toISOString(),
    };
  }

  /**
   * Get system metrics (admin only)
   */
  async getSystemMetrics(timeRange) {
    try {
      // This would integrate with the metrics system
      return {
        storageUsage: {
          kv: 'Not available', // Would need Cloudflare API integration
          d1: 'Not available',
        },
        requestVolume: 'Not available',
        errorRates: 'Not available',
        responseTime: 'Not available',
        note: 'System metrics require additional Cloudflare API integration',
      };
    } catch (error) {
      this.logger.error('Failed to get system metrics', { error: error.message });
      return { error: 'System metrics unavailable' };
    }
  }

  /**
   * Cache management
   */
  generateCacheKey(type, params) {
    return `analytics:${type}:${JSON.stringify(params)}`;
  }

  getCached(key) {
    const cached = this.cache.get(key);
    if (!cached) return null;

    const { data, timestamp } = cached;
    if (Date.now() - timestamp > this.cacheTimeout) {
      this.cache.delete(key);
      return null;
    }

    return data;
  }

  setCached(key, data) {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
    });

    // Simple cache cleanup - remove old entries
    if (this.cache.size > 100) {
      const oldEntries = Array.from(this.cache.entries())
        .filter(([k, v]) => Date.now() - v.timestamp > this.cacheTimeout);
      
      for (const [key] of oldEntries) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Create response
   */
  createResponse(data, status = 200) {
    return new Response(JSON.stringify(data, null, 2), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'private, max-age=300', // 5 minutes cache
      },
    });
  }
}