/**
 * Enhanced Analytics Engine - Advanced analysis with ML-inspired patterns
 * Implements proactive insights and anomaly detection as suggested in feedback
 */

import { Logger } from '../utils/logger.js';
import { ErrorHandler } from '../utils/errorHandler.js';

export class AdvancedAnalyticsEngine {
  constructor(logStorage, config) {
    this.storage = logStorage;
    this.config = config;
    this.logger = new Logger('AdvancedAnalyticsEngine');
    
    // Historical patterns for anomaly detection
    this.baselinePatterns = new Map();
    this.anomalyThresholds = {
      errorRateIncrease: 2.0, // 2x normal error rate
      volumeSpike: 3.0, // 3x normal volume
      newErrorPattern: 0.8, // 80% confidence for new patterns
    };
  }

  /**
   * Generate proactive insights and recommendations
   */
  async generateProactiveInsights(timeRange, domain) {
    try {
      const insights = {
        timestamp: new Date().toISOString(),
        domain,
        timeRange,
        insights: [],
        recommendations: [],
        severity: 'info',
      };

      // Get recent logs for analysis
      const logs = await this.storage.retrieveLogs({
        startTime: timeRange.start,
        endTime: timeRange.end,
        limit: 10000,
      });

      // Analyze different aspects
      const errorPatternInsights = await this.analyzeErrorPatterns(logs);
      const performanceInsights = await this.analyzePerformancePatterns(logs);
      const securityInsights = await this.analyzeSecurityPatterns(logs);
      const systemHealthInsights = await this.analyzeSystemHealth(logs);
      const predictiveInsights = await this.generatePredictiveInsights(logs);

      // Combine all insights
      insights.insights.push(
        ...errorPatternInsights.insights,
        ...performanceInsights.insights,
        ...securityInsights.insights,
        ...systemHealthInsights.insights,
        ...predictiveInsights.insights
      );

      insights.recommendations.push(
        ...errorPatternInsights.recommendations,
        ...performanceInsights.recommendations,
        ...securityInsights.recommendations,
        ...systemHealthInsights.recommendations,
        ...predictiveInsights.recommendations
      );

      // Determine overall severity
      insights.severity = this.calculateOverallSeverity(insights.insights);

      this.logger.info('Proactive insights generated', {
        domain,
        insightsCount: insights.insights.length,
        recommendationsCount: insights.recommendations.length,
        severity: insights.severity,
      });

      return insights;

    } catch (error) {
      this.logger.error('Failed to generate proactive insights', {
        domain,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Analyze error patterns for proactive insights
   */
  async analyzeErrorPatterns(logs) {
    const insights = [];
    const recommendations = [];

    const errorLogs = logs.filter(log => 
      log.severity === 'error' || log.severity === 'critical'
    );

    if (errorLogs.length === 0) {
      return { insights, recommendations };
    }

    // Group errors by component and endpoint
    const errorGroups = this.groupErrorsByPattern(errorLogs);

    // Analyze each error group
    for (const [pattern, errors] of Object.entries(errorGroups)) {
      const errorCount = errors.length;
      const uniqueMessages = new Set(errors.map(e => e.message)).size;
      const timeSpan = this.calculateTimeSpan(errors);

      // Check for error spikes
      if (errorCount > 10 && timeSpan < 3600000) { // More than 10 errors in 1 hour
        insights.push({
          type: 'error_spike',
          severity: 'high',
          pattern,
          message: `Error spike detected: ${errorCount} errors in ${Math.round(timeSpan/60000)} minutes`,
          metadata: {
            errorCount,
            timeSpanMinutes: Math.round(timeSpan / 60000),
            uniqueMessages,
          },
        });

        recommendations.push({
          type: 'immediate_action',
          priority: 'high',
          title: `Investigate ${pattern} error spike`,
          description: `High frequency of errors detected in ${pattern}. Consider immediate investigation or automated restart.`,
          actions: [
            'Check system resources and dependencies',
            'Review recent deployments or configuration changes',
            'Consider implementing circuit breaker pattern',
            'Set up automated alerts for this pattern',
          ],
        });
      }

      // Check for recurring patterns
      if (uniqueMessages < errorCount * 0.3) { // Less than 30% unique messages indicates repetition
        insights.push({
          type: 'recurring_error_pattern',
          severity: 'medium',
          pattern,
          message: `Recurring error pattern detected: ${uniqueMessages} unique errors repeated ${errorCount} times`,
          metadata: {
            repetitionRate: ((errorCount - uniqueMessages) / errorCount * 100).toFixed(1),
          },
        });

        recommendations.push({
          type: 'optimization',
          priority: 'medium',
          title: `Fix recurring error in ${pattern}`,
          description: `The same errors are occurring repeatedly, indicating a systemic issue.`,
          actions: [
            'Implement proper error handling and retry logic',
            'Add input validation to prevent invalid requests',
            'Consider caching or rate limiting for this endpoint',
          ],
        });
      }
    }

    // Check for new error patterns
    const newPatterns = await this.detectNewErrorPatterns(errorLogs);
    for (const newPattern of newPatterns) {
      insights.push({
        type: 'new_error_pattern',
        severity: 'medium',
        pattern: newPattern.pattern,
        message: `New error pattern detected: ${newPattern.description}`,
        metadata: newPattern.metadata,
      });

      recommendations.push({
        type: 'monitoring',
        priority: 'medium',
        title: `Monitor new error pattern: ${newPattern.pattern}`,
        description: `A new type of error has emerged. Monitor closely to understand impact.`,
        actions: [
          'Set up specific monitoring for this error type',
          'Analyze root cause and impact on users',
          'Document error pattern for future reference',
        ],
      });
    }

    return { insights, recommendations };
  }

  /**
   * Analyze performance patterns
   */
  async analyzePerformancePatterns(logs) {
    const insights = [];
    const recommendations = [];

    const performanceLogs = logs.filter(log => 
      log.duration || log.category === 'performance'
    );

    if (performanceLogs.length === 0) {
      return { insights, recommendations };
    }

    // Group by endpoint for performance analysis
    const endpointPerformance = {};
    for (const log of performanceLogs) {
      const endpoint = log.endpoint || 'unknown';
      if (!endpointPerformance[endpoint]) {
        endpointPerformance[endpoint] = [];
      }
      if (log.duration) {
        endpointPerformance[endpoint].push(log.duration);
      }
    }

    // Analyze each endpoint's performance
    for (const [endpoint, durations] of Object.entries(endpointPerformance)) {
      if (durations.length < 5) continue; // Need sufficient data

      durations.sort((a, b) => a - b);
      const p50 = this.calculatePercentile(durations, 50);
      const p95 = this.calculatePercentile(durations, 95);
      const p99 = this.calculatePercentile(durations, 99);
      const average = durations.reduce((sum, d) => sum + d, 0) / durations.length;

      // Check for performance degradation
      if (p95 > 5000) { // 5 seconds
        insights.push({
          type: 'performance_degradation',
          severity: p95 > 10000 ? 'high' : 'medium',
          pattern: endpoint,
          message: `Performance degradation detected: P95 response time is ${Math.round(p95)}ms`,
          metadata: {
            p50: Math.round(p50),
            p95: Math.round(p95),
            p99: Math.round(p99),
            average: Math.round(average),
          },
        });

        recommendations.push({
          type: 'performance_optimization',
          priority: p95 > 10000 ? 'high' : 'medium',
          title: `Optimize performance for ${endpoint}`,
          description: `Response times are significantly higher than expected.`,
          actions: [
            'Profile the endpoint for bottlenecks',
            'Check database query performance',
            'Consider implementing caching',
            'Review resource allocation and scaling',
          ],
        });
      }

      // Check for high variability
      const variability = (p95 - p50) / p50;
      if (variability > 2.0) { // P95 is more than 3x P50
        insights.push({
          type: 'performance_variability',
          severity: 'medium',
          pattern: endpoint,
          message: `High performance variability detected: P95 is ${variability.toFixed(1)}x P50`,
          metadata: {
            variabilityRatio: variability.toFixed(2),
            p50: Math.round(p50),
            p95: Math.round(p95),
          },
        });

        recommendations.push({
          type: 'stability_improvement',
          priority: 'medium',
          title: `Stabilize performance for ${endpoint}`,
          description: `Response times are highly variable, indicating unstable performance.`,
          actions: [
            'Investigate resource contention',
            'Review concurrent request handling',
            'Consider load balancing improvements',
            'Implement performance monitoring alerts',
          ],
        });
      }
    }

    return { insights, recommendations };
  }

  /**
   * Analyze security patterns
   */
  async analyzeSecurityPatterns(logs) {
    const insights = [];
    const recommendations = [];

    const securityLogs = logs.filter(log =>
      log.category === 'security' ||
      log.message?.toLowerCase().includes('security') ||
      log.message?.toLowerCase().includes('attack') ||
      log.message?.toLowerCase().includes('unauthorized')
    );

    if (securityLogs.length === 0) {
      return { insights, recommendations };
    }

    // Analyze authentication failures
    const authFailures = securityLogs.filter(log =>
      log.message?.toLowerCase().includes('authentication') ||
      log.message?.toLowerCase().includes('login') ||
      log.message?.toLowerCase().includes('unauthorized')
    );

    if (authFailures.length > 0) {
      // Group by IP address or user
      const failuresBySource = {};
      for (const log of authFailures) {
        const source = log.metadata?.ip || log.userId || 'unknown';
        failuresBySource[source] = (failuresBySource[source] || 0) + 1;
      }

      // Check for potential brute force
      for (const [source, count] of Object.entries(failuresBySource)) {
        if (count >= 10) { // 10 or more failures from same source
          insights.push({
            type: 'potential_brute_force',
            severity: count >= 50 ? 'critical' : 'high',
            pattern: 'authentication',
            message: `Potential brute force attack detected: ${count} failed attempts from ${source}`,
            metadata: {
              source,
              attemptCount: count,
            },
          });

          recommendations.push({
            type: 'security_action',
            priority: 'critical',
            title: `Block suspicious source: ${source}`,
            description: `High number of authentication failures indicates potential attack.`,
            actions: [
              'Temporarily block IP address or user account',
              'Review authentication logs for patterns',
              'Implement CAPTCHA or account lockout policies',
              'Alert security team for investigation',
            ],
          });
        }
      }
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      { pattern: /sql.*injection/i, type: 'sql_injection' },
      { pattern: /xss|cross.*site/i, type: 'xss_attempt' },
      { pattern: /csrf|cross.*site.*request/i, type: 'csrf_attempt' },
    ];

    for (const { pattern, type } of suspiciousPatterns) {
      const matches = securityLogs.filter(log => pattern.test(log.message));
      if (matches.length > 0) {
        insights.push({
          type: 'security_threat',
          severity: 'high',
          pattern: type,
          message: `Security threat detected: ${matches.length} ${type.replace('_', ' ')} attempts`,
          metadata: {
            threatType: type,
            attemptCount: matches.length,
          },
        });

        recommendations.push({
          type: 'security_hardening',
          priority: 'high',
          title: `Strengthen defenses against ${type.replace('_', ' ')}`,
          description: `Active attempts detected. Review and strengthen security measures.`,
          actions: [
            'Review input validation and sanitization',
            'Update security headers and policies',
            'Implement Web Application Firewall rules',
            'Conduct security audit of affected components',
          ],
        });
      }
    }

    return { insights, recommendations };
  }

  /**
   * Analyze overall system health
   */
  async analyzeSystemHealth(logs) {
    const insights = [];
    const recommendations = [];

    // Calculate error rates
    const totalLogs = logs.length;
    const errorLogs = logs.filter(log => 
      log.severity === 'error' || log.severity === 'critical'
    ).length;
    
    const errorRate = totalLogs > 0 ? (errorLogs / totalLogs) * 100 : 0;

    // Check error rate thresholds
    if (errorRate > 10) {
      insights.push({
        type: 'high_error_rate',
        severity: errorRate > 25 ? 'critical' : 'high',
        pattern: 'system_health',
        message: `High system error rate detected: ${errorRate.toFixed(1)}%`,
        metadata: {
          errorRate: errorRate.toFixed(2),
          errorCount: errorLogs,
          totalLogs,
        },
      });

      recommendations.push({
        type: 'system_investigation',
        priority: errorRate > 25 ? 'critical' : 'high',
        title: 'Investigate system health issues',
        description: `Error rate is significantly above normal levels.`,
        actions: [
          'Check system resources and dependencies',
          'Review recent deployments or changes',
          'Examine infrastructure health',
          'Consider rolling back recent changes',
        ],
      });
    }

    // Analyze component health
    const componentHealth = this.analyzeComponentHealth(logs);
    for (const [component, health] of Object.entries(componentHealth)) {
      if (health.errorRate > 20) {
        insights.push({
          type: 'component_health_issue',
          severity: health.errorRate > 50 ? 'high' : 'medium',
          pattern: component,
          message: `Component health issue: ${component} has ${health.errorRate.toFixed(1)}% error rate`,
          metadata: health,
        });

        recommendations.push({
          type: 'component_investigation',
          priority: health.errorRate > 50 ? 'high' : 'medium',
          title: `Investigate ${component} component`,
          description: `This component is showing elevated error rates.`,
          actions: [
            'Review component logs in detail',
            'Check component dependencies',
            'Consider component restart or scaling',
            'Review component-specific metrics',
          ],
        });
      }
    }

    return { insights, recommendations };
  }

  /**
   * Generate predictive insights using pattern analysis
   */
  async generatePredictiveInsights(logs) {
    const insights = [];
    const recommendations = [];

    // Analyze trends over time
    const trends = this.analyzeTimeTrends(logs);
    
    // Predict potential issues based on trends
    if (trends.errorTrend > 0.1) { // 10% increase in errors
      insights.push({
        type: 'predictive_error_increase',
        severity: 'medium',
        pattern: 'trend_analysis',
        message: `Trending increase in errors detected: ${(trends.errorTrend * 100).toFixed(1)}% growth rate`,
        metadata: {
          trendRate: trends.errorTrend,
          projectedIncrease: (trends.errorTrend * 100).toFixed(1),
        },
      });

      recommendations.push({
        type: 'preventive_action',
        priority: 'medium',
        title: 'Prepare for potential error increase',
        description: `Error rates are trending upward. Take preventive action.`,
        actions: [
          'Monitor system capacity and scaling',
          'Review error handling and recovery procedures',
          'Prepare incident response procedures',
          'Consider proactive scaling or optimization',
        ],
      });
    }

    // Detect capacity issues
    const capacityIssues = this.predictCapacityIssues(logs);
    for (const issue of capacityIssues) {
      insights.push({
        type: 'capacity_prediction',
        severity: 'medium',
        pattern: issue.resource,
        message: `Potential capacity issue predicted: ${issue.description}`,
        metadata: issue.metrics,
      });

      recommendations.push({
        type: 'capacity_planning',
        priority: 'medium',
        title: `Plan for ${issue.resource} capacity`,
        description: issue.description,
        actions: issue.recommendedActions,
      });
    }

    return { insights, recommendations };
  }

  /**
   * Group errors by meaningful patterns
   */
  groupErrorsByPattern(errorLogs) {
    const groups = {};

    for (const log of errorLogs) {
      const component = log.component || 'unknown';
      const endpoint = log.endpoint || 'unknown';
      const pattern = `${component}:${endpoint}`;

      if (!groups[pattern]) {
        groups[pattern] = [];
      }
      groups[pattern].push(log);
    }

    return groups;
  }

  /**
   * Calculate time span for a set of logs
   */
  calculateTimeSpan(logs) {
    if (logs.length < 2) return 0;

    const timestamps = logs.map(log => new Date(log.timestamp).getTime());
    return Math.max(...timestamps) - Math.min(...timestamps);
  }

  /**
   * Detect new error patterns
   */
  async detectNewErrorPatterns(errorLogs) {
    const newPatterns = [];
    
    // This would integrate with historical baseline data
    // For now, implement simple heuristics
    
    const patternCounts = {};
    for (const log of errorLogs) {
      const pattern = this.extractErrorPattern(log.message);
      patternCounts[pattern] = (patternCounts[pattern] || 0) + 1;
    }

    // Check for patterns that seem new (simplified logic)
    for (const [pattern, count] of Object.entries(patternCounts)) {
      if (count >= 3 && !this.isKnownPattern(pattern)) {
        newPatterns.push({
          pattern,
          description: `New error pattern: ${pattern}`,
          metadata: {
            occurrences: count,
            confidence: Math.min(count / 10, 1.0),
          },
        });
      }
    }

    return newPatterns;
  }

  /**
   * Extract error pattern from message
   */
  extractErrorPattern(message) {
    if (!message) return 'unknown';
    
    // Normalize the message to create a pattern
    return message
      .toLowerCase()
      .replace(/\d+/g, 'N') // Replace numbers
      .replace(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g, 'UUID') // UUIDs
      .replace(/https?:\/\/[^\s]+/g, 'URL') // URLs
      .substring(0, 100); // Limit length
  }

  /**
   * Check if pattern is known (placeholder)
   */
  isKnownPattern(pattern) {
    // This would check against historical baseline
    // For now, return false to treat all as potentially new
    return false;
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
   * Analyze component health
   */
  analyzeComponentHealth(logs) {
    const componentStats = {};

    for (const log of logs) {
      const component = log.component || 'unknown';
      
      if (!componentStats[component]) {
        componentStats[component] = {
          totalLogs: 0,
          errorLogs: 0,
          errorRate: 0,
        };
      }

      componentStats[component].totalLogs++;
      
      if (log.severity === 'error' || log.severity === 'critical') {
        componentStats[component].errorLogs++;
      }
    }

    // Calculate error rates
    for (const stats of Object.values(componentStats)) {
      stats.errorRate = stats.totalLogs > 0 
        ? (stats.errorLogs / stats.totalLogs) * 100 
        : 0;
    }

    return componentStats;
  }

  /**
   * Analyze time trends
   */
  analyzeTimeTrends(logs) {
    if (logs.length < 10) {
      return { errorTrend: 0, volumeTrend: 0 };
    }

    // Sort logs by timestamp
    const sortedLogs = logs.sort((a, b) => 
      new Date(a.timestamp) - new Date(b.timestamp)
    );

    // Split into first and second half
    const midpoint = Math.floor(sortedLogs.length / 2);
    const firstHalf = sortedLogs.slice(0, midpoint);
    const secondHalf = sortedLogs.slice(midpoint);

    // Calculate error rates for each half
    const firstHalfErrors = firstHalf.filter(log => 
      log.severity === 'error' || log.severity === 'critical'
    ).length;
    const secondHalfErrors = secondHalf.filter(log => 
      log.severity === 'error' || log.severity === 'critical'
    ).length;

    const firstErrorRate = firstHalf.length > 0 ? firstHalfErrors / firstHalf.length : 0;
    const secondErrorRate = secondHalf.length > 0 ? secondHalfErrors / secondHalf.length : 0;

    // Calculate trend (simplified linear trend)
    const errorTrend = firstErrorRate > 0 
      ? (secondErrorRate - firstErrorRate) / firstErrorRate 
      : 0;

    const volumeTrend = firstHalf.length > 0 
      ? (secondHalf.length - firstHalf.length) / firstHalf.length 
      : 0;

    return { errorTrend, volumeTrend };
  }

  /**
   * Predict capacity issues
   */
  predictCapacityIssues(logs) {
    const issues = [];

    // Check volume trends
    const volumeMetrics = this.analyzeVolumeMetrics(logs);
    
    if (volumeMetrics.growthRate > 0.5) { // 50% growth
      issues.push({
        resource: 'log_volume',
        description: `Log volume growing at ${(volumeMetrics.growthRate * 100).toFixed(1)}% rate`,
        metrics: volumeMetrics,
        recommendedActions: [
          'Monitor storage capacity and scaling',
          'Review log retention policies',
          'Consider log sampling for high-volume sources',
          'Optimize log processing performance',
        ],
      });
    }

    return issues;
  }

  /**
   * Analyze volume metrics
   */
  analyzeVolumeMetrics(logs) {
    // Simplified volume analysis
    const totalLogs = logs.length;
    const timeSpan = this.calculateTimeSpan(logs);
    const logsPerHour = timeSpan > 0 ? (totalLogs / (timeSpan / 3600000)) : 0;

    return {
      totalLogs,
      timeSpanHours: timeSpan / 3600000,
      logsPerHour: logsPerHour.toFixed(2),
      growthRate: 0.1, // Simplified - would need historical comparison
    };
  }

  /**
   * Calculate overall severity from insights
   */
  calculateOverallSeverity(insights) {
    if (insights.some(i => i.severity === 'critical')) return 'critical';
    if (insights.some(i => i.severity === 'high')) return 'high';
    if (insights.some(i => i.severity === 'medium')) return 'medium';
    return 'info';
  }
}