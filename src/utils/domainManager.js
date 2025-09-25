/**
 * Domain Manager - Handles multi-tenant domain isolation and configuration
 * Implements per-domain settings and customer separation as suggested in feedback
 */

import { Logger } from './logger.js';
import { ErrorHandler } from './errorHandler.js';

export class DomainManager {
  constructor(config) {
    this.config = config;
    this.logger = new Logger('DomainManager');
    this.domainConfigs = new Map();
    
    // Initialize with default domain configurations
    this.initializeDefaultDomains();
  }

  /**
   * Initialize default domain configurations
   */
  initializeDefaultDomains() {
    const defaultDomains = [
      {
        domain: 'tamyla.com',
        subdomain: 'logger.tamyla.com',
        tenantId: 'tamyla-main',
        config: {
          retentionDays: 90,
          maxLogsPerDay: 100000,
          enableAnalytics: true,
          enableIntegrations: true,
          alertThresholds: {
            errorRate: 5, // 5% error rate
            criticalCount: 10, // 10 critical errors per hour
          },
        },
      },
      {
        domain: 'wetechfounders.com',
        subdomain: 'logger.wetechfounders.com',
        tenantId: 'wetech-main',
        config: {
          retentionDays: 30,
          maxLogsPerDay: 50000,
          enableAnalytics: true,
          enableIntegrations: false,
          alertThresholds: {
            errorRate: 3,
            criticalCount: 5,
          },
        },
      },
    ];

    for (const domainConfig of defaultDomains) {
      this.domainConfigs.set(domainConfig.domain, domainConfig);
    }
  }

  /**
   * Extract domain from request and validate
   */
  async extractDomainContext(request) {
    try {
      const url = new URL(request.url);
      const hostname = url.hostname;
      
      // Extract base domain (remove subdomains)
      let baseDomain = hostname;
      const parts = hostname.split('.');
      
      if (parts.length > 2) {
        // For subdomains like logger.tamyla.com, extract tamyla.com
        baseDomain = parts.slice(-2).join('.');
      }

      // Check if domain is registered
      const domainConfig = this.domainConfigs.get(baseDomain);
      
      if (!domainConfig) {
        // Check for wildcard or default configuration
        const defaultConfig = this.getDefaultDomainConfig(baseDomain);
        if (defaultConfig) {
          return defaultConfig;
        }
        
        throw ErrorHandler.createError(
          'UNKNOWN_DOMAIN',
          `Domain ${baseDomain} not configured for logging service`,
          403
        );
      }

      return {
        ...domainConfig,
        extractedDomain: baseDomain,
        originalHostname: hostname,
        isSubdomain: hostname !== baseDomain,
      };

    } catch (error) {
      this.logger.error('Failed to extract domain context', {
        url: request.url,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Register new domain configuration
   */
  async registerDomain(domainData) {
    try {
      const {
        domain,
        tenantId,
        config = {},
        contactEmail,
        plan = 'basic',
      } = domainData;

      // Validate domain format
      if (!this.isValidDomain(domain)) {
        throw ErrorHandler.createError(
          'INVALID_DOMAIN',
          'Invalid domain format provided',
          400
        );
      }

      // Check if domain already exists
      if (this.domainConfigs.has(domain)) {
        throw ErrorHandler.createError(
          'DOMAIN_EXISTS',
          `Domain ${domain} already registered`,
          409
        );
      }

      // Create domain configuration
      const domainConfig = {
        domain,
        subdomain: `logger.${domain}`,
        tenantId: tenantId || `tenant-${domain.replace(/\./g, '-')}`,
        config: {
          ...this.getDefaultConfigForPlan(plan),
          ...config,
        },
        contactEmail,
        plan,
        registeredAt: new Date().toISOString(),
        status: 'active',
      };

      // Store configuration
      this.domainConfigs.set(domain, domainConfig);

      this.logger.info('Domain registered successfully', {
        domain,
        tenantId: domainConfig.tenantId,
        plan,
      });

      return domainConfig;

    } catch (error) {
      this.logger.error('Domain registration failed', {
        domain: domainData?.domain,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get default configuration based on plan
   */
  getDefaultConfigForPlan(plan) {
    const plans = {
      basic: {
        retentionDays: 7,
        maxLogsPerDay: 10000,
        enableAnalytics: false,
        enableIntegrations: false,
        alertThresholds: {
          errorRate: 10,
          criticalCount: 20,
        },
      },
      standard: {
        retentionDays: 30,
        maxLogsPerDay: 100000,
        enableAnalytics: true,
        enableIntegrations: true,
        alertThresholds: {
          errorRate: 5,
          criticalCount: 10,
        },
      },
      premium: {
        retentionDays: 365,
        maxLogsPerDay: 1000000,
        enableAnalytics: true,
        enableIntegrations: true,
        enableAdvancedFeatures: true,
        alertThresholds: {
          errorRate: 1,
          criticalCount: 5,
        },
      },
    };

    return plans[plan] || plans.basic;
  }

  /**
   * Get default configuration for unknown domains
   */
  getDefaultDomainConfig(domain) {
    // Allow development/localhost domains
    if (this.isDevelopmentDomain(domain)) {
      return {
        domain,
        subdomain: `logger.${domain}`,
        tenantId: `dev-${domain}`,
        config: {
          retentionDays: 1,
          maxLogsPerDay: 1000,
          enableAnalytics: false,
          enableIntegrations: false,
          alertThresholds: {
            errorRate: 50,
            criticalCount: 100,
          },
        },
        plan: 'development',
        status: 'development',
      };
    }

    return null;
  }

  /**
   * Check if domain is for development
   */
  isDevelopmentDomain(domain) {
    const devPatterns = [
      /localhost/i,
      /127\.0\.0\.1/,
      /192\.168\./,
      /10\./,
      /\.local$/i,
      /\.dev$/i,
      /\.test$/i,
    ];

    return devPatterns.some(pattern => pattern.test(domain));
  }

  /**
   * Validate domain format
   */
  isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return domainRegex.test(domain) && domain.length <= 253;
  }

  /**
   * Update domain configuration
   */
  async updateDomainConfig(domain, updates) {
    try {
      const existingConfig = this.domainConfigs.get(domain);
      
      if (!existingConfig) {
        throw ErrorHandler.createError(
          'DOMAIN_NOT_FOUND',
          `Domain ${domain} not found`,
          404
        );
      }

      const updatedConfig = {
        ...existingConfig,
        ...updates,
        config: {
          ...existingConfig.config,
          ...updates.config,
        },
        updatedAt: new Date().toISOString(),
      };

      this.domainConfigs.set(domain, updatedConfig);

      this.logger.info('Domain configuration updated', {
        domain,
        updates: Object.keys(updates),
      });

      return updatedConfig;

    } catch (error) {
      this.logger.error('Failed to update domain config', {
        domain,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Check domain limits and quotas
   */
  async checkDomainLimits(domain, logCount = 1) {
    try {
      const domainConfig = this.domainConfigs.get(domain);
      
      if (!domainConfig) {
        return { allowed: false, reason: 'Domain not configured' };
      }

      const { config } = domainConfig;
      
      // Check daily log limit (would need to track actual usage)
      // This is a simplified check - in production, you'd query actual usage
      const dailyUsage = await this.getDailyLogUsage(domain);
      
      if (dailyUsage + logCount > config.maxLogsPerDay) {
        return {
          allowed: false,
          reason: 'Daily log limit exceeded',
          limit: config.maxLogsPerDay,
          usage: dailyUsage,
        };
      }

      return {
        allowed: true,
        remaining: config.maxLogsPerDay - dailyUsage - logCount,
      };

    } catch (error) {
      this.logger.error('Failed to check domain limits', {
        domain,
        error: error.message,
      });
      
      // Allow by default on error to avoid blocking
      return { allowed: true, reason: 'Limit check failed, allowing by default' };
    }
  }

  /**
   * Get daily log usage (placeholder - would integrate with metrics)
   */
  async getDailyLogUsage(domain) {
    // In production, this would query actual metrics
    // For now, return a mock value
    return Math.floor(Math.random() * 1000);
  }

  /**
   * List all registered domains
   */
  getAllDomains() {
    const domains = [];
    
    for (const [domain, config] of this.domainConfigs.entries()) {
      domains.push({
        domain,
        tenantId: config.tenantId,
        plan: config.plan,
        status: config.status,
        registeredAt: config.registeredAt,
        config: {
          retentionDays: config.config.retentionDays,
          maxLogsPerDay: config.config.maxLogsPerDay,
          enableAnalytics: config.config.enableAnalytics,
        },
      });
    }

    return domains.sort((a, b) => a.domain.localeCompare(b.domain));
  }

  /**
   * Get domain statistics
   */
  getDomainStats() {
    const stats = {
      totalDomains: this.domainConfigs.size,
      planDistribution: {},
      statusDistribution: {},
    };

    for (const config of this.domainConfigs.values()) {
      // Count by plan
      const plan = config.plan || 'unknown';
      stats.planDistribution[plan] = (stats.planDistribution[plan] || 0) + 1;

      // Count by status
      const status = config.status || 'unknown';
      stats.statusDistribution[status] = (stats.statusDistribution[status] || 0) + 1;
    }

    return stats;
  }

  /**
   * Generate tenant-specific storage keys
   */
  generateTenantKey(domain, keyType, identifier) {
    const domainConfig = this.domainConfigs.get(domain);
    const tenantId = domainConfig?.tenantId || `unknown-${domain}`;
    
    return `tenant:${tenantId}:${keyType}:${identifier}`;
  }

  /**
   * Export domain configurations
   */
  exportDomainConfigs() {
    return {
      exportedAt: new Date().toISOString(),
      domains: Object.fromEntries(this.domainConfigs.entries()),
      stats: this.getDomainStats(),
    };
  }

  /**
   * Import domain configurations
   */
  importDomainConfigs(configData) {
    try {
      if (!configData.domains || typeof configData.domains !== 'object') {
        throw new Error('Invalid domain configuration data');
      }

      let imported = 0;
      const errors = [];

      for (const [domain, config] of Object.entries(configData.domains)) {
        try {
          // Validate configuration
          if (this.isValidDomain(domain)) {
            this.domainConfigs.set(domain, config);
            imported++;
          } else {
            errors.push(`Invalid domain format: ${domain}`);
          }
        } catch (error) {
          errors.push(`Failed to import ${domain}: ${error.message}`);
        }
      }

      this.logger.info('Domain configurations imported', {
        imported,
        errors: errors.length,
      });

      return {
        success: true,
        imported,
        errors,
        importedAt: new Date().toISOString(),
      };

    } catch (error) {
      this.logger.error('Failed to import domain configs', {
        error: error.message,
      });
      
      return {
        success: false,
        error: error.message,
      };
    }
  }
}