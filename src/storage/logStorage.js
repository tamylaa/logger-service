/**
 * Log Storage - Handles persistence using Cloudflare KV and D1 database
 * Provides fast access via KV and complex queries via D1
 */

export class LogStorage {
  constructor(config, env) {
    this.config = config;
    this.env = env;
    this.kv = env.LOGS_KV;
    this.db = env.LOGS_DB;
  }

  /**
   * Store a processed log entry
   */
  async storeLog(processedLog) {
    try {
      const logId = processedLog.id;
      const timestamp = new Date(processedLog.timestamp || processedLog.processedAt).getTime();
      
      // Store in KV for fast retrieval
      await this.storeInKV(logId, processedLog, timestamp);
      
      // Store in D1 for complex queries and analytics
      await this.storeInD1(processedLog, timestamp);
      
      return {
        success: true,
        logId,
        stored: {
          kv: true,
          d1: true,
        },
      };

    } catch (error) {
      throw new Error(`Failed to store log: ${error.message}`);
    }
  }

  /**
   * Store log in KV for fast access
   */
  async storeInKV(logId, log, timestamp) {
    const kvKey = `log:${logId}`;
    const kvValue = {
      ...log,
      storedAt: new Date().toISOString(),
    };

    await this.kv.put(kvKey, JSON.stringify(kvValue), {
      expirationTtl: this.config.logs.retentionDays * 24 * 60 * 60,
    });

    // Store time-based index for range queries
    const dateKey = new Date(timestamp).toISOString().split('T')[0];
    const timeIndexKey = `index:time:${dateKey}:${timestamp}:${logId}`;
    
    await this.kv.put(timeIndexKey, logId, {
      expirationTtl: this.config.logs.retentionDays * 24 * 60 * 60,
    });

    // Store category index
    if (log.category) {
      const categoryIndexKey = `index:category:${log.category}:${timestamp}:${logId}`;
      await this.kv.put(categoryIndexKey, logId, {
        expirationTtl: this.config.logs.retentionDays * 24 * 60 * 60,
      });
    }

    // Store severity index
    if (log.severity) {
      const severityIndexKey = `index:severity:${log.severity}:${timestamp}:${logId}`;
      await this.kv.put(severityIndexKey, logId, {
        expirationTtl: this.config.logs.retentionDays * 24 * 60 * 60,
      });
    }
  }

  /**
   * Store log in D1 database for complex queries
   */
  async storeInD1(log, timestamp) {
    const insertSQL = `
      INSERT INTO logs (
        id, timestamp, severity, category, source, component, endpoint,
        environment, message, error_type, error_code, stack_trace,
        user_id, session_id, request_id, ip_address, user_agent,
        metadata, tags, duration, memory_usage, feature, workflow, version,
        processed_at, processing_time, categorization_confidence,
        patterns, triage_level, triage_actions
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const params = [
      log.id,
      timestamp,
      log.severity,
      log.category,
      log.source,
      log.component,
      log.endpoint,
      log.environment,
      log.message,
      log.errorType,
      log.errorCode,
      log.stackTrace,
      log.userContext?.userId,
      log.sessionId,
      log.requestId,
      log.ipAddress,
      log.userAgent,
      JSON.stringify(log.metadata || {}),
      JSON.stringify(log.tags || []),
      log.duration,
      log.memoryUsage,
      log.feature,
      log.workflow,
      log.version,
      log.processedAt,
      log.processingMetrics?.processingTime,
      log.categorizationConfidence,
      JSON.stringify(log.patterns || []),
      log.triage?.level,
      JSON.stringify(log.triageActions || []),
    ];

    await this.db.prepare(insertSQL).bind(...params).run();
  }

  /**
   * Retrieve logs based on query parameters
   */
  async retrieveLogs(queryParams, user) {
    try {
      // For simple queries, use KV indexes
      if (this.canUseKVQuery(queryParams)) {
        return await this.retrieveFromKV(queryParams, user);
      }

      // For complex queries, use D1
      return await this.retrieveFromD1(queryParams, user);

    } catch (error) {
      throw new Error(`Failed to retrieve logs: ${error.message}`);
    }
  }

  /**
   * Check if query can be efficiently handled by KV
   */
  canUseKVQuery(queryParams) {
    // KV is good for simple time-based or single-category queries
    const hasSimpleFilters = (
      !queryParams.component &&
      !queryParams.endpoint &&
      !queryParams.tags?.length &&
      !queryParams.userId &&
      Object.keys(queryParams).filter(key => 
        !['page', 'limit', 'sortBy', 'sortOrder', 'startTime', 'endTime', 'severity', 'category'].includes(key)
      ).length === 0
    );

    return hasSimpleFilters && queryParams.limit <= 100;
  }

  /**
   * Retrieve logs from KV using indexes
   */
  async retrieveFromKV(queryParams, user) {
    const { page, limit, startTime, endTime, severity, category } = queryParams;
    const offset = (page - 1) * limit;

    let indexPrefix = 'index:time';
    
    // Use more specific index if available
    if (severity && !category) {
      indexPrefix = `index:severity:${severity}`;
    } else if (category && !severity) {
      indexPrefix = `index:category:${category}`;
    }

    // Build time range for listing keys
    const startDate = startTime ? new Date(startTime) : new Date(Date.now() - 24 * 60 * 60 * 1000);
    const endDate = endTime ? new Date(endTime) : new Date();

    const logIds = await this.getLogIdsFromTimeRange(indexPrefix, startDate, endDate, offset + limit);
    
    // Apply additional filtering
    const filteredIds = this.filterLogIds(logIds, queryParams).slice(offset, offset + limit);
    
    // Retrieve actual log data
    const logs = await this.getLogsByIds(filteredIds);
    
    // Apply user access control
    const authorizedLogs = this.filterLogsByAccess(logs, user);

    return {
      data: authorizedLogs,
      pagination: {
        page,
        limit,
        total: filteredIds.length,
        hasMore: filteredIds.length === limit,
      },
    };
  }

  /**
   * Retrieve logs from D1 database
   */
  async retrieveFromD1(queryParams, user) {
    const { page, limit, sortBy, sortOrder } = queryParams;
    const offset = (page - 1) * limit;

    // Build WHERE clause
    const { whereClause, params } = this.buildWhereClause(queryParams, user);
    
    // Build ORDER BY clause
    const orderBy = this.buildOrderByClause(sortBy, sortOrder);

    // Count total records
    const countSQL = `SELECT COUNT(*) as total FROM logs ${whereClause}`;
    const countResult = await this.db.prepare(countSQL).bind(...params).first();
    const total = countResult?.total || 0;

    // Retrieve paginated results
    const selectSQL = `
      SELECT * FROM logs 
      ${whereClause} 
      ${orderBy} 
      LIMIT ? OFFSET ?
    `;
    
    const results = await this.db.prepare(selectSQL)
      .bind(...params, limit, offset)
      .all();

    const logs = results.results?.map(row => this.parseLogFromD1(row)) || [];

    return {
      data: logs,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasMore: offset + limit < total,
      },
    };
  }

  /**
   * Search logs with advanced criteria
   */
  async searchLogs(searchCriteria, user) {
    const startTime = Date.now();

    try {
      const { query, filters, timeRange, sort, pagination, facets } = searchCriteria;

      // Build complex search query for D1
      const { searchSQL, params } = this.buildSearchQuery(searchCriteria, user);
      
      // Execute search
      const results = await this.db.prepare(searchSQL).bind(...params).all();
      const logs = results.results?.map(row => this.parseLogFromD1(row)) || [];

      // Get facet data if requested
      let facetData = {};
      if (facets?.length) {
        facetData = await this.getFacetData(facets, searchCriteria, user);
      }

      const executionTime = Date.now() - startTime;

      return {
        data: logs,
        pagination: {
          page: pagination?.page || 1,
          limit: pagination?.limit || 50,
          total: logs.length,
        },
        executionTime,
        totalMatches: logs.length,
        facets: facetData,
      };

    } catch (error) {
      throw new Error(`Search failed: ${error.message}`);
    }
  }

  /**
   * Get log summary statistics
   */
  async getLogSummary(timeRange, user) {
    try {
      const { whereClause, params } = this.buildWhereClause(timeRange, user);

      const summarySQL = `
        SELECT 
          severity,
          category,
          COUNT(*) as count,
          AVG(duration) as avg_duration,
          MAX(timestamp) as latest_timestamp
        FROM logs 
        ${whereClause}
        GROUP BY severity, category
        ORDER BY count DESC
      `;

      const results = await this.db.prepare(summarySQL).bind(...params).all();
      
      return {
        summary: results.results || [],
        timeRange,
        generatedAt: new Date().toISOString(),
      };

    } catch (error) {
      throw new Error(`Failed to get summary: ${error.message}`);
    }
  }

  /**
   * Get log IDs from time range index
   */
  async getLogIdsFromTimeRange(indexPrefix, startDate, endDate, maxResults = 1000) {
    // This is a simplified implementation
    // In practice, you'd need to implement efficient key listing
    const logIds = [];
    
    // For demo purposes, return empty array
    // In real implementation, you'd list KV keys with the prefix
    // and filter by timestamp
    
    return logIds;
  }

  /**
   * Filter log IDs based on query parameters
   */
  filterLogIds(logIds, queryParams) {
    // Apply additional filtering logic here
    return logIds;
  }

  /**
   * Get logs by their IDs from KV
   */
  async getLogsByIds(logIds) {
    const logs = [];
    
    for (const logId of logIds) {
      try {
        const logData = await this.kv.get(`log:${logId}`);
        if (logData) {
          logs.push(JSON.parse(logData));
        }
      } catch (error) {
        // Skip failed retrievals
        console.warn(`Failed to retrieve log ${logId}:`, error);
      }
    }
    
    return logs;
  }

  /**
   * Filter logs based on user access permissions
   */
  filterLogsByAccess(logs, user) {
    if (user.role === 'admin') {
      return logs;
    }

    // Filter logs user has access to
    return logs.filter(log => {
      // Users can see their own logs
      if (log.userContext?.userId === user.id) {
        return true;
      }

      // Check domain permissions
      if (user.domains?.includes(log.userContext?.userDomain)) {
        return true;
      }

      return false;
    });
  }

  /**
   * Build WHERE clause for D1 queries
   */
  buildWhereClause(queryParams, user) {
    const conditions = [];
    const params = [];

    // Time range
    if (queryParams.startTime) {
      conditions.push('timestamp >= ?');
      params.push(new Date(queryParams.startTime).getTime());
    }

    if (queryParams.endTime) {
      conditions.push('timestamp <= ?');
      params.push(new Date(queryParams.endTime).getTime());
    }

    // Filters
    const filterMappings = {
      severity: 'severity',
      category: 'category',
      source: 'source',
      component: 'component',
      endpoint: 'endpoint',
      environment: 'environment',
      userId: 'user_id',
      sessionId: 'session_id',
    };

    for (const [param, column] of Object.entries(filterMappings)) {
      if (queryParams[param]) {
        conditions.push(`${column} = ?`);
        params.push(queryParams[param]);
      }
    }

    // User access control
    if (user.role !== 'admin') {
      const userConditions = ['user_id = ?'];
      const userParams = [user.id];

      if (user.domains?.length) {
        userConditions.push(`user_domain IN (${user.domains.map(() => '?').join(', ')})`);
        userParams.push(...user.domains);
      }

      if (userConditions.length) {
        conditions.push(`(${userConditions.join(' OR ')})`);
        params.push(...userParams);
      }
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    return { whereClause, params };
  }

  /**
   * Build ORDER BY clause
   */
  buildOrderByClause(sortBy = 'timestamp', sortOrder = 'desc') {
    const allowedSortFields = {
      timestamp: 'timestamp',
      severity: 'severity',
      category: 'category',
      component: 'component',
      endpoint: 'endpoint',
    };

    const field = allowedSortFields[sortBy] || 'timestamp';
    const order = sortOrder.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    return `ORDER BY ${field} ${order}`;
  }

  /**
   * Build search query for complex searches
   */
  buildSearchQuery(searchCriteria, user) {
    const { query, filters, timeRange, sort, pagination } = searchCriteria;
    const conditions = [];
    const params = [];

    // Full-text search in message
    if (query) {
      conditions.push('message LIKE ?');
      params.push(`%${query}%`);
    }

    // Apply filters
    if (filters) {
      for (const [field, values] of Object.entries(filters)) {
        if (Array.isArray(values) && values.length) {
          const placeholders = values.map(() => '?').join(', ');
          conditions.push(`${field} IN (${placeholders})`);
          params.push(...values);
        }
      }
    }

    // Time range
    if (timeRange) {
      if (timeRange.startTime) {
        conditions.push('timestamp >= ?');
        params.push(new Date(timeRange.startTime).getTime());
      }
      if (timeRange.endTime) {
        conditions.push('timestamp <= ?');
        params.push(new Date(timeRange.endTime).getTime());
      }
    }

    // User access control
    if (user.role !== 'admin') {
      conditions.push('user_id = ?');
      params.push(user.id);
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const orderBy = this.buildOrderByClause(sort?.field, sort?.order);
    
    const limit = pagination?.limit || 50;
    const offset = ((pagination?.page || 1) - 1) * limit;

    const searchSQL = `
      SELECT * FROM logs 
      ${whereClause} 
      ${orderBy} 
      LIMIT ? OFFSET ?
    `;

    params.push(limit, offset);

    return { searchSQL, params };
  }

  /**
   * Get facet data for search results
   */
  async getFacetData(facets, searchCriteria, user) {
    const facetData = {};

    for (const facet of facets) {
      try {
        const { whereClause, params } = this.buildWhereClause(searchCriteria, user);
        
        const facetSQL = `
          SELECT ${facet}, COUNT(*) as count 
          FROM logs 
          ${whereClause} 
          GROUP BY ${facet} 
          ORDER BY count DESC 
          LIMIT 10
        `;

        const results = await this.db.prepare(facetSQL).bind(...params).all();
        facetData[facet] = results.results || [];
      } catch (error) {
        facetData[facet] = { error: error.message };
      }
    }

    return facetData;
  }

  /**
   * Parse log data from D1 database row
   */
  parseLogFromD1(row) {
    return {
      id: row.id,
      timestamp: new Date(row.timestamp).toISOString(),
      severity: row.severity,
      category: row.category,
      source: row.source,
      component: row.component,
      endpoint: row.endpoint,
      environment: row.environment,
      message: row.message,
      errorType: row.error_type,
      errorCode: row.error_code,
      stackTrace: row.stack_trace,
      userId: row.user_id,
      sessionId: row.session_id,
      requestId: row.request_id,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      metadata: row.metadata ? JSON.parse(row.metadata) : {},
      tags: row.tags ? JSON.parse(row.tags) : [],
      duration: row.duration,
      memoryUsage: row.memory_usage,
      feature: row.feature,
      workflow: row.workflow,
      version: row.version,
      processedAt: row.processed_at,
      processingTime: row.processing_time,
      categorizationConfidence: row.categorization_confidence,
      patterns: row.patterns ? JSON.parse(row.patterns) : [],
      triageLevel: row.triage_level,
      triageActions: row.triage_actions ? JSON.parse(row.triage_actions) : [],
    };
  }
}