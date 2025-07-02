const logger = require('../utils/logger');
const config = require('../config/config');

class AuditService {
  constructor() {
    this.events = new Map(); // In production, use database or external service
  }

  /**
   * Log an audit event
   */
  async log(action, data = {}) {
    try {
      if (!config.logging.enableAuditLogging) {
        return;
      }

      const auditEvent = {
        id: this.generateEventId(),
        action,
        timestamp: new Date().toISOString(),
        ...data
      };

      // Store in memory (in production, store in database)
      this.events.set(auditEvent.id, auditEvent);

      // Log to winston
      logger.audit(action, auditEvent);

      // Clean up old events periodically
      if (this.events.size > 10000) {
        this.cleanup();
      }

      return auditEvent.id;
    } catch (error) {
      logger.error('Error logging audit event:', error);
    }
  }

  /**
   * Get audit events with filtering
   */
  async getEvents(filters = {}) {
    try {
      const {
        userId,
        action,
        startDate,
        endDate,
        limit = 100,
        offset = 0
      } = filters;

      let events = Array.from(this.events.values());

      // Apply filters
      if (userId) {
        events = events.filter(event => event.userId === userId);
      }

      if (action) {
        events = events.filter(event => event.action === action);
      }

      if (startDate) {
        events = events.filter(event => new Date(event.timestamp) >= new Date(startDate));
      }

      if (endDate) {
        events = events.filter(event => new Date(event.timestamp) <= new Date(endDate));
      }

      // Sort by timestamp (newest first)
      events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      // Apply pagination
      const total = events.length;
      events = events.slice(offset, offset + limit);

      return {
        events,
        total,
        limit,
        offset
      };
    } catch (error) {
      logger.error('Error getting audit events:', error);
      throw error;
    }
  }

  /**
   * Get audit statistics
   */
  async getStatistics(timeframe = '24h') {
    try {
      const now = new Date();
      let startDate;

      switch (timeframe) {
        case '1h':
          startDate = new Date(now.getTime() - 60 * 60 * 1000);
          break;
        case '24h':
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
          break;
        case '7d':
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        case '30d':
          startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
          break;
        default:
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      }

      const events = Array.from(this.events.values())
        .filter(event => new Date(event.timestamp) >= startDate);

      const stats = {
        totalEvents: events.length,
        timeframe,
        startDate: startDate.toISOString(),
        endDate: now.toISOString(),
        eventsByAction: {},
        eventsByHour: {},
        securityEvents: 0,
        failedLogins: 0,
        successfulLogins: 0,
        rateLimitExceeded: 0,
        accessDenied: 0
      };

      // Count events by action
      events.forEach(event => {
        const action = event.action;
        stats.eventsByAction[action] = (stats.eventsByAction[action] || 0) + 1;

        // Count specific security events
        if (action.includes('failed') || action.includes('denied') || action.includes('exceeded')) {
          stats.securityEvents++;
        }

        if (action === 'login_failed') {
          stats.failedLogins++;
        }

        if (action === 'login_success') {
          stats.successfulLogins++;
        }

        if (action.includes('rate_limit_exceeded')) {
          stats.rateLimitExceeded++;
        }

        if (action === 'access_denied') {
          stats.accessDenied++;
        }

        // Count events by hour
        const hour = new Date(event.timestamp).getHours();
        stats.eventsByHour[hour] = (stats.eventsByHour[hour] || 0) + 1;
      });

      return stats;
    } catch (error) {
      logger.error('Error getting audit statistics:', error);
      throw error;
    }
  }

  /**
   * Get user activity
   */
  async getUserActivity(userId, limit = 50) {
    try {
      const events = Array.from(this.events.values())
        .filter(event => event.userId === userId)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, limit);

      return events;
    } catch (error) {
      logger.error('Error getting user activity:', error);
      throw error;
    }
  }

  /**
   * Get security events
   */
  async getSecurityEvents(limit = 100) {
    try {
      const securityActions = [
        'login_failed',
        'rate_limit_exceeded',
        'access_denied',
        'token_auth_failed',
        'suspicious_activity',
        'account_locked',
        'password_reset_requested',
        'email_verification_failed',
        '2fa_failed'
      ];

      const events = Array.from(this.events.values())
        .filter(event => securityActions.some(action => event.action.includes(action)))
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, limit);

      return events;
    } catch (error) {
      logger.error('Error getting security events:', error);
      throw error;
    }
  }

  /**
   * Generate unique event ID
   */
  generateEventId() {
    return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Clean up old events
   */
  cleanup() {
    try {
      const retentionMs = (config.logging.auditLogRetentionDays || 90) * 24 * 60 * 60 * 1000;
      const cutoffDate = new Date(Date.now() - retentionMs);

      let deletedCount = 0;
      for (const [id, event] of this.events.entries()) {
        if (new Date(event.timestamp) < cutoffDate) {
          this.events.delete(id);
          deletedCount++;
        }
      }

      if (deletedCount > 0) {
        logger.info(`Cleaned up ${deletedCount} old audit events`);
      }
    } catch (error) {
      logger.error('Error cleaning up audit events:', error);
    }
  }

  /**
   * Export audit events
   */
  async exportEvents(filters = {}, format = 'json') {
    try {
      const { events } = await this.getEvents(filters);

      switch (format.toLowerCase()) {
        case 'csv':
          return this.exportToCSV(events);
        case 'json':
        default:
          return JSON.stringify(events, null, 2);
      }
    } catch (error) {
      logger.error('Error exporting audit events:', error);
      throw error;
    }
  }

  /**
   * Export events to CSV format
   */
  exportToCSV(events) {
    if (events.length === 0) {
      return 'No events to export';
    }

    const headers = ['timestamp', 'action', 'userId', 'ip', 'userAgent', 'details'];
    const csvRows = [headers.join(',')];

    events.forEach(event => {
      const row = [
        event.timestamp,
        event.action,
        event.userId || '',
        event.ip || '',
        event.userAgent || '',
        JSON.stringify(event).replace(/"/g, '""') // Escape quotes
      ];
      csvRows.push(row.join(','));
    });

    return csvRows.join('\n');
  }

  /**
   * Search audit events
   */
  async searchEvents(query, filters = {}) {
    try {
      const { events } = await this.getEvents(filters);
      
      if (!query) {
        return events;
      }

      const searchQuery = query.toLowerCase();
      const matchedEvents = events.filter(event => {
        const searchableText = JSON.stringify(event).toLowerCase();
        return searchableText.includes(searchQuery);
      });

      return matchedEvents;
    } catch (error) {
      logger.error('Error searching audit events:', error);
      throw error;
    }
  }

  /**
   * Get compliance report
   */
  async getComplianceReport(startDate, endDate) {
    try {
      const events = await this.getEvents({ startDate, endDate, limit: 10000 });
      
      const report = {
        period: {
          start: startDate,
          end: endDate
        },
        summary: {
          totalEvents: events.events.length,
          uniqueUsers: new Set(events.events.map(e => e.userId).filter(Boolean)).size,
          securityIncidents: 0,
          dataAccess: 0,
          adminActions: 0,
          failedAuthentications: 0
        },
        details: {
          topActions: {},
          topUsers: {},
          securityEvents: [],
          complianceFlags: []
        }
      };

      // Analyze events
      events.events.forEach(event => {
        // Count actions
        report.details.topActions[event.action] = (report.details.topActions[event.action] || 0) + 1;
        
        // Count users
        if (event.userId) {
          report.details.topUsers[event.userId] = (report.details.topUsers[event.userId] || 0) + 1;
        }

        // Categorize events
        if (event.action.includes('failed') || event.action.includes('denied')) {
          report.summary.securityIncidents++;
          if (event.action === 'login_failed') {
            report.summary.failedAuthentications++;
          }
        }

        if (event.action.includes('data_access') || event.action.includes('read')) {
          report.summary.dataAccess++;
        }

        if (event.action.includes('admin') || event.userId && event.action.includes('role')) {
          report.summary.adminActions++;
        }

        // Flag compliance issues
        if (event.action === 'access_denied' && event.path?.includes('/admin/')) {
          report.details.complianceFlags.push({
            type: 'unauthorized_admin_access',
            event: event,
            severity: 'high'
          });
        }
      });

      return report;
    } catch (error) {
      logger.error('Error generating compliance report:', error);
      throw error;
    }
  }
}

module.exports = new AuditService();

