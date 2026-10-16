/**
 * Security Middleware for Playwright MCP Server
 * Provides:
 * 1. Token-based authentication (Bearer Header, X-API-Key, Query Parameter, and Session Tracking)
 * 2. SSRF Protection (Blocks browser navigation to private/internal IPs & loopback)
 * 3. Health check endpoint (/health, /ping) for reverse proxies & Docker healthchecks
 */

const http = require('http');
const https = require('https');
const net = require('net');

class SecurityManager {
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.MCP_API_KEY || null;
    this.blockInternalIPs = options.blockInternalIPs !== undefined 
      ? options.blockInternalIPs 
      : (process.env.MCP_BLOCK_INTERNAL_IPS !== 'false' && process.env.MCP_BLOCK_INTERNAL_IPS !== '0');
    
    // In-memory set of actively authenticated SSE sessions
    this.activeSessions = new Set();
    this.initialized = false;
  }

  isPrivateIp(ip) {
    if (net.isIPv4(ip)) {
      const parts = ip.split('.').map(Number);
      if (parts.length !== 4) return false;
      // 127.0.0.0/8 (Loopback)
      if (parts[0] === 127) return true;
      // 10.0.0.0/8 (Private)
      if (parts[0] === 10) return true;
      // 172.16.0.0/12 (Docker bridge / private)
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
      // 192.168.0.0/16 (Private LAN)
      if (parts[0] === 192 && parts[1] === 168) return true;
      // 169.254.0.0/16 (Link-local / Cloud metadata service)
      if (parts[0] === 169 && parts[1] === 254) return true;
      // 0.0.0.0/8
      if (parts[0] === 0) return true;
      return false;
    }
    if (net.isIPv6(ip)) {
      const lower = ip.toLowerCase();
      // ::1 Loopback
      if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
      // fc00::/7 (Unique local)
      if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
      // fe80::/10 (Link-local)
      if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
      return false;
    }
    return false;
  }

  isBlockedHost(hostname) {
    if (!hostname) return false;
    const lower = hostname.toLowerCase().trim();
    if (lower === 'localhost') return true;
    if (lower.endsWith('.local') || lower.endsWith('.internal')) return true;
    if (this.isPrivateIp(lower)) return true;
    return false;
  }

  authenticateRequest(req, res) {
    // 1. Healthcheck / Ping endpoints (always unauthenticated for monitoring/load balancers)
    const rawUrl = req.url || '/';
    if (rawUrl === '/health' || rawUrl === '/ping') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'healthy', timestamp: new Date().toISOString() }));
      return false; // Handled, do not forward
    }

    // If no API key configured, allow all requests with a notice
    if (!this.apiKey) {
      return true; // Forward to Playwright
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(rawUrl, 'http://localhost');
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad Request: Malformed URL' }));
      return false;
    }

    const authHeader = req.headers['authorization'];
    const xApiKey = req.headers['x-api-key'];
    const tokenQuery = parsedUrl.searchParams.get('token') || parsedUrl.searchParams.get('apiKey');
    const sessionId = parsedUrl.searchParams.get('sessionId') || req.headers['mcp-session-id'];

    let isAuthed = false;

    // Check Bearer token
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7).trim();
      if (token === this.apiKey) isAuthed = true;
    }

    // Check X-API-Key header
    if (xApiKey && xApiKey.trim() === this.apiKey) {
      isAuthed = true;
    }

    // Check URL query param token
    if (tokenQuery && tokenQuery.trim() === this.apiKey) {
      isAuthed = true;
    }

    // If request explicitly provided a valid credential
    if (isAuthed) {
      // If client is initiating an SSE session, intercept output to register the generated sessionId
      if (parsedUrl.pathname.startsWith('/sse') && req.method === 'GET') {
        const origWrite = res.write;
        const self = this;
        res.write = function (chunk, ...args) {
          if (typeof chunk === 'string' || Buffer.isBuffer(chunk)) {
            const match = chunk.toString().match(/sessionId=([a-zA-Z0-9_-]+)/);
            if (match && match[1]) {
              const sid = match[1];
              self.activeSessions.add(sid);
              res.once('close', () => {
                self.activeSessions.delete(sid);
              });
            }
          }
          return origWrite.apply(this, [chunk, ...args]);
        };
      }
      return true; // Forward to Playwright
    }

    // If no explicit credential, check if this is a follow-up POST message with an active authenticated sessionId
    if (sessionId && this.activeSessions.has(sessionId)) {
      return true; // Forward to Playwright
    }

    // Unauthorized
    res.writeHead(401, {
      'Content-Type': 'application/json',
      'WWW-Authenticate': 'Bearer realm="Playwright MCP"'
    });
    res.end(JSON.stringify({
      error: 'Unauthorized',
      message: 'Missing or invalid MCP API key. Provide via Authorization: Bearer <key>, X-API-Key header, or ?token=<key> query parameter.'
    }));
    return false; // Handled, do not forward
  }

  hookHttpServer(server) {
    const origEmit = server.emit;
    const self = this;

    server.emit = function (event, ...args) {
      if (event === 'request') {
        const [req, res] = args;
        const forward = self.authenticateRequest(req, res);
        if (!forward) {
          return true; // Handled internally
        }
      }
      return origEmit.apply(this, [event, ...args]);
    };
  }

  installHttpHooks() {
    const self = this;

    // Intercept http.createServer
    const origCreateHttpServer = http.createServer;
    http.createServer = function (...args) {
      const server = origCreateHttpServer.apply(this, args);
      self.hookHttpServer(server);
      return server;
    };

    // Intercept https.createServer
    const origCreateHttpsServer = https.createServer;
    https.createServer = function (...args) {
      const server = origCreateHttpsServer.apply(this, args);
      self.hookHttpServer(server);
      return server;
    };
  }

  hookBrowserContext(context) {
    if (!context || context._securitySsrfHooked) return;
    context._securitySsrfHooked = true;

    if (this.blockInternalIPs) {
      context.route('**/*', async (route) => {
        const req = route.request();
        const urlStr = req.url();
        try {
          const parsed = new URL(urlStr);
          // Block internal/loopback/cloud metadata hostnames
          if (this.isBlockedHost(parsed.hostname)) {
            console.warn(`[SECURITY SSRF] Blocked request to internal address: ${urlStr}`);
            return route.abort('accessdenied');
          }
        } catch (e) {
          // Allow about:, data:, etc.
        }
        return route.continue();
      });
    }
  }

  hookBrowser(browser) {
    if (!browser || browser._securityHooked) return;
    browser._securityHooked = true;

    const origNewContext = browser.newContext;
    const self = this;

    if (origNewContext) {
      browser.newContext = async function (...args) {
        const context = await origNewContext.apply(this, args);
        self.hookBrowserContext(context);
        return context;
      };
    }

    if (browser.contexts && typeof browser.contexts === 'function') {
      for (const ctx of browser.contexts()) {
        self.hookBrowserContext(ctx);
      }
    }
  }

  installBrowserHooks() {
    try {
      const pwCore = require('playwright-core');
      const browserTypes = ['chromium', 'firefox', 'webkit'];
      const self = this;

      for (const bType of browserTypes) {
        const browserType = pwCore[bType];
        if (browserType && browserType.launch) {
          const origLaunch = browserType.launch;
          browserType.launch = async function (...args) {
            const browser = await origLaunch.apply(this, args);
            self.hookBrowser(browser);
            return browser;
          };

          if (browserType.launchPersistentContext) {
            const origLaunchPersistent = browserType.launchPersistentContext;
            browserType.launchPersistentContext = async function (...args) {
              const context = await origLaunchPersistent.apply(this, args);
              self.hookBrowserContext(context);
              return context;
            };
          }
        }
      }
    } catch (e) {
      // playwright-core might not be loaded yet or using a bundled version
    }
  }

  init() {
    if (this.initialized) return;
    this.initialized = true;

    this.installHttpHooks();
    this.installBrowserHooks();

    if (this.apiKey) {
      console.log('🔒 [SECURITY] Playwright MCP Security Middleware ACTIVE: API Key Authentication enabled.');
    } else {
      console.warn('⚠️  [SECURITY] WARNING: No MCP_API_KEY detected. Running in open/unauthenticated mode.');
    }

    if (this.blockInternalIPs) {
      console.log('🛡️  [SECURITY] SSRF Protection ACTIVE: Internal IPs & Loopback addresses are blocked.');
    } else {
      console.warn('⚠️  [SECURITY] SSRF Protection DISABLED: Internal IPs permitted.');
    }
  }
}

// Singleton instance
let defaultManager = null;

function initSecurity(options = {}) {
  if (!defaultManager) {
    defaultManager = new SecurityManager(options);
    defaultManager.init();
  }
  return defaultManager;
}

module.exports = {
  SecurityManager,
  initSecurity
};
