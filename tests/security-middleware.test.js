const assert = require('assert');
const http = require('http');
const { SecurityManager } = require('../security');
const { chromium } = require('playwright-core');

async function runTests() {
  console.log('🧪 Starting Security Middleware Test Suite...\n');

  const TEST_API_KEY = 'test-secret-key-gemari-2026';
  const manager = new SecurityManager({
    apiKey: TEST_API_KEY,
    blockInternalIPs: true
  });

  // ---------------------------------------------------------------------------
  // 1. UNIT TESTS: SSRF Host & IP Detection
  // ---------------------------------------------------------------------------
  console.log('--- 1. Testing SSRF Host & IP Detection ---');

  // Should block:
  assert.strictEqual(manager.isBlockedHost('localhost'), true, 'localhost must be blocked');
  assert.strictEqual(manager.isBlockedHost('127.0.0.1'), true, '127.0.0.1 must be blocked');
  assert.strictEqual(manager.isBlockedHost('127.0.1.1'), true, '127.0.1.1 must be blocked');
  assert.strictEqual(manager.isBlockedHost('10.0.0.1'), true, '10.0.0.1 must be blocked');
  assert.strictEqual(manager.isBlockedHost('172.16.0.1'), true, '172.16.0.1 must be blocked');
  assert.strictEqual(manager.isBlockedHost('172.24.0.1'), true, '172.24.0.1 must be blocked');
  assert.strictEqual(manager.isBlockedHost('172.31.255.255'), true, '172.31.255.255 must be blocked');
  assert.strictEqual(manager.isBlockedHost('192.168.1.1'), true, '192.168.1.1 must be blocked');
  assert.strictEqual(manager.isBlockedHost('169.254.169.254'), true, 'Cloud metadata IP must be blocked');
  assert.strictEqual(manager.isBlockedHost('dev.local'), true, '.local domain must be blocked');
  assert.strictEqual(manager.isBlockedHost('service.internal'), true, '.internal domain must be blocked');
  assert.strictEqual(manager.isBlockedHost('::1'), true, 'IPv6 loopback must be blocked');

  // Should allow:
  assert.strictEqual(manager.isBlockedHost('google.com'), false, 'google.com must be allowed');
  assert.strictEqual(manager.isBlockedHost('gemaritematik.com'), false, 'gemaritematik.com must be allowed');
  assert.strictEqual(manager.isBlockedHost('demo.gemaritematik.com'), false, 'demo.gemaritematik.com must be allowed');
  assert.strictEqual(manager.isBlockedHost('103.42.245.208'), false, 'Public server IP must be allowed');
  assert.strictEqual(manager.isBlockedHost(''), false, 'Empty host (about:blank) must be allowed');

  console.log('✅ SSRF Host & IP Detection passed!\n');

  // ---------------------------------------------------------------------------
  // 2. INTEGRATION TESTS: HTTP Authentication & Session Tracking
  // ---------------------------------------------------------------------------
  console.log('--- 2. Testing HTTP Authentication & Session Tracking ---');

  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/sse') && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write('event: endpoint\ndata: /sse?sessionId=session-live-123\n\n');
      return;
    }
    if (req.url.startsWith('/sse') && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Message received' }));
      return;
    }
    res.end('OK');
  });

  manager.hookHttpServer(server);

  await new Promise((resolve) => server.listen(9870, '127.0.0.1', resolve));
  const baseUrl = 'http://127.0.0.1:9870';

  // Test 2.1: Health check (/health)
  const resHealth = await fetch(`${baseUrl}/health`);
  assert.strictEqual(resHealth.status, 200, 'Health check must return 200 without auth');
  const healthJson = await resHealth.json();
  assert.strictEqual(healthJson.status, 'healthy');
  console.log('  ✓ /health endpoint accessible without auth (200 OK)');

  // Test 2.2: Unauthenticated GET /sse
  const resUnauth = await fetch(`${baseUrl}/sse`);
  assert.strictEqual(resUnauth.status, 401, 'Unauthenticated /sse must return 401');
  console.log('  ✓ Unauthenticated request rejected (401 Unauthorized)');

  // Test 2.3: Authenticated GET /sse with Bearer Header
  const resBearer = await fetch(`${baseUrl}/sse`, {
    headers: { 'Authorization': `Bearer ${TEST_API_KEY}` }
  });
  assert.strictEqual(resBearer.status, 200, 'Bearer auth /sse must return 200');
  console.log('  ✓ Bearer Header auth accepted (200 OK)');

  // Test 2.4: Authenticated GET /sse with query param ?token=...
  const resQuery = await fetch(`${baseUrl}/sse?token=${TEST_API_KEY}`);
  assert.strictEqual(resQuery.status, 200, 'Query param token /sse must return 200');
  // Wait brief tick for res.write to register sessionId
  await new Promise(r => setTimeout(r, 60));
  console.log('  ✓ Query param token auth accepted (200 OK)');

  // Test 2.5: Authenticated GET /sse with X-API-Key header
  const resXApiKey = await fetch(`${baseUrl}/sse`, {
    headers: { 'X-API-Key': TEST_API_KEY }
  });
  assert.strictEqual(resXApiKey.status, 200, 'X-API-Key header auth must return 200');
  console.log('  ✓ X-API-Key header auth accepted (200 OK)');

  // Test 2.6: POST message with active sessionId registered from query stream
  const resPostSession = await fetch(`${baseUrl}/sse?sessionId=session-live-123`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  });
  assert.strictEqual(resPostSession.status, 200, 'POST with active session must be allowed');
  console.log('  ✓ POST with active authenticated session allowed (200 OK)');

  // Test 2.7: POST message with fake/invalid sessionId
  const resPostFake = await fetch(`${baseUrl}/sse?sessionId=fake-session-999`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  });
  assert.strictEqual(resPostFake.status, 401, 'POST with fake session must return 401');
  console.log('  ✓ POST with unknown sessionId rejected (401 Unauthorized)');

  server.close();
  console.log('✅ HTTP Authentication & Session Tracking passed!\n');

  // ---------------------------------------------------------------------------
  // 3. END-TO-END BROWSER TEST: SSRF Guard & Browser Operations
  // ---------------------------------------------------------------------------
  console.log('--- 3. Testing Browser SSRF Protection & Safe Navigation ---');

  const browser = await chromium.launch({ headless: true });
  manager.hookBrowser(browser);

  const context = await browser.newContext();
  const page = await context.newPage();

  // Test 3.1: Attempting to navigate to loopback / internal port must be aborted
  let blockedCaught = false;
  try {
    await page.goto('http://127.0.0.1:9870/', { timeout: 3000 });
  } catch (err) {
    if (err.message.includes('ERR_ACCESS_DENIED') || err.message.includes('net::ERR_ABORTED')) {
      blockedCaught = true;
    }
  }
  assert.strictEqual(blockedCaught, true, 'Internal IP navigation must be aborted by SSRF Guard');
  console.log('  ✓ SSRF Guard blocked navigation to 127.0.0.1 (net::ERR_ACCESS_DENIED)');

  // Test 3.2: Legitimate browser operations must work seamlessly
  const page2 = await context.newPage();
  await page2.setContent(`
    <html>
      <body>
        <h1 id="title">Playwright MCP Secure Remote Browser</h1>
        <button id="btn" onclick="document.getElementById('title').innerText = 'Clicked!'">Click Me</button>
      </body>
    </html>
  `);

  // Verify DOM query
  const titleText = await page2.textContent('#title');
  assert.strictEqual(titleText, 'Playwright MCP Secure Remote Browser');
  console.log('  ✓ Page content rendered and read successfully');

  // Verify Clicking
  await page2.click('#btn');
  const updatedTitle = await page2.textContent('#title');
  assert.strictEqual(updatedTitle, 'Clicked!');
  console.log('  ✓ Browser click interaction executed successfully');

  // Verify Screenshotting
  const screenshotBuffer = await page2.screenshot();
  assert.ok(screenshotBuffer && screenshotBuffer.length > 0, 'Screenshot buffer must not be empty');
  console.log(`  ✓ Browser screenshot captured successfully (${screenshotBuffer.length} bytes)`);

  // Verify JavaScript Evaluation
  const evalResult = await page2.evaluate(() => 2 + 2);
  assert.strictEqual(evalResult, 4);
  console.log('  ✓ JavaScript evaluation inside browser executed successfully');

  await browser.close();
  console.log('✅ Browser SSRF Protection & Safe Navigation passed!\n');

  console.log('🎉 ALL SECURITY TESTS PASSED SUCCESSFULLY! No disruption to remote browser processes.');
}

runTests().catch((err) => {
  console.error('❌ Test failed with error:', err);
  process.exit(1);
});
