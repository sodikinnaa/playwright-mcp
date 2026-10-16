#!/usr/bin/env node
/**
 * Copyright (c) Microsoft Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const { program } = require('playwright-core/lib/utilsBundle');
const { tools, libCli } = require('playwright-core/lib/coreBundle');

if (process.argv.includes('install-browser')) {
  const argv = process.argv.map(arg => arg === 'install-browser' ? 'install' : arg);
  libCli.decorateProgram(program);
  void program.parseAsync(argv);
  return;
}

// Initialize security layer before Playwright MCP starts
let apiKeyFromArg = null;
const apiKeyIndex = process.argv.indexOf('--api-key');
if (apiKeyIndex !== -1 && process.argv[apiKeyIndex + 1]) {
  apiKeyFromArg = process.argv[apiKeyIndex + 1];
  process.argv.splice(apiKeyIndex, 2);
}

const { initSecurity } = require('./security');
initSecurity({
  apiKey: apiKeyFromArg || process.env.MCP_API_KEY
});

// Ensure reverse proxy hosts (e.g. browser.siapdigital.id) are permitted by Playwright's host checker
if (!process.argv.includes('--allowed-hosts')) {
  process.argv.push('--allowed-hosts', process.env.MCP_ALLOWED_HOSTS || '*');
}

// Run in isolated in-memory profile mode to prevent profile lock conflicts ("Browser is already in use")
if (!process.argv.includes('--isolated')) {
  process.argv.push('--isolated');
}

const packageJSON = require('./package.json');
const p = program.version('Version ' + packageJSON.version).name('Playwright MCP');
tools.decorateMCPCommand(p, packageJSON.version);

void program.parseAsync(process.argv);
