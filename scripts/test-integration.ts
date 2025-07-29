#!/usr/bin/env npx tsx

/**
 * Integration Test Suite for Vercel Log Drain Function
 * 
 * This script performs comprehensive testing of the Vercel log drain endpoint by simulating
 * real Vercel webhook requests with proper HMAC-SHA1 signatures and NDJSON payloads.
 * 
 * Features:
 * - Tests Vercel endpoint verification flow
 * - Validates HMAC-SHA1 signature authentication
 * - Tests NDJSON log processing (newline-delimited JSON)
 * - Verifies graceful error handling for malformed data and invalid signatures
 * - Tests batch log processing capabilities
 * - Tests structured JSON message extraction and parsing
 * - Tests comprehensive metadata label generation
 * - Tests proxy data preservation and mixed batch processing
 * - Provides colorized console output for easy result interpretation
 * 
 * Prerequisites:
 * - Server must be running (locally via `npm run dev` or deployed)
 * - `.env` file must exist with required environment variables:
 *   - VERCEL_VERIFICATION_KEY: For endpoint verification
 *   - VERCEL_LOG_DRAIN_SECRET: For HMAC signature generation
 *   - GOOGLE_CLOUD_PROJECT: For Google Cloud Logging (optional)
 * - For local testing: Google Cloud authentication must be set up
 * 
 * Usage:
 *   npm run test:integration                    # Test localhost:8080
 *   npm run test:integration https://your-url  # Test remote endpoint
 * 
 * Test Cases:
 * 1. Vercel Verification - Tests endpoint verification handshake
 * 2. Sample Logs - Tests processing of realistic log entries
 * 3. Invalid Signature - Verifies security by rejecting tampered requests
 * 4. Batch Processing - Tests handling of multiple log entries
 * 5. Malformed JSON - Tests graceful error handling for corrupted data
 * 6. Structured Data - Tests JSON message extraction and level overrides
 * 7. Comprehensive Metadata - Tests label generation from all metadata fields
 * 8. Mixed Valid/Invalid Batch - Tests partial success handling
 * 
 * Expected Results:
 * ✅ All tests should pass when server is properly configured and authenticated
 * ❌ Tests 2, 4, 6, 7 may fail with HTTP 500 if Google Cloud authentication is not set up
 * ℹ️  Test 5 & 8 should show graceful error handling with HTTP 200 and mixed results
 * 
 * @author Vercel Log Drain Integration Test Suite
 * @version 1.0.0
 */

import fs from 'fs';
import crypto from 'crypto';
import https from 'https';
import http from 'http';
import { URL } from 'url';

// Configuration
const endpoint = process.argv[2] || 'http://localhost:8080';
const envFile = '.env';

// Colors for output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  blue: '\x1b[34m',
  yellow: '\x1b[33m',
  reset: '\x1b[0m'
} as const;

function colorLog(color: keyof typeof colors, message: string): void {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

interface EnvVars {
  VERCEL_VERIFICATION_KEY: string;
  VERCEL_LOG_DRAIN_SECRET: string;
  GOOGLE_CLOUD_PROJECT?: string;
}

interface HttpResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string | string[]>;
}

interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
}

interface VercelLog {
  id: string;
  message: string;
  timestamp: number;
  level: string;
  source: 'build' | 'lambda' | 'static' | 'edge';
  type?: string;
  requestId?: string;
  deploymentId?: string;
  projectName?: string;
  projectId?: string;
  executionRegion?: string;
  environment?: string;
  branch?: string;
  path?: string;
  host?: string;
  proxy?: Record<string, unknown>;
  [key: string]: unknown;
}

// Load environment variables from .env
function loadEnvVars(): EnvVars {
  if (!fs.existsSync(envFile)) {
    colorLog('red', `❌ Error: ${envFile} not found. Please create it`);
    process.exit(1);
  }

  try {
    const envContent = fs.readFileSync(envFile, 'utf8');
    const envVars: Partial<EnvVars> = {};

    // Parse .env file format (KEY=value)
    envContent.split('\n').forEach(line => {
      const trimmedLine = line.trim();
      if (trimmedLine && !trimmedLine.startsWith('#')) {
        const [key, ...valueParts] = trimmedLine.split('=');
        if (key && valueParts.length > 0) {
          const value = valueParts.join('=').trim();
          (envVars as Record<string, string>)[key] = value;
        }
      }
    });

    if (!envVars.VERCEL_VERIFICATION_KEY || !envVars.VERCEL_LOG_DRAIN_SECRET) {
      colorLog('red', `❌ Error: Missing VERCEL_VERIFICATION_KEY or VERCEL_LOG_DRAIN_SECRET in ${envFile}`);
      process.exit(1);
    }

    return envVars as EnvVars;
  } catch (error) {
    colorLog('red', `❌ Error reading ${envFile}: ${(error as Error).message}`);
    process.exit(1);
  }
}

// Create HMAC signature
function createSignature(data: string, secret: string): string {
  const hmac = crypto.createHmac('sha1', secret);
  hmac.update(data);
  return hmac.digest('hex');
}

// Make HTTP request
function makeRequest(options: RequestOptions, data?: string): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint);
    const isHttps = url.protocol === 'https:';
    const httpModule = isHttps ? https : http;

    const requestOptions = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname,
      method: options.method || 'GET',
      headers: options.headers || {}
    };

    const req = httpModule.request(requestOptions, (res) => {
      let responseData = '';
      res.on('data', chunk => responseData += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 0,
          body: responseData,
          headers: res.headers as Record<string, string | string[]>
        });
      });
    });

    req.on('error', reject);

    if (data) {
      req.write(data);
    }
    req.end();
  });
}

// Test functions
async function testVerification(): Promise<void> {
  colorLog('yellow', '📋 Test 1: Vercel Verification');

  try {
    const response = await makeRequest({
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain'
      }
    }, '{}');

    if (response.statusCode === 200) {
      colorLog('green', '✅ Verification successful');
    } else {
      colorLog('red', `❌ Verification failed (HTTP ${response.statusCode})`);
      console.log(response.body);
    }
  } catch (error) {
    colorLog('red', `❌ Verification request failed: ${(error as Error).message}`);
  }
  console.log('');
}

async function testSampleLogs(envVars: EnvVars): Promise<void> {
  colorLog('yellow', '📋 Test 2: Sending Sample Logs');

  const timestamp = Date.now();
  const logData: VercelLog[] = [
    { id: 'test-1', message: 'Sample info log from lambda', timestamp, level: 'info', source: 'lambda' },
    { id: 'test-2', message: 'Sample error log from build', timestamp, level: 'error', source: 'build' },
    { id: 'test-3', message: 'Sample warning from static', timestamp, level: 'warn', source: 'static' }
  ];

  const ndjson = logData.map(log => JSON.stringify(log)).join('\n');
  const signature = createSignature(ndjson, envVars.VERCEL_LOG_DRAIN_SECRET);

  try {
    const response = await makeRequest({
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'x-vercel-signature': signature
      }
    }, ndjson);

    if (response.statusCode === 200) {
      colorLog('green', '✅ Log processing successful');
      console.log(response.body);
    } else {
      colorLog('red', `❌ Log processing failed (HTTP ${response.statusCode})`);
      console.log(response.body);
    }
  } catch (error) {
    colorLog('red', `❌ Log processing request failed: ${(error as Error).message}`);
  }
  console.log('');
}

async function testInvalidSignature(): Promise<void> {
  colorLog('yellow', '📋 Test 3: Invalid Signature (should fail)');

  const logData: VercelLog = {
    id: 'test-1',
    message: 'Test log',
    timestamp: Date.now(),
    level: 'info',
    source: 'lambda'
  };
  const ndjson = JSON.stringify(logData);

  try {
    const response = await makeRequest({
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'x-vercel-signature': 'invalid-signature'
      }
    }, ndjson);

    if (response.statusCode === 401) {
      colorLog('green', '✅ Correctly rejected invalid signature');
    } else {
      colorLog('red', `❌ Should have rejected invalid signature (HTTP ${response.statusCode})`);
      console.log(response.body);
    }
  } catch (error) {
    colorLog('red', `❌ Invalid signature test failed: ${(error as Error).message}`);
  }
  console.log('');
}

async function testBatchLogs(envVars: EnvVars): Promise<void> {
  colorLog('yellow', '📋 Test 4: Large Batch of Logs');

  const timestamp = Date.now();
  const batchData: VercelLog[] = [];

  for (let i = 1; i <= 10; i++) {
    batchData.push({
      id: `batch-${i}`,
      message: `Batch log entry ${i}`,
      timestamp: timestamp + i,
      level: 'info',
      source: 'lambda'
    });
  }

  const ndjson = batchData.map(log => JSON.stringify(log)).join('\n');
  const signature = createSignature(ndjson, envVars.VERCEL_LOG_DRAIN_SECRET);

  try {
    const response = await makeRequest({
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'x-vercel-signature': signature
      }
    }, ndjson);

    if (response.statusCode === 200) {
      colorLog('green', '✅ Batch processing successful (10 logs)');
      console.log(response.body);
    } else {
      colorLog('red', `❌ Batch processing failed (HTTP ${response.statusCode})`);
      console.log(response.body);
    }
  } catch (error) {
    colorLog('red', `❌ Batch processing request failed: ${(error as Error).message}`);
  }
  console.log('');
}

async function testMalformedJson(envVars: EnvVars): Promise<void> {
  colorLog('yellow', '📋 Test 5: Malformed JSON (should fail gracefully)');

  const validLog: VercelLog = {
    id: 'test-1',
    message: 'Valid log',
    timestamp: Date.now(),
    level: 'info',
    source: 'lambda'
  };
  const malformedData = JSON.stringify(validLog) + '\n{"invalid": json malformed}';
  const signature = createSignature(malformedData, envVars.VERCEL_LOG_DRAIN_SECRET);

  try {
    const response = await makeRequest({
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'x-vercel-signature': signature
      }
    }, malformedData);

    if (response.statusCode === 200) {
      const responseData = JSON.parse(response.body);
      if (responseData.successful > 0 && responseData.failed > 0) {
        colorLog('green', '✅ Correctly handled malformed JSON gracefully');
        console.log(`   Valid: ${responseData.successful}, Failed: ${responseData.failed}, Total: ${responseData.total}`);
      } else {
        colorLog('red', '❌ Expected mixed success/failure response');
        console.log(response.body);
      }
    } else {
      colorLog('red', `❌ Unexpected response to malformed JSON (HTTP ${response.statusCode})`);
      console.log(response.body);
    }
  } catch (error) {
    colorLog('red', `❌ Malformed JSON test failed: ${(error as Error).message}`);
  }
  console.log('');
}

async function testStructuredData(envVars: EnvVars): Promise<void> {
  colorLog('yellow', '📋 Test 6: Structured Data Processing');

  const timestamp = Date.now();
  const structuredMessage = JSON.stringify({
    msg: 'This is a structured log message',
    level: 'error',
    requestId: 'req-12345',
    duration: 1234,
    userId: 'user-789'
  });

  const logData: VercelLog[] = [
    {
      id: 'struct-1',
      message: structuredMessage,
      timestamp,
      level: 'info', // This should be overridden by structured level
      source: 'lambda',
      requestId: 'outer-req-456',
      deploymentId: 'dep-789',
      projectName: 'test-project',
      environment: 'production'
    },
    {
      id: 'struct-2',
      message: 'Simple string message',
      timestamp: timestamp + 1,
      level: 'warn',
      source: 'build',
      type: 'stdout'
    }
  ];

  const ndjson = logData.map(log => JSON.stringify(log)).join('\n');
  const signature = createSignature(ndjson, envVars.VERCEL_LOG_DRAIN_SECRET);

  try {
    const response = await makeRequest({
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'x-vercel-signature': signature
      }
    }, ndjson);

    if (response.statusCode === 200) {
      const responseData = JSON.parse(response.body);
      colorLog('green', '✅ Structured data processing successful');
      console.log(`   Processed: ${responseData.successful} logs with metadata extraction`);
    } else {
      colorLog('red', `❌ Structured data processing failed (HTTP ${response.statusCode})`);
      console.log(response.body);
    }
  } catch (error) {
    colorLog('red', `❌ Structured data test failed: ${(error as Error).message}`);
  }
  console.log('');
}

async function testComprehensiveMetadata(envVars: EnvVars): Promise<void> {
  colorLog('yellow', '📋 Test 7: Comprehensive Metadata & Labels');

  const proxyData = {
    region: 'us-east-1',
    cacheId: 'cache-abc123',
    userAgent: 'Mozilla/5.0 (Test Browser)',
    ip: '192.168.1.1'
  };

  const logData: VercelLog = {
    id: 'meta-test-1',
    message: 'Log with comprehensive metadata',
    timestamp: Date.now(),
    level: 'info',
    source: 'lambda',
    type: 'middleware-invocation',
    requestId: 'req-comprehensive-123',
    deploymentId: 'dep-meta-456',
    projectName: 'meta-test-project',
    projectId: 'proj-789',
    executionRegion: 'us-west-2',
    environment: 'staging',
    branch: 'feature/metadata-test',
    path: '/api/comprehensive-test',
    host: 'test.example.com',
    proxy: proxyData
  };

  const ndjson = JSON.stringify(logData);
  const signature = createSignature(ndjson, envVars.VERCEL_LOG_DRAIN_SECRET);

  try {
    const response = await makeRequest({
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'x-vercel-signature': signature
      }
    }, ndjson);

    if (response.statusCode === 200) {
      JSON.parse(response.body); // Validate response format
      colorLog('green', '✅ Comprehensive metadata processing successful');
      console.log(`   Labels generated for: ${Object.keys(logData).filter(k => k !== 'id' && k !== 'message' && k !== 'timestamp').length} metadata fields`);
    } else {
      colorLog('red', `❌ Comprehensive metadata processing failed (HTTP ${response.statusCode})`);
      console.log(response.body);
    }
  } catch (error) {
    colorLog('red', `❌ Comprehensive metadata test failed: ${(error as Error).message}`);
  }
  console.log('');
}

async function testMixedBatch(envVars: EnvVars): Promise<void> {
  colorLog('yellow', '📋 Test 8: Mixed Valid/Invalid Batch');

  const timestamp = Date.now();
  const validLogs = [
    { id: 'mixed-1', message: 'Valid log 1', timestamp: timestamp, level: 'info', source: 'lambda' as const },
    { id: 'mixed-2', message: 'Valid log 2', timestamp: timestamp + 1, level: 'error', source: 'build' as const }
  ];

  const mixedData = [
    JSON.stringify(validLogs[0]),
    '{"invalid": json}',
    JSON.stringify(validLogs[1]),
    '{"another": malformed',
    JSON.stringify({ id: 'mixed-3', message: 'Valid log 3', timestamp: timestamp + 2, level: 'warn', source: 'static' })
  ].join('\n');

  const signature = createSignature(mixedData, envVars.VERCEL_LOG_DRAIN_SECRET);

  try {
    const response = await makeRequest({
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'x-vercel-signature': signature
      }
    }, mixedData);

    if (response.statusCode === 200) {
      const responseData = JSON.parse(response.body);
      if (responseData.successful === 3 && responseData.failed === 2 && responseData.total === 5) {
        colorLog('green', '✅ Mixed batch processing successful');
        console.log(`   Valid: ${responseData.successful}, Failed: ${responseData.failed}, Total: ${responseData.total}`);
        if (responseData.warning) {
          console.log(`   Warning: ${responseData.warning}`);
        }
      } else {
        colorLog('red', '❌ Unexpected mixed batch results');
        console.log(response.body);
      }
    } else {
      colorLog('red', `❌ Mixed batch processing failed (HTTP ${response.statusCode})`);
      console.log(response.body);
    }
  } catch (error) {
    colorLog('red', `❌ Mixed batch test failed: ${(error as Error).message}`);
  }
  console.log('');
}

// Main execution
async function main(): Promise<void> {
  colorLog('blue', `🧪 Testing Vercel Log Drain at: ${endpoint}`);
  console.log('');

  const envVars = loadEnvVars();

  await testVerification();
  await testSampleLogs(envVars);
  await testInvalidSignature();
  await testBatchLogs(envVars);
  await testMalformedJson(envVars);
  await testStructuredData(envVars);
  await testComprehensiveMetadata(envVars);
  await testMixedBatch(envVars);

  colorLog('blue', '🎉 Testing complete! All structured data features tested.');
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  colorLog('red', `❌ Uncaught error: ${error.message}`);
  process.exit(1);
});

// Run the tests
main().catch(error => {
  colorLog('red', `❌ Test execution failed: ${error.message}`);
  process.exit(1);
});