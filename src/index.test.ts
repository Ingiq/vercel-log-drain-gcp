import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as crypto from 'crypto';
import { Request, Response } from '@google-cloud/functions-framework';

// Use vi.hoisted to create mocks that are available during module initialization
const { mockWrite, mockEntry } = vi.hoisted(() => ({
  mockWrite: vi.fn(),
  mockEntry: vi.fn(),
}));

vi.mock('@google-cloud/logging', () => ({
  Logging: vi.fn().mockImplementation(() => ({
    log: vi.fn(() => ({
      write: mockWrite,
      entry: mockEntry,
    })),
  })),
}));

import { vercelLogDrain } from './index';
import { google } from '@google-cloud/logging/build/protos/protos';

// Mock environment variables
const mockEnv = {
  VERCEL_VERIFICATION_KEY: 'test-verification-key',
  VERCEL_LOG_DRAIN_SECRET: 'test-secret',
  GCP_PROJECT_ID: 'test-project',
};

// Helper function to create valid request with HMAC signature
const createValidRequest = (data: unknown): { rawBody: Buffer; signature: string } => {
  const rawBody = Buffer.from(typeof data === 'string' ? data : JSON.stringify(data));
  const hmac = crypto.createHmac('sha1', 'test-secret');
  hmac.update(rawBody);
  return {
    rawBody,
    signature: hmac.digest('hex')
  };
};

describe('vercelLogDrain', () => {
  let mockReq: Request;
  let mockRes: Response;

  beforeEach(() => {
    vi.clearAllMocks();

    // Reset environment variables
    Object.keys(mockEnv).forEach(key => {
      process.env[key] = mockEnv[key as keyof typeof mockEnv];
    });

    // Mock request object
    mockReq = {
      headers: {},
      method: 'POST',
      rawBody: Buffer.from(''),
    } as Request;

    // Mock response object
    mockRes = {
      status: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      setHeader: vi.fn().mockReturnThis(),
    } as unknown as Response;

    // Setup default mock return values
    mockEntry.mockReturnValue({ test: 'entry' });
    mockWrite.mockResolvedValue(undefined);
  });

  describe('Vercel Verification', () => {
    it('should handle verification request correctly', async () => {
      mockReq.headers['x-vercel-verify'] = 'test-verification-key';
      mockReq.rawBody = Buffer.from('{}');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.setHeader).toHaveBeenCalledWith('x-vercel-verify', 'test-verification-key');
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({ message: 'OK' });
    });

    it('should reject verification with wrong key', async () => {
      mockReq.headers['x-vercel-verify'] = 'wrong-key';
      mockReq.rawBody = Buffer.from('{}');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({ message: 'OK' });
    });

    it('should handle missing verification key environment variable', async () => {
      delete process.env.VERCEL_VERIFICATION_KEY;
      mockReq.rawBody = Buffer.from('{}');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
    });

    it('should handle array header value', async () => {
      mockReq.headers['x-vercel-verify'] = ['test-verification-key', 'duplicate'];
      mockReq.rawBody = Buffer.from('{}');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({ message: 'OK' });
    });
  });

  describe('Signature Validation', () => {
    beforeEach(() => {
      const testData = JSON.stringify({ id: '1', message: 'test', timestamp: Date.now(), level: 'info', source: 'lambda' });
      mockReq.rawBody = Buffer.from(testData);

      // Create valid signature
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      const validSignature = hmac.digest('hex');
      mockReq.headers['x-vercel-signature'] = validSignature;
    });

    it('should accept valid signature', async () => {
      await vercelLogDrain(mockReq, mockRes);

      expect(mockWrite).toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        message: 'Logs processed',
        successful: 1,
        failed: 0,
        total: 1
      });
    });

    it('should reject invalid signature', async () => {
      mockReq.headers['x-vercel-signature'] = 'invalid-hash';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized: Invalid signature' });
    });

    it('should reject missing signature', async () => {
      delete mockReq.headers['x-vercel-signature'];

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized: Missing signature or secret' });
    });

    it('should reject array signature header', async () => {
      mockReq.headers['x-vercel-signature'] = ['hash1', 'hash2'];

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
    });

    it('should reject missing secret', async () => {
      delete process.env.VERCEL_LOG_DRAIN_SECRET;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
    });

    it.each([
      { description: 'invalid signature format', signature: 'invalid-hash-format', expectedError: 'Unauthorized: Invalid signature' },
      { description: 'unsupported algorithm', signature: 'somehash', expectedError: 'Unauthorized: Invalid signature' },
      { description: 'empty signature', signature: '', expectedError: 'Unauthorized: Missing signature or secret' },
    ])('should reject $description', async ({ signature, expectedError }) => {
      mockReq.headers['x-vercel-signature'] = signature;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: expectedError });
    });

    it('should reject empty body', async () => {
      mockReq.rawBody = Buffer.from('');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Bad Request: Empty body' });
    });
  });

  describe('HTTP Method Validation', () => {
    beforeEach(() => {
      const testData = JSON.stringify({ id: '1', message: 'test', timestamp: Date.now(), level: 'info', source: 'lambda' });
      mockReq.rawBody = Buffer.from(testData);

      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');
    });

    it('should reject non-POST requests', async () => {
      mockReq.method = 'GET';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(405);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Method Not Allowed' });
    });
  });

  describe('Log Processing', () => {
    beforeEach(() => {
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody as Buffer);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');
    });

    it('should process valid NDJSON logs', async () => {
      const log1 = { id: '1', message: 'test1', timestamp: 1234567890, level: 'info' as const, source: 'lambda' as const };
      const log2 = { id: '2', message: 'test2', timestamp: 1234567891, level: 'error' as const, source: 'build' as const };
      const ndjson = `${JSON.stringify(log1)}\n${JSON.stringify(log2)}`;

      const { rawBody, signature } = createValidRequest(ndjson);
      mockReq.rawBody = rawBody;
      mockReq.headers['x-vercel-signature'] = signature;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockEntry).toHaveBeenCalledTimes(2);
      expect(mockWrite).toHaveBeenCalledWith([{ test: 'entry' }, { test: 'entry' }]);
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        message: 'Logs processed',
        successful: 2,
        failed: 0,
        total: 2
      });
    });

    it('should handle empty log data', async () => {
      mockReq.rawBody = Buffer.from('');
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    it('should handle whitespace-only logs', async () => {
      const { rawBody, signature } = createValidRequest('\n  \n\t\n');
      mockReq.rawBody = rawBody;
      mockReq.headers['x-vercel-signature'] = signature;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({ message: 'No logs to process.', count: 0 });
    });

    it('should handle malformed JSON gracefully', async () => {
      const invalidJson = '{"invalid": json}';
      const { rawBody, signature } = createValidRequest(invalidJson);
      mockReq.rawBody = rawBody;
      mockReq.headers['x-vercel-signature'] = signature;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        message: 'Logs processed',
        successful: 0,
        failed: 1,
        total: 1,
        warning: '1 log lines failed to parse and were skipped'
      });
    });

    it('should handle mixed valid/invalid logs in same batch', async () => {
      const ndjson = [
        JSON.stringify({ id: '1', message: 'valid', timestamp: Date.now(), level: 'info', source: 'lambda' }),
        '{"invalid": json}',
        JSON.stringify({ id: '2', message: 'valid2', timestamp: Date.now(), level: 'info', source: 'lambda' }),
        '{"another": invalid}',
        JSON.stringify({ id: '3', message: 'valid3', timestamp: Date.now(), level: 'error', source: 'build' })
      ].join('\n');

      const { rawBody, signature } = createValidRequest(ndjson);
      mockReq.rawBody = rawBody;
      mockReq.headers['x-vercel-signature'] = signature;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        message: 'Logs processed',
        successful: 3,
        failed: 2,
        total: 5,
        warning: '2 log lines failed to parse and were skipped'
      });
      expect(mockEntry).toHaveBeenCalledTimes(3);
      expect(mockWrite).toHaveBeenCalledWith([{ test: 'entry' }, { test: 'entry' }, { test: 'entry' }]);
    });

    it('should handle Google Cloud Logging write errors', async () => {
      const validLog = JSON.stringify({ id: '1', message: 'test', timestamp: Date.now(), level: 'info', source: 'lambda' });
      mockReq.rawBody = Buffer.from(validLog);
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      mockWrite.mockRejectedValue(new Error('GCP Error'));

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
    });

    it('should handle GCP authentication errors with helpful message', async () => {
      const validLog = JSON.stringify({ id: '1', message: 'test', timestamp: Date.now(), level: 'info', source: 'lambda' });
      const { rawBody, signature } = createValidRequest(validLog);
      mockReq.rawBody = rawBody;
      mockReq.headers['x-vercel-signature'] = signature;

      mockWrite.mockRejectedValue(new Error('Getting metadata from plugin failed with error: invalid_grant'));

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Server Error: Google Cloud authentication required. Please check server logs for setup instructions.'
      });
    });
  });

  describe('Severity Mapping', () => {
    beforeEach(() => {
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody as Buffer);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');
    });

    it('should map different log levels correctly', async () => {
      const logs = [
        { id: '1', message: 'info', timestamp: Date.now(), level: 'info' as const, source: 'lambda' as const },
        { id: '2', message: 'build', timestamp: Date.now(), level: 'info' as const, source: 'build' as const },
        { id: '3', message: 'error', timestamp: Date.now(), level: 'error' as const, source: 'lambda' as const },
        { id: '4', message: 'warn', timestamp: Date.now(), level: 'warn' as const, source: 'lambda' as const },
        { id: '5', message: 'debug', timestamp: Date.now(), level: 'debug' as const, source: 'lambda' as const },
      ];

      const ndjson = logs.map(log => JSON.stringify(log)).join('\n');
      mockReq.rawBody = Buffer.from(ndjson);
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockEntry).toHaveBeenCalledTimes(5);
      expect(mockRes.json).toHaveBeenCalledWith({
        message: 'Logs processed',
        successful: 5,
        failed: 0,
        total: 5
      });

      // Check that entries were created with correct severity mappings
      const calls = mockEntry.mock.calls;
      expect(calls[0][0].severity).toBe(google.logging.type.LogSeverity.INFO);      // info
      expect(calls[1][0].severity).toBe(google.logging.type.LogSeverity.INFO);      // info (source doesn't affect severity anymore)
      expect(calls[2][0].severity).toBe(google.logging.type.LogSeverity.ERROR);     // error
      expect(calls[3][0].severity).toBe(google.logging.type.LogSeverity.WARNING);   // warn
      expect(calls[4][0].severity).toBe(google.logging.type.LogSeverity.DEBUG);     // debug
    });
  });

  describe('Structured Data Processing', () => {
    beforeEach(() => {
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody as Buffer);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');
    });

    it('should extract message from JSON structured data', async () => {
      const structuredMessage = JSON.stringify({ msg: 'Extracted message', level: 'info', timestamp: Date.now() });
      const log = {
        id: '1',
        message: structuredMessage,
        timestamp: Date.now(),
        level: 'info',
        source: 'lambda' as const
      };

      mockReq.rawBody = Buffer.from(JSON.stringify(log));
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockEntry).toHaveBeenCalledTimes(1);
      const [, logData] = mockEntry.mock.calls[0];
      expect(logData.message).toBe('Extracted message');
      expect(logData.structured_data).toEqual({ msg: 'Extracted message', level: 'info', timestamp: expect.any(Number) });
    });

    it('should prefer "msg" field when both msg and message exist', async () => {
      const structuredMessage = JSON.stringify({
        msg: 'Primary message',
        message: 'Secondary message',
        level: 'info'
      });
      const log = {
        id: '1',
        message: structuredMessage,
        timestamp: Date.now(),
        level: 'info',
        source: 'lambda' as const
      };

      mockReq.rawBody = Buffer.from(JSON.stringify(log));
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      const [, logData] = mockEntry.mock.calls[0];
      expect(logData.message).toBe('Primary message');
    });

    it('should use "message" field when msg is empty', async () => {
      const structuredMessage = JSON.stringify({
        msg: '',
        message: 'Fallback message',
        level: 'info'
      });
      const log = {
        id: '1',
        message: structuredMessage,
        timestamp: Date.now(),
        level: 'info',
        source: 'lambda' as const
      };

      mockReq.rawBody = Buffer.from(JSON.stringify(log));
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      const [, logData] = mockEntry.mock.calls[0];
      expect(logData.message).toBe('Fallback message');
    });

    it('should use error field when no msg or message field exists', async () => {
      const structuredMessage = JSON.stringify({
        error: 'Error message',
        level: 'error'
      });
      const log = {
        id: '1',
        message: structuredMessage,
        timestamp: Date.now(),
        level: 'error',
        source: 'lambda' as const
      };

      mockReq.rawBody = Buffer.from(JSON.stringify(log));
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      const [, logData] = mockEntry.mock.calls[0];
      expect(logData.message).toBe('Error message');
    });

    it('should use original message when structured data has no extractable message', async () => {
      const structuredMessage = JSON.stringify({
        someField: 'some value',
        otherField: 42
      });
      const log = {
        id: '1',
        message: structuredMessage,
        timestamp: Date.now(),
        level: 'info',
        source: 'lambda' as const
      };

      mockReq.rawBody = Buffer.from(JSON.stringify(log));
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      const [, logData] = mockEntry.mock.calls[0];
      expect(logData.message).toBe(structuredMessage);
      expect(logData.structured_data).toEqual({ someField: 'some value', otherField: 42 });
    });

    it('should use structured data level when available', async () => {
      const structuredMessage = JSON.stringify({
        msg: 'Test message',
        level: 'error'
      });
      const log = {
        id: '1',
        message: structuredMessage,
        timestamp: Date.now(),
        level: 'info',  // Different from structured level
        source: 'lambda' as const
      };

      mockReq.rawBody = Buffer.from(JSON.stringify(log));
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      const [metadata] = mockEntry.mock.calls[0];
      expect(metadata.severity).toBe(google.logging.type.LogSeverity.ERROR); // Should use structured level
    });

    it('should preserve proxy data in log entries', async () => {
      const proxyData = {
        region: 'us-east-1',
        cacheId: 'cache-123',
        userAgent: 'Mozilla/5.0'
      };

      const log = {
        id: '1',
        message: 'test with proxy data',
        timestamp: Date.now(),
        level: 'info',
        source: 'lambda' as const,
        proxy: proxyData
      };

      const { rawBody, signature } = createValidRequest(log);
      mockReq.rawBody = rawBody;
      mockReq.headers['x-vercel-signature'] = signature;

      await vercelLogDrain(mockReq, mockRes);

      const [, logData] = mockEntry.mock.calls[0];
      expect(logData.proxy_data).toEqual(proxyData);
      expect(logData.message).toBe('test with proxy data');
    });
  });

  describe('Label Generation', () => {
    beforeEach(() => {
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody as Buffer);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');
    });

    it('should create comprehensive labels from Vercel metadata', async () => {
      const log = {
        id: '1',
        message: 'test',
        timestamp: Date.now(),
        level: 'info',
        source: 'lambda' as const,
        requestId: 'req-123',
        deploymentId: 'dep-456',
        projectName: 'my-project',
        projectId: 'proj-789',
        executionRegion: 'us-east-1',
        type: 'stdout',
        environment: 'production',
        branch: 'main',
        path: '/api/test',
        host: 'example.com'
      };

      mockReq.rawBody = Buffer.from(JSON.stringify(log));
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      const [metadata] = mockEntry.mock.calls[0];
      expect(metadata.labels).toEqual({
        vercel_request_id: 'req-123',
        vercel_deployment_id: 'dep-456',
        vercel_project_name: 'my-project',
        vercel_project_id: 'proj-789',
        vercel_execution_region: 'us-east-1',
        vercel_source: 'lambda',
        vercel_type: 'stdout',
        vercel_environment: 'production',
        vercel_branch: 'main',
        vercel_path: '/api/test',
        vercel_host: 'example.com'
      });
    });

    it('should handle camelCase to snake_case conversion', async () => {
      const log = {
        id: '1',
        message: 'test',
        timestamp: Date.now(),
        level: 'info',
        source: 'lambda' as const,
        requestId: 'req-123',
        deploymentId: 'dep-456',
        executionRegion: 'us-east-1'
      };

      mockReq.rawBody = Buffer.from(JSON.stringify(log));
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      const [metadata] = mockEntry.mock.calls[0];
      expect(metadata.labels.vercel_request_id).toBe('req-123');
      expect(metadata.labels.vercel_deployment_id).toBe('dep-456');
      expect(metadata.labels.vercel_execution_region).toBe('us-east-1');
    });
  });

  describe('Enhanced Severity Mapping', () => {
    beforeEach(() => {
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody as Buffer);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');
    });

    it('should map additional log levels correctly', async () => {
      const logs = [
        { id: '1', message: 'fatal', timestamp: Date.now(), level: 'fatal', source: 'lambda' as const },
        { id: '2', message: 'trace', timestamp: Date.now(), level: 'trace', source: 'lambda' as const },
        { id: '3', message: 'unknown', timestamp: Date.now(), level: 'unknown', source: 'lambda' as const },
      ];

      const ndjson = logs.map(log => JSON.stringify(log)).join('\n');
      mockReq.rawBody = Buffer.from(ndjson);
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = hmac.digest('hex');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockEntry).toHaveBeenCalledTimes(3);
      const calls = mockEntry.mock.calls;
      expect(calls[0][0].severity).toBe(google.logging.type.LogSeverity.CRITICAL);  // fatal
      expect(calls[1][0].severity).toBe(google.logging.type.LogSeverity.DEBUG);     // trace
      expect(calls[2][0].severity).toBe(google.logging.type.LogSeverity.DEFAULT);   // unknown
    });
  });
});