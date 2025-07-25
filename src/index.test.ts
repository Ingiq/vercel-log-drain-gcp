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

// Mock environment variables
const mockEnv = {
  VERCEL_VERIFICATION_KEY: 'test-verification-key',
  VERCEL_LOG_DRAIN_SECRET: 'test-secret',
  GCP_PROJECT_ID: 'test-project',
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
      setHeader: vi.fn().mockReturnThis(),
    } as unknown as Response;

    // Setup default mock return values
    mockEntry.mockReturnValue({ test: 'entry' });
    mockWrite.mockResolvedValue(undefined);
  });

  describe('Vercel Verification', () => {
    it('should handle verification request correctly', async () => {
      mockReq.headers['x-vercel-verify'] = 'test-verification-key';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.setHeader).toHaveBeenCalledWith('x-vercel-verify', 'test-verification-key');
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith('OK');
    });

    it('should reject verification with wrong key', async () => {
      mockReq.headers['x-vercel-verify'] = 'wrong-key';
      mockReq.headers['x-vercel-signature'] = 'sha1=invalid';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith('Bad Request: Empty body');
    });

    it('should handle missing verification key environment variable', async () => {
      delete process.env.VERCEL_VERIFICATION_KEY;
      mockReq.headers['x-vercel-verify'] = 'test-verification-key';
      mockReq.headers['x-vercel-signature'] = 'sha1=invalid';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    it('should handle array header value', async () => {
      mockReq.headers['x-vercel-verify'] = ['test-verification-key', 'duplicate'];
      mockReq.headers['x-vercel-signature'] = 'sha1=invalid';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
    });
  });

  describe('Signature Validation', () => {
    beforeEach(() => {
      const testData = JSON.stringify({ id: '1', message: 'test', timestamp: Date.now(), level: 'info', source: 'lambda' });
      mockReq.rawBody = Buffer.from(testData);

      // Create valid signature
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      const validSignature = `sha1=${hmac.digest('hex')}`;
      mockReq.headers['x-vercel-signature'] = validSignature;
    });

    it('should accept valid signature', async () => {
      await vercelLogDrain(mockReq, mockRes);

      expect(mockWrite).toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith('Logs written to Google Cloud Logging');
    });

    it('should reject invalid signature', async () => {
      mockReq.headers['x-vercel-signature'] = 'sha1=invalid-hash';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.send).toHaveBeenCalledWith('Unauthorized: Invalid signature');
    });

    it('should reject missing signature', async () => {
      delete mockReq.headers['x-vercel-signature'];

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.send).toHaveBeenCalledWith('Unauthorized: Missing signature or secret');
    });

    it('should reject array signature header', async () => {
      mockReq.headers['x-vercel-signature'] = ['sha1=hash1', 'sha1=hash2'];

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
    });

    it('should reject missing secret', async () => {
      delete process.env.VERCEL_LOG_DRAIN_SECRET;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
    });

    it('should reject invalid signature format', async () => {
      mockReq.headers['x-vercel-signature'] = 'invalid-format-no-equals';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith('Bad Request: Invalid signature format');
    });

    it('should reject unsupported algorithm', async () => {
      mockReq.headers['x-vercel-signature'] = 'md5=somehash';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith('Bad Request: Unsupported signature algorithm');
    });

    it('should reject signature without hash', async () => {
      mockReq.headers['x-vercel-signature'] = 'sha1=';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    it('should reject empty body', async () => {
      mockReq.rawBody = Buffer.from('');

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith('Bad Request: Empty body');
    });
  });

  describe('HTTP Method Validation', () => {
    beforeEach(() => {
      const testData = JSON.stringify({ id: '1', message: 'test', timestamp: Date.now(), level: 'info', source: 'lambda' });
      mockReq.rawBody = Buffer.from(testData);

      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = `sha1=${hmac.digest('hex')}`;
    });

    it('should reject non-POST requests', async () => {
      mockReq.method = 'GET';

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(405);
      expect(mockRes.send).toHaveBeenCalledWith('Method Not Allowed');
    });
  });

  describe('Log Processing', () => {
    beforeEach(() => {
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody as Buffer);
      mockReq.headers['x-vercel-signature'] = `sha1=${hmac.digest('hex')}`;
    });

    it('should process valid NDJSON logs', async () => {
      const log1 = { id: '1', message: 'test1', timestamp: 1234567890, level: 'info' as const, source: 'lambda' as const };
      const log2 = { id: '2', message: 'test2', timestamp: 1234567891, level: 'error' as const, source: 'build' as const };
      const ndjson = `${JSON.stringify(log1)}\n${JSON.stringify(log2)}`;

      mockReq.rawBody = Buffer.from(ndjson);
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = `sha1=${hmac.digest('hex')}`;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockEntry).toHaveBeenCalledTimes(2);
      expect(mockWrite).toHaveBeenCalledWith([{ test: 'entry' }, { test: 'entry' }]);
      expect(mockRes.status).toHaveBeenCalledWith(200);
    });

    it('should handle empty log data', async () => {
      mockReq.rawBody = Buffer.from('');
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = `sha1=${hmac.digest('hex')}`;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    it('should handle whitespace-only logs', async () => {
      mockReq.rawBody = Buffer.from('\n  \n\t\n');
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = `sha1=${hmac.digest('hex')}`;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith('No logs to process.');
    });

    it('should handle malformed JSON', async () => {
      const invalidJson = '{"invalid": json}';
      mockReq.rawBody = Buffer.from(invalidJson);
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = `sha1=${hmac.digest('hex')}`;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.send).toHaveBeenCalledWith('Internal Server Error');
    });

    it('should handle Google Cloud Logging write errors', async () => {
      const validLog = JSON.stringify({ id: '1', message: 'test', timestamp: Date.now(), level: 'info', source: 'lambda' });
      mockReq.rawBody = Buffer.from(validLog);
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody);
      mockReq.headers['x-vercel-signature'] = `sha1=${hmac.digest('hex')}`;

      mockWrite.mockRejectedValue(new Error('GCP Error'));

      await vercelLogDrain(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.send).toHaveBeenCalledWith('Internal Server Error');
    });
  });

  describe('Severity Mapping', () => {
    beforeEach(() => {
      const hmac = crypto.createHmac('sha1', 'test-secret');
      hmac.update(mockReq.rawBody as Buffer);
      mockReq.headers['x-vercel-signature'] = `sha1=${hmac.digest('hex')}`;
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
      mockReq.headers['x-vercel-signature'] = `sha1=${hmac.digest('hex')}`;

      await vercelLogDrain(mockReq, mockRes);

      expect(mockEntry).toHaveBeenCalledTimes(5);

      // Check that entries were created with correct severity mappings
      const calls = mockEntry.mock.calls;
      expect(calls[0][0].severity).toBe('INFO');      // info + lambda
      expect(calls[1][0].severity).toBe('NOTICE');    // info + build
      expect(calls[2][0].severity).toBe('ERROR');     // error
      expect(calls[3][0].severity).toBe('WARNING');   // warn
      expect(calls[4][0].severity).toBe('DEBUG');     // debug
    });
  });
});