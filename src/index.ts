import { HttpFunction } from '@google-cloud/functions-framework';
import { Entry, Logging } from '@google-cloud/logging';
import { google } from '@google-cloud/logging/build/protos/protos';
import { LogEntry, LogSeverity } from '@google-cloud/logging/build/src/entry';
import * as crypto from 'crypto';

// Extended Vercel log drain payload shape with all observed fields
interface VercelLog {
  id: string;
  message: string;
  timestamp: number;
  level: string;
  source: 'build' | 'lambda' | 'static' | 'edge';
  type?: string; // stdout, middleware-invocation, lambda, etc.
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

// Interface for parsed message content
interface ParsedMessage {
  extractedMessage: string;
  structuredData?: Record<string, unknown>;
}

// Initialize Google Cloud Logging client
// The projectId is auto-detected from GOOGLE_CLOUD_PROJECT env var in Cloud Run/Functions,
// but it's good practice to provide it or use an environment variable for clarity.
const logging = new Logging({ projectId: process.env.GOOGLE_CLOUD_PROJECT });
const log = logging.log('vercel-logs'); // Define a specific log name in GCP

/**
 * Extracts the most meaningful message from a Vercel log entry. If the message is a JSON object, it
 * will be parsed and the most meaningful message will be extracted from the message field.
 * @param vercelLog - The Vercel log entry to extract the message from.
 * @returns An object containing the extracted message and structured data.
 */
const extractMessage = (vercelLog: VercelLog): ParsedMessage => {
  let extractedMessage = vercelLog.message;
  let structuredData: Record<string, unknown> | undefined;

  // Try to parse the message field as JSON (common in stdout logs)
  try {
    const parsed = JSON.parse(vercelLog.message);
    if (typeof parsed === 'object' && parsed !== null) {
      structuredData = parsed;

      // Extract the most meaningful message from common fields
      if (typeof parsed.msg === 'string' && parsed.msg.trim()) {
        extractedMessage = parsed.msg;
      } else if (typeof parsed.message === 'string' && parsed.message.trim()) {
        extractedMessage = parsed.message;
      } else if (typeof parsed.error === 'string' && parsed.error.trim()) {
        extractedMessage = parsed.error;
      } else {
        // If no clear message field, use the original message
        extractedMessage = vercelLog.message;
      }
    }
  } catch {
    // If parsing fails, use the original message
    extractedMessage = vercelLog.message;
  }

  return { extractedMessage, structuredData };
};

/**
 * Creates comprehensive labels from Vercel metadata.
 * @param vercelLog - The Vercel log entry to create labels from.
 * @returns A record of labels.
 */
const createLabels = (vercelLog: VercelLog): Record<string, string> => {
  const labelFields = [
    'requestId', 'deploymentId', 'projectName', 'projectId',
    'executionRegion', 'source', 'type', 'environment',
    'branch', 'path', 'host'
  ];

  const labels: Record<string, string> = {};

  for (const field of labelFields) {
    const value = vercelLog[field];
    if (value && typeof value === 'string') {
      const labelKey = `vercel_${field.replace(/([A-Z])/g, '_$1').toLowerCase()}`;
      labels[labelKey] = value;
    }
  }

  return labels;
};

const mapVercelLogLevelToGCP = (level: string): LogSeverity => {
  switch (level.toLowerCase()) {
    case 'fatal':
      return google.logging.type.LogSeverity.CRITICAL;
    case 'error':
      return google.logging.type.LogSeverity.ERROR;
    case 'warn':
      return google.logging.type.LogSeverity.WARNING;
    case 'info':
      return google.logging.type.LogSeverity.INFO;
    case 'debug':
      return google.logging.type.LogSeverity.DEBUG;
    case 'trace':
      return google.logging.type.LogSeverity.DEBUG;
    default:
      return google.logging.type.LogSeverity.DEFAULT;
  }
};

export const vercelLogDrain: HttpFunction = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  if (!req.rawBody || req.rawBody.length === 0) {
    return res.status(400).json({ error: 'Bad Request: Empty body' });
  }

  // Vercel sends NDJSON, which means each line is a separate JSON object.
  // `req.rawBody` is a Buffer, convert it to string and split by newline.
  const logLines = req.rawBody.toString('utf8').split('\n').filter((line: string) => line.trim() !== '');
  if (!logLines || logLines.length === 0) {
    return res.status(200).json({ message: 'No logs to process.', count: 0 });
  }

  // Vercel sends an empty log line request during initial setup to verify ownership.
  // We must respond with the verification key in the x-vercel-verify header.
  if (logLines.length === 1 && logLines[0] === '{}') {
    const verificationKey = process.env.VERCEL_VERIFICATION_KEY;
    if (!verificationKey) {
      console.error('VERCEL_VERIFICATION_KEY is not set. Aborting.');
      return res.status(500).json({ error: 'Server Error: VERCEL_VERIFICATION_KEY is not set.' });
    }

    console.log('Vercel verification request received.');
    res.setHeader('x-vercel-verify', verificationKey);
    return res.status(200).json({ message: 'OK' });
  }

  const secret = process.env.VERCEL_LOG_DRAIN_SECRET;
  if (!secret) {
    console.error('VERCEL_LOG_DRAIN_SECRET is not set. Aborting.');
    return res.status(500).json({ error: 'Server Error: VERCEL_LOG_DRAIN_SECRET is not set.' });
  }

  // Verify Vercel Signature
  // This ensures the logs are genuinely coming from Vercel and haven't been tampered with.
  const vercelSignature = req.headers['x-vercel-signature'];
  if (!vercelSignature || typeof vercelSignature !== 'string' || !secret) {
    console.error('Missing Vercel signature or secret. Aborting.');
    return res.status(401).json({ error: 'Unauthorized: Missing signature or secret' });
  }

  const hmac = crypto.createHmac('sha1', secret);
  hmac.update(req.rawBody);
  const expectedHash = hmac.digest('hex');
  if (vercelSignature !== expectedHash) {
    console.error('Invalid Vercel signature. Aborting.');
    return res.status(401).json({ error: 'Unauthorized: Invalid signature' });
  }

  const entries: Entry[] = [];
  let successCount = 0;
  let failureCount = 0;

  // Process each log line individually to handle failures gracefully
  for (const line of logLines) {
    try {
      const item: VercelLog = JSON.parse(line);

      // Extract meaningful message and structured data
      const { extractedMessage, structuredData } = extractMessage(item);

      // Create comprehensive labels for filtering
      const labels = createLabels(item);

      const level = typeof structuredData?.level === 'string' && structuredData.level.trim() !== '' ? structuredData.level : item.level;
      const metadata: LogEntry = {
        resource: { type: 'global' },
        severity: mapVercelLogLevelToGCP(level),
        timestamp: new Date(item.timestamp),
        labels,
      };

      // Create the log entry with clean message and preserve structured data
      const logData = {
        message: extractedMessage,
        vercel_log_id: item.id,
        vercel_level: item.level,
        vercel_source: item.source,
        ...(structuredData && { structured_data: structuredData }),
        ...(item.proxy && { proxy_data: item.proxy }),
      };

      entries.push(log.entry(metadata, logData));
      successCount++;
    } catch (parseError) {
      failureCount++;
      console.error(`Failed to parse log line (skipping): ${line.substring(0, 100)}...`, parseError);
      // Continue processing other log lines instead of failing the entire batch
    }
  }

  if (entries.length > 0) {
    try {
      await log.write(entries);
    } catch (error) {
      const errorMessage = (error as Error).message;

      // Check if it's a Google Cloud authentication error
      if (errorMessage.includes('invalid_grant') || errorMessage.includes('Getting metadata from plugin failed')) {
        console.error('❌ Google Cloud authentication failed. Please run:');
        console.error('   gcloud auth login');
        console.error('   gcloud config set project YOUR_PROJECT_ID');
        console.error('   gcloud auth application-default login');
        console.error('Error details:', error);
        return res.status(500).json({ error: 'Server Error: Google Cloud authentication required. Please check server logs for setup instructions.' });
      }

      console.error('Error processing logs:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  }

  const response: {
    message: string;
    successful: number;
    failed: number;
    total: number;
    warning?: string;
  } = {
    message: 'Logs processed',
    successful: successCount,
    failed: failureCount,
    total: logLines.length
  };

  if (failureCount > 0) {
    response.warning = `${failureCount} log lines failed to parse and were skipped`;
  }

  return res.status(200).json(response);
};
