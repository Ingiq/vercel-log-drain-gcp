import { HttpFunction } from '@google-cloud/functions-framework';
import { Logging } from '@google-cloud/logging';
import * as crypto from 'crypto';

// Vercel log drain payload shape
interface VercelLog {
  id: string;
  message: string;
  timestamp: number;
  level: 'info' | 'error' | 'warn' | 'debug';
  source: 'build' | 'lambda' | 'static' | 'edge';
  [key: string]: unknown;
}

interface LogMetadata {
  resource: {
    type: string;
  };
  severity: string;
  timestamp: Date;
}

// Initialize Google Cloud Logging client
// The projectId is auto-detected from GOOGLE_CLOUD_PROJECT env var in Cloud Run/Functions,
// but it's good practice to provide it or use an environment variable for clarity.
const logging = new Logging({ projectId: process.env.GOOGLE_CLOUD_PROJECT });
const log = logging.log('vercel-logs'); // Define a specific log name in GCP

const mapVercelSeverityToGCP = (log: VercelLog): string => {
  switch (log.level) {
    case 'error':
      return 'ERROR';
    case 'warn':
      return 'WARNING';
    case 'debug':
      return 'DEBUG';
    case 'info':
      if (log.source === 'build') {
        return 'NOTICE';
      }
      return 'INFO';
    default:
      return 'DEFAULT';
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

  try {
    const entries = logLines.map((line: string) => {
      let item: VercelLog;
      try {
        item = JSON.parse(line);
      } catch (parseError) {
        console.error('Failed to parse log line:', line, parseError);
        throw new Error(`Invalid JSON in log line: ${parseError}`);
      }

      const metadata: LogMetadata = {
        resource: { type: 'global' },
        severity: mapVercelSeverityToGCP(item),
        timestamp: new Date(item.timestamp),
      };
      return log.entry(metadata, item);
    });

    await log.write(entries);
    return res.status(200).json({ message: 'Logs written to Google Cloud Logging', count: entries.length });
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
};
