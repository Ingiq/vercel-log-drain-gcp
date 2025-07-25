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
  console.log({ env: process.env });
  const verificationKey = process.env.VERCEL_VERIFICATION_KEY;
  if (!verificationKey) {
    console.error('VERCEL_VERIFICATION_KEY is not set. Aborting.');
    return res.status(500).send('Server Error: VERCEL_VERIFICATION_KEY is not set.');
  }
  const secret = process.env.VERCEL_LOG_DRAIN_SECRET;
  if (!secret) {
    console.error('VERCEL_LOG_DRAIN_SECRET is not set. Aborting.');
    return res.status(500).send('Server Error: VERCEL_LOG_DRAIN_SECRET is not set.');
  }

  // Vercel Endpoint Verification ---
  // Vercel sends this header during the initial setup to verify ownership.
  // Your function must respond with the same header and a 200 OK.
  const vercelVerifyHeader = req.headers['x-vercel-verify'];
  if (vercelVerifyHeader && typeof vercelVerifyHeader === 'string' && verificationKey && vercelVerifyHeader === verificationKey) {
    console.log('Vercel verification request received.');
    res.setHeader('x-vercel-verify', verificationKey);
    return res.status(200).send('OK');
  }

  // Verify Vercel Signature
  // This ensures the logs are genuinely coming from Vercel and haven't been tampered with.
  const vercelSignature = req.headers['x-vercel-signature'];

  if (!vercelSignature || typeof vercelSignature !== 'string' || !secret) {
    console.error('Missing Vercel signature or secret. Aborting.');
    return res.status(401).send('Unauthorized: Missing signature or secret');
  }

  // Vercel's signature format is `sha1=HEX_HASH`
  if (!vercelSignature.includes('=')) {
    console.error('Invalid signature format.');
    return res.status(400).send('Bad Request: Invalid signature format');
  }

  const [algorithm, hash] = vercelSignature.split('=', 2);

  if (algorithm !== 'sha1' || !hash) {
    console.error('Unsupported signature algorithm or missing hash:', algorithm);
    return res.status(400).send('Bad Request: Unsupported signature algorithm');
  }

  // `req.rawBody` contains the raw request body as a Buffer
  if (!req.rawBody || req.rawBody.length === 0) {
    console.error('Request body is empty, cannot verify signature.');
    return res.status(400).send('Bad Request: Empty body');
  }

  const hmac = crypto.createHmac(algorithm, secret);
  hmac.update(req.rawBody); // Use the raw buffer
  const expectedHash = hmac.digest('hex');

  if (hash !== expectedHash) {
    console.error('Invalid Vercel signature. Aborting.');
    return res.status(401).send('Unauthorized: Invalid signature');
  }

  // --- 3. Process Log Entries ---
  if (req.method !== 'POST') {
    res.status(405).send('Method Not Allowed');
    return;
  }

  // Vercel sends NDJSON, which means each line is a separate JSON object.
  // `req.rawBody` is a Buffer, convert it to string and split by newline.
  const logLines = req.rawBody.toString('utf8').split('\n').filter((line: string) => line.trim() !== '');

  if (!logLines || logLines.length === 0) {
    res.status(200).send('No logs to process.');
    return;
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
    return res.status(200).send('Logs written to Google Cloud Logging');
  } catch (error) {
    const errorMessage = (error as Error).message;

    // Check if it's a Google Cloud authentication error
    if (errorMessage.includes('invalid_grant') || errorMessage.includes('Getting metadata from plugin failed')) {
      console.error('❌ Google Cloud authentication failed. Please run:');
      console.error('   gcloud auth login');
      console.error('   gcloud config set project YOUR_PROJECT_ID');
      console.error('   gcloud auth application-default login');
      console.error('Error details:', error);
      return res.status(500).send('Server Error: Google Cloud authentication required. Please check server logs for setup instructions.');
    }

    console.error('Error processing logs:', error);
    return res.status(500).send('Internal Server Error');
  }
};
