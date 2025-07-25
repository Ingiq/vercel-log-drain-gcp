# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Google Cloud Function that serves as a log drain for Vercel deployments. It receives logs from Vercel via HTTP webhook and forwards them to Google Cloud Logging.

## Development Commands

- **Build**: `npm run build` - Compiles TypeScript to JavaScript in `dist/` directory
- **Test**: `npm test` or `npm run test` - Runs tests with Vitest
- **Lint**: `npm run lint` - Lints TypeScript files in src/ with ESLint
- **Type Check**: `npm run typecheck` - Runs TypeScript compiler without emitting files
- **Start Locally**: `npm start` - Runs the function locally using Functions Framework

## Architecture

### Core Function (`src/index.ts`)
The main export is `vercelLogDrain`, an HTTP Cloud Function that:

1. **Vercel Verification**: Handles Vercel's endpoint verification during log drain setup using `x-vercel-verify` header and `VERCEL_VERIFICATION_KEY` environment variable
2. **Signature Validation**: Validates incoming requests using HMAC-SHA1 signature verification with `VERCEL_LOG_DRAIN_SECRET`
3. **Log Processing**: Parses NDJSON format logs from Vercel and converts them to Google Cloud Logging entries
4. **Severity Mapping**: Maps Vercel log levels (info/warn/error/debug) to Google Cloud Logging severities, with special handling for build logs

### Key Interfaces
- `VercelLog`: Defines the structure of incoming Vercel log entries
- `LogMetadata`: Defines Google Cloud Logging metadata structure

### Dependencies
- `@google-cloud/functions-framework`: HTTP function runtime
- `@google-cloud/logging`: Google Cloud Logging client
- Built-in `crypto` module for signature verification

### Environment Variables Required
- `VERCEL_VERIFICATION_KEY`: For Vercel endpoint verification
- `VERCEL_LOG_DRAIN_SECRET`: For HMAC signature validation
- `GCP_PROJECT_ID`: Google Cloud project ID (optional, auto-detected in Cloud Functions)

### Log Processing Flow
1. Raw request body is parsed as NDJSON (newline-delimited JSON)
2. Each log line becomes a separate Google Cloud Logging entry
3. Logs are written to the 'vercel-logs' log in Google Cloud Logging
4. Severity levels are mapped from Vercel format to Google Cloud format

## Testing
- Uses Vitest as the testing framework
- Test file: `src/index.test.ts` - 20 comprehensive tests covering all functionality
- Coverage reporting configured for text, JSON, and HTML formats

## Local Development

### Functions Framework (Recommended)
The simplest way to run locally using Google Cloud Functions Framework:

1. **Setup Google Cloud authentication:**
   ```bash
   # Install Google Cloud SDK if not already installed
   # https://cloud.google.com/sdk/docs/install
   
   # Authenticate with your Google Cloud account
   gcloud auth login
   
   # Set your default project (must have Cloud Logging API enabled)
   gcloud config set project YOUR_PROJECT_ID
   
   # Create application default credentials for local development
   gcloud auth application-default login
   ```

2. **Setup environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your values (use the same project ID from step 1)
   ```

3. **Start development:**
   ```bash
   npm run dev
   ```

4. **Access:** http://localhost:8080

Functions Framework automatically loads `.env` and uses your GCP credentials to write logs to Cloud Logging!

### Development Commands
- `npm run dev` - Build and start with Functions Framework
- `npm run build` - Build TypeScript only
- `npm start` - Start Functions Framework (requires prior build)

### Testing Locally
Test your running instance with simulated Vercel requests:

```bash
# Start the server first
npm run dev

# In another terminal, run tests
npm run test:local                           # Test localhost:8080
npm run test:local:remote https://your-url  # Test remote endpoint
```

The test script will:
- ✅ Test Vercel verification flow
- ✅ Send realistic log data with proper HMAC signatures  
- ✅ Test error scenarios (invalid signatures, malformed JSON)
- ✅ Verify batch log processing

### Alternative: Docker
For production-like testing:
- `npm run docker:build && npm run docker:run` - Uses Docker with `.env` file

## Production Deployment

### Cloud Run Deployment
Deploy to Google Cloud Run using the provided scripts:

**Prerequisites:**
- Google Cloud SDK installed and authenticated
- Docker installed locally
- `GOOGLE_CLOUD_PROJECT` environment variable set

**Deploy Commands:**
- `npm run deploy` - Full deployment (build + deploy)
- `npm run deploy:build` - Build container image only
- `npm run deploy:run` - Deploy to Cloud Run only

**Environment Variables for Cloud Run:**
Set these in Cloud Run service configuration:
- `VERCEL_VERIFICATION_KEY` - For endpoint verification  
- `VERCEL_LOG_DRAIN_SECRET` - For signature validation
- `GOOGLE_CLOUD_PROJECT` - Auto-set by Cloud Run, but can override if needed