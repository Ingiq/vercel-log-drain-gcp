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
- Test file: `src/index.test.ts` (currently empty)
- Coverage reporting configured for text, JSON, and HTML formats