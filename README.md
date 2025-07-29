# Vercel Log Drain for Google Cloud Logging

This project implements a Vercel Log Drain that forwards logs from Vercel deployments to Google Cloud Logging. It's designed to be deployed as a Google Cloud Function or on Google Cloud Run.

## Setup

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Ingiq/vercel-log-drain-gcp.git
    cd vercel-log-drain-gcp
    ```

2.  **Install dependencies:**

    ```bash
    npm install
    ```

3.  **Environment Variables:**

    Create a `.env` file based on `.env.example` and populate it with your values:

    ```
    VERCEL_VERIFICATION_KEY=your-verification-key-here
    VERCEL_LOG_DRAIN_SECRET=your-secret-key-here
    GOOGLE_CLOUD_PROJECT=your-gcp-project-id
    # GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json # Optional: for local development with service account
    ```

    *   `VERCEL_VERIFICATION_KEY`: A unique key for Vercel to verify ownership of the log drain.
    *   `VERCEL_LOG_DRAIN_SECRET`: A secret key used to sign log payloads from Vercel.
    *   `GOOGLE_CLOUD_PROJECT`: Your Google Cloud Project ID where logs will be sent.

## Configuration Options

### Feature Flags (Optional)

The log drain includes configurable parsing features that can be controlled via environment variables:

```bash
# Optional: Disable JSON message parsing (default: enabled)
ENABLE_JSON_PARSING=false

# Optional: Disable Lambda execution log parsing (default: enabled)  
ENABLE_LAMBDA_PARSING=false
```

**`ENABLE_JSON_PARSING`** (default: `true`)
- **When enabled**: Parses JSON-formatted log messages to extract structured data and meaningful messages from fields like `msg`, `message`, or `error`
- **When disabled**: Uses the raw JSON string as the log message without parsing
- **Use case**: Disable if you prefer raw JSON messages or experience parsing issues

**`ENABLE_LAMBDA_PARSING`** (default: `true`)
- **When enabled**: Parses AWS Lambda execution logs (START/END/REPORT format) to extract performance metrics like duration, memory usage, and request IDs
- **When disabled**: Treats Lambda execution logs as plain text messages
- **Use case**: Disable if you don't need Lambda metrics or want to reduce processing overhead

Both features are **enabled by default**. To disable a feature, explicitly set the environment variable to `'false'`. Any other value (including unset) keeps the feature enabled.

4.  **Google Cloud Authentication:**

    Ensure your Google Cloud environment is authenticated. For local development, you might need:

    ```bash
    gcloud auth login
    gcloud config set project YOUR_PROJECT_ID
    gcloud auth application-default login
    ```

## Running Locally

To run the function locally:

```bash
npm run dev
```

This will build the TypeScript code and start the function on `http://localhost:8080` (or the port specified by the `PORT` environment variable).

## Deployment to Google Cloud

This project is designed for deployment to Google Cloud Run or Google Cloud Functions.

To deploy to Google Cloud Run (ensure `gcloud` CLI is configured and authenticated):

```bash
npm run deploy
```

This command uses `env-cmd` to pick up environment variables from your `.env` file and deploys the service to Google Cloud Run.

## Testing

Run unit tests using Vitest:

```bash
npm test
```

Run integration tests against the local server:

```bash
npm run dev
npm run test:integration
```

Run integration tests against Cloud Run:

```bash
npm run dev
npm run test:integration https://url-to-the-cloud-run.run.app
```