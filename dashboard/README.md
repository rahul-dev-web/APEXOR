# APEXOR Dashboard

React + Vite security console for APEXOR.

## Local development

```bash
cd dashboard
npm install
npm run dev
```

Set `VITE_APEXOR_API_URL` to the FastAPI API origin when the dashboard is served separately, for example `http://localhost:8000`.

The dashboard authenticates through APEXOR's Discord OAuth session cookie and calls guild-scoped APIs with browser credentials. It does not contain a dashboard API key.

## Current views

- Overview
- Security Center
- Incidents
- Events
- Recovery
- Snapshots
- AI Security

Production deployment should use HTTPS for both dashboard and API so the secure session cookie is enabled by the backend.
