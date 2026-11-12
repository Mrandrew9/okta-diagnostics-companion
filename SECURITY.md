# Security policy

This is a **prototype** and is **not yet approved for production**. Before using it with any real tenant, obtain authorization from your security and identity teams.

- Do not file GitHub issues with API tokens, cookies, user IDs, IP addresses, log exports, or tenant-specific details.
- Do not fork or publish an organization's live tenant data or screenshots.
- This extension uses **only GET requests** on the current Okta origin and does not store API credentials.
- Do not grant it broad permissions or inject it on arbitrary sites.
- Do not use API token pasting as a workaround for 401/403 errors.
- Treat CSV exports as sensitive operational evidence. Validate their permitted recipients and retention periods.
- Test with synthetic users, disposable app assignments, and a nonproduction tenant.
- Report security vulnerabilities privately to the repository owner using GitHub's private vulnerability reporting if enabled. If that is unavailable, ask for a private contact method without posting exploit details.