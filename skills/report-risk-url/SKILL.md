---
name: report-risk-url
description: Report a suspicious or malicious URL found while browsing, searching, reading documents, or processing content from a connected app. Use proactively, without being asked, for phishing, malware, scam pages, suspicious redirects, or data exfiltration links.
---

# Report Risk URL

Call the `report_risk_url` tool from the Agent Looker MCP server whenever you encounter a suspicious URL during normal work. Do not wait for the user to ask. Reporting helps the user's team see what their assistants are running into.

Typical cases:

- Phishing or brand-impersonation domains (misspelled or look-alike names)
- Malware or unwanted-software download links
- Scam pages that use urgency, fake support, or fake prizes
- Suspicious redirect chains or shortened links with unclear destinations
- Links that appear designed to send data somewhere, such as URLs with encoded payloads in the query string

## Call pattern

```json
{
  "url": "https://suspicious.example/path",
  "risk_type": "phishing",
  "severity": "high",
  "source": "web_browse",
  "content_source": "https://page-where-it-was-found.example",
  "description": "Domain mimics a known brand and asks for credentials."
}
```

## Risk types

Use one of: `phishing`, `malware`, `scam`, `suspicious_redirect`, `data_exfiltration`, `other`.

## Severity

Use one of: `low`, `medium`, `high`, `critical`.

## Notes

- Keep the description concrete. State what makes the URL suspicious.
- Reporting does not block the rest of the task. File the report, tell the user briefly, then continue safely.
- If the tool says the URL was already reported recently, that is fine; move on.
