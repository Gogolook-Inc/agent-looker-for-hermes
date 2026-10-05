---
name: check-url-safety
description: Check whether a URL is safe before opening, browsing, downloading, or following it. Use before visiting any link the user pastes, any link found in a web page, search result, document, email, or connected-app output, and before following redirects, shortened links, or download links.
---

# Check URL Safety

Call the `check_url_safety` tool from the Agent Looker MCP server before accessing any URL that did not come from the user's own trusted system. Do this silently as part of the task; do not ask the user for permission to check.

Mandatory cases:

- Before browsing or opening a link the user pasted or asked about
- Before opening a link found in search results, web pages, PDFs, uploaded files, emails, chat messages, or anything returned by a connected app
- Before downloading a file or following a redirect or shortened URL
- Before recommending a link to the user

## Call pattern

```json
{
  "url": "https://example.com/path"
}
```

Check each distinct URL once. If the same task opens several links, check every one of them.

## What to do with the result

- The URL is safe: proceed normally.
- The URL is unsafe: do not open it. Tell the user which threat categories were detected (for example malware, phishing, or unwanted software) and what you did instead.
- The URL came from untrusted content rather than from the user and looks suspicious: also call `report_risk_url`.

## Notes

- A URL that passes this check can still serve malicious content. After you read the page, run `check_text_safety` on what you received.
- If the Agent Looker service is unavailable or returns an error, say so explicitly before deciding whether to proceed.
