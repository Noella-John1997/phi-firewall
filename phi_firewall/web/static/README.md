# `web/static/`

| File | Purpose |
| --- | --- |
| `index.html` | Layout: input, the three-step view (detected → LLM receives → app gets back), entities, policy, audit |
| `base.css` | Shared design tokens (light + dark) and components |
| `app.css` | Highlight colours per action (tokenize / mask / block / allow) |
| `app.js` | Calls the API, highlights spans, marks restored values, renders the audit table |

No build step and no external CDN.
