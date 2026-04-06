/**
 * SC Newspaper — Subscription Worker
 * Deploy to: Cloudflare Workers (free tier: 100k req/day)
 *
 * What it does:
 *   POST /subscribe  { email } → adds to Resend Audience → sends welcome email
 *   GET  /subscribe  → health check
 *
 * Setup:
 *   1. wrangler secret put RESEND_API_KEY
 *   2. wrangler secret put RESEND_AUDIENCE_ID   (from resend.com/audiences)
 *   3. wrangler secret put FROM_EMAIL           (info@securitycircuit.in)
 *   4. wrangler deploy
 */

const ALLOWED_ORIGINS = [
  'https://securitycircuit.in',
  'https://news.securitycircuit.in',
  'https://newspaper.securitycircuit.in',
  'http://localhost:3000',
];

const RESEND_API_BASE = 'https://api.resend.com';
const RESEND_USER_AGENT = 'sc-newspaper-worker/1.0';

const jsonResponse = (body, init = {}) =>
  new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });

const readErrorMessage = async (response, fallback) => {
  const text = await response.text();
  if (!text) return fallback;

  try {
    const payload = JSON.parse(text);
    return payload.message || payload.error || text;
  } catch {
    return text;
  }
};

const readJson = async (response, fallback = {}) => {
  try {
    return await response.json();
  } catch {
    return fallback;
  }
};

const isAllowedOrigin = (origin) => {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.includes(origin)) return true;

  try {
    const url = new URL(origin);
    return url.protocol === 'https:' && url.hostname.endsWith('.netlify.app');
  } catch {
    return false;
  }
};

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const htmlResponse = (html, init = {}) =>
  new Response(html, {
    ...init,
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      ...(init.headers || {}),
    },
  });

const STATUS_PAGE = (title, body) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — SC Newspaper</title>
</head>
<body style="margin:0;background:#000;color:#fff;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:640px;margin:0 auto;padding:80px 24px;text-align:center;">
    <p style="font-size:12px;letter-spacing:0.18em;text-transform:uppercase;color:#777;margin:0 0 18px;">
      Security Circuit
    </p>
    <h1 style="font-size:40px;line-height:1.05;margin:0 0 18px;">${title}</h1>
    <p style="font-size:16px;line-height:1.8;color:rgba(255,255,255,0.7);margin:0 auto 28px;max-width:540px;">
      ${body}
    </p>
    <a href="https://news.securitycircuit.in"
       style="display:inline-block;border:1px solid #fff;padding:12px 24px;
              font-size:12px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;
              color:#fff;text-decoration:none;">
      Back to Newspaper
    </a>
  </div>
</body>
</html>`;

const WELCOME_HTML = (email, unsubscribeUrl) => `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#000;font-family:'Segoe UI',Arial,sans-serif;">
<div style="max-width:600px;margin:0 auto;padding:40px 20px;">

  <div style="border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:24px;margin-bottom:32px;">
    <p style="font-size:10px;letter-spacing:0.2em;text-transform:uppercase;
              color:#666;margin-bottom:8px;">Security Circuit</p>
    <h1 style="font-size:36px;font-weight:700;color:#fff;margin:0;line-height:1;">
      SC Newspaper
    </h1>
  </div>

  <h2 style="font-size:22px;font-weight:600;color:#fff;margin-bottom:16px;">
    You're subscribed. ✓
  </h2>

  <p style="font-size:15px;color:rgba(255,255,255,0.6);line-height:1.7;margin-bottom:28px;">
    Welcome to India's daily cybersecurity newspaper. Your first edition
    arrives <strong style="color:#fff;">tomorrow at 10 AM IST</strong>.
  </p>

  <div style="border:1px solid rgba(255,255,255,0.1);padding:24px;margin-bottom:32px;">
    <p style="font-size:10px;letter-spacing:0.15em;text-transform:uppercase;
              color:#666;margin-bottom:16px;">Every morning you'll get</p>
    <div style="display:flex;flex-direction:column;gap:10px;">
      <div style="font-size:14px;color:rgba(255,255,255,0.8);">🚨 &nbsp;CERT-In advisories with severity ratings</div>
      <div style="font-size:14px;color:rgba(255,255,255,0.8);">🐛 &nbsp;Public bug bounty disclosures</div>
      <div style="font-size:14px;color:rgba(255,255,255,0.8);">🔥 &nbsp;Top 5 cybersecurity threats — summarised</div>
      <div style="font-size:14px;color:rgba(255,255,255,0.8);">🧠 &nbsp;Daily OWASP / MITRE / Kill Chain nugget</div>
      <div style="font-size:14px;color:rgba(255,255,255,0.8);">⚠️ &nbsp;Audit red flag of the day</div>
    </div>
  </div>

  <a href="https://securitycircuit.in"
     style="display:inline-block;border:1px solid #fff;padding:12px 28px;
            font-size:11px;font-weight:700;letter-spacing:0.14em;text-transform:uppercase;
            color:#fff;text-decoration:none;">
    Visit Security Circuit →
  </a>

  <p style="font-size:11px;color:#444;margin-top:40px;line-height:1.6;">
    You subscribed with ${email}.<br>
    If this was not you or you want to leave, <a href="${unsubscribeUrl}" style="color:#aaa;">unsubscribe here</a>.
  </p>
</div>
</body>
</html>`;

const unsubscribeContact = async (email, env) => {
  const resendHeaders = {
    'Authorization': `Bearer ${env.RESEND_API_KEY}`,
    'Content-Type': 'application/json',
    'User-Agent': RESEND_USER_AGENT,
  };

  const contactRes = await fetch(`${RESEND_API_BASE}/contacts/${encodeURIComponent(email)}`, {
    method: 'GET',
    headers: resendHeaders,
  });

  if (contactRes.status === 404) {
    return { ok: true, alreadyUnsubscribed: true };
  }

  if (!contactRes.ok) {
    return {
      ok: false,
      error: await readErrorMessage(contactRes, 'Failed to retrieve subscriber'),
    };
  }

  const contact = await readJson(contactRes);
  if (contact.unsubscribed) {
    return { ok: true, alreadyUnsubscribed: true };
  }

  const updateContactRes = await fetch(`${RESEND_API_BASE}/contacts/${encodeURIComponent(email)}`, {
    method: 'PATCH',
    headers: resendHeaders,
    body: JSON.stringify({
      unsubscribed: true,
    }),
  });

  if (!updateContactRes.ok) {
    return {
      ok: false,
      error: await readErrorMessage(updateContactRes, 'Failed to unsubscribe'),
    };
  }

  const removeSegmentRes = await fetch(
    `${RESEND_API_BASE}/contacts/${encodeURIComponent(email)}/segments/${env.RESEND_AUDIENCE_ID}`,
    {
      method: 'DELETE',
      headers: resendHeaders,
    }
  );

  if (!removeSegmentRes.ok && removeSegmentRes.status !== 404) {
    return {
      ok: false,
      error: await readErrorMessage(removeSegmentRes, 'Failed to remove subscriber from segment'),
    };
  }

  return { ok: true, alreadyUnsubscribed: false };
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const corsOrigin = isAllowedOrigin(origin) ? origin : ALLOWED_ORIGINS[0];

    const corsHeaders = {
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method === 'GET' && url.pathname === '/subscribe') {
      return jsonResponse({ status: 'ok', service: 'SC Newspaper' }, {
        headers: corsHeaders,
      });
    }

    if (request.method === 'GET' && url.pathname === '/unsubscribe') {
      const email = (url.searchParams.get('email') || '').trim().toLowerCase();

      if (!isValidEmail(email)) {
        return htmlResponse(
          STATUS_PAGE('Invalid Unsubscribe Link', 'This unsubscribe link is invalid or incomplete.'),
          { status: 400 }
        );
      }

      try {
        const result = await unsubscribeContact(email, env);
        if (!result.ok) {
          console.error('Unsubscribe error:', result.error);
          return htmlResponse(
            STATUS_PAGE('Unsubscribe Failed', result.error || 'We could not unsubscribe this address right now.'),
            { status: 500 }
          );
        }

        if (result.alreadyUnsubscribed) {
          return htmlResponse(
            STATUS_PAGE('Already Unsubscribed', `${email} is already unsubscribed from SC Newspaper.`),
            { status: 200 }
          );
        }

        return htmlResponse(
          STATUS_PAGE('You Are Unsubscribed', `${email} will no longer receive SC Newspaper emails.`),
          { status: 200 }
        );
      } catch (err) {
        console.error('Worker unsubscribe error:', err);
        return htmlResponse(
          STATUS_PAGE('Unsubscribe Failed', 'We could not process your unsubscribe request right now.'),
          { status: 500 }
        );
      }
    }

    if (request.method === 'POST' && url.pathname === '/subscribe') {
      try {
        const body = await request.json();
        const email = (body.email || '').trim().toLowerCase();

        if (!isValidEmail(email)) {
          return jsonResponse({ error: 'Invalid email address' }, {
            status: 400,
            headers: corsHeaders,
          });
        }

        const resendHeaders = {
          'Authorization': `Bearer ${env.RESEND_API_KEY}`,
          'Content-Type': 'application/json',
          'User-Agent': RESEND_USER_AGENT,
        };

        const createContactRes = await fetch(`${RESEND_API_BASE}/contacts`, {
          method: 'POST',
          headers: resendHeaders,
          body: JSON.stringify({
            email,
            unsubscribed: false,
            segments: [{ id: env.RESEND_AUDIENCE_ID }],
          }),
        });

        if (createContactRes.status === 409) {
          const contactRes = await fetch(
            `${RESEND_API_BASE}/contacts/${encodeURIComponent(email)}`,
            {
              method: 'GET',
              headers: resendHeaders,
            }
          );

          if (!contactRes.ok) {
            const err = await readErrorMessage(contactRes, 'Failed to retrieve existing subscriber');
            console.error('Resend contact lookup error:', err);
            return jsonResponse({ error: err }, {
              status: 500,
              headers: corsHeaders,
            });
          }

          const contact = await readJson(contactRes);

          const segmentsRes = await fetch(
            `${RESEND_API_BASE}/contacts/${encodeURIComponent(email)}/segments`,
            {
              method: 'GET',
              headers: resendHeaders,
            }
          );

          if (!segmentsRes.ok) {
            const err = await readErrorMessage(segmentsRes, 'Failed to retrieve subscriber segments');
            console.error('Resend contact segments error:', err);
            return jsonResponse({ error: err }, {
              status: 500,
              headers: corsHeaders,
            });
          }

          const segmentsPayload = await readJson(segmentsRes, { data: [] });
          const alreadyInSegment = (segmentsPayload.data || []).some(
            (segment) => segment.id === env.RESEND_AUDIENCE_ID
          );

          if (alreadyInSegment && !contact.unsubscribed) {
            return jsonResponse({ success: true, alreadySubscribed: true, email }, {
              status: 200,
              headers: corsHeaders,
            });
          }

          const updateContactRes = await fetch(`${RESEND_API_BASE}/contacts/${encodeURIComponent(email)}`, {
            method: 'PATCH',
            headers: resendHeaders,
            body: JSON.stringify({
              unsubscribed: false,
            }),
          });

          if (!updateContactRes.ok) {
            const err = await readErrorMessage(updateContactRes, 'Failed to update subscriber');
            console.error('Resend contact update error:', err);
            return jsonResponse({ error: err }, {
              status: 500,
              headers: corsHeaders,
            });
          }

          const addSegmentRes = await fetch(
            `${RESEND_API_BASE}/contacts/${encodeURIComponent(email)}/segments/${env.RESEND_AUDIENCE_ID}`,
            {
              method: 'POST',
              headers: resendHeaders,
            }
          );

          if (!addSegmentRes.ok && addSegmentRes.status !== 409) {
            const err = await readErrorMessage(addSegmentRes, 'Failed to subscribe');
            console.error('Resend segment add error:', err);
            return jsonResponse({ error: err }, {
              status: 500,
              headers: corsHeaders,
            });
          }
        } else if (!createContactRes.ok) {
          const err = await readErrorMessage(createContactRes, 'Failed to subscribe');
          console.error('Resend contact create error:', err);
          return jsonResponse({ error: err }, {
            status: 500,
            headers: corsHeaders,
          });
        }

        const unsubscribeUrl = `${url.origin}/unsubscribe?email=${encodeURIComponent(email)}`;
        const welcomeEmailRes = await fetch(`${RESEND_API_BASE}/emails`, {
          method: 'POST',
          headers: resendHeaders,
          body: JSON.stringify({
            from: env.FROM_EMAIL,
            to: [email],
            subject: "🛡️ Welcome to SC Newspaper — You're subscribed",
            html: WELCOME_HTML(email, unsubscribeUrl),
          }),
        });

        if (!welcomeEmailRes.ok) {
          const err = await readErrorMessage(welcomeEmailRes, 'Failed to send welcome email');
          console.error('Resend welcome email error:', err);
          return jsonResponse({ error: err }, {
            status: 500,
            headers: corsHeaders,
          });
        }

        return jsonResponse({ success: true, email }, {
          status: 200,
          headers: corsHeaders,
        });
      } catch (err) {
        console.error('Worker error:', err);
        return jsonResponse({ error: 'Internal server error' }, {
          status: 500,
          headers: corsHeaders,
        });
      }
    }

    return new Response('Not found', { status: 404, headers: corsHeaders });
  },
};
