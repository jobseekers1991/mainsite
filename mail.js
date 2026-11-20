// ================================
// Mail: Resend wrapper + console fallback
// ================================
// Reads RESEND_API_KEY from env. If the key is missing the module logs the
// link to stdout so local development keeps working without an email account.
// Reads MAIL_FROM too; defaults to "Jobseekers.ph <hello@jobseekers.ph>".
// Reads BASE_URL for the public origin to prefix in the email link.

const API_KEY  = process.env.RESEND_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || 'Jobseekers.ph <hello@jobseekers.ph>';
const BASE_URL  = (process.env.BASE_URL || 'http://localhost:3004').replace(/\/+$/, '');

let resendClient = null;
function getClient() {
  if (!API_KEY) return null;
  if (resendClient) return resendClient;
  try {
    const { Resend } = require('resend');
    resendClient = new Resend(API_KEY);
    return resendClient;
  } catch (e) {
    console.error('[mail] "resend" package is not installed. Run `npm install` first.');
    return null;
  }
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function renderVerifyEmail({ firstName, verifyUrl, role }) {
  const name = firstName ? escapeHtml(firstName) : 'there';
  const roleCopy = role === 'va'
    ? 'Finish verifying so clients can find your profile and send you offers.'
    : 'Finish verifying so you can post jobs and start matching with VAs.';
  const html = `<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background:#F8FAFC;font-family:Inter,Arial,sans-serif;color:#1E293B;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F8FAFC;padding:32px 16px;">
      <tr><td align="center">
        <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:16px;border:1px solid #E2E8F0;overflow:hidden;">
          <tr><td style="padding:28px 32px;border-bottom:1px solid #E2E8F0;">
            <div style="font-family:Poppins,Arial,sans-serif;font-weight:800;font-size:20px;color:#0F172A;">
              Jobseekers<span style="color:#4F46E5;">.ph</span>
            </div>
          </td></tr>
          <tr><td style="padding:32px;">
            <h1 style="font-family:Poppins,Arial,sans-serif;font-size:22px;color:#0F172A;margin:0 0 12px;">Welcome, ${name} 👋</h1>
            <p style="font-size:15px;line-height:1.6;color:#334155;margin:0 0 20px;">${roleCopy}</p>
            <p style="margin:0 0 24px;">
              <a href="${verifyUrl}" style="display:inline-block;background:#4F46E5;color:#fff;text-decoration:none;padding:14px 24px;border-radius:9999px;font-weight:600;font-size:15px;">Verify my email</a>
            </p>
            <p style="font-size:13px;line-height:1.6;color:#64748B;margin:0 0 8px;">Or paste this link into your browser:</p>
            <p style="font-size:12px;line-height:1.5;color:#64748B;word-break:break-all;margin:0 0 24px;">
              <a href="${verifyUrl}" style="color:#4F46E5;">${verifyUrl}</a>
            </p>
            <p style="font-size:12px;line-height:1.6;color:#94A3B8;margin:0;">This link expires in 48 hours. If you didn't create a Jobseekers.ph account, you can ignore this email.</p>
          </td></tr>
          <tr><td style="padding:20px 32px;background:#F8FAFC;border-top:1px solid #E2E8F0;font-size:12px;color:#94A3B8;text-align:center;">
            © Jobseekers.ph · Philippines' VA marketplace
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>`;
  const text = `Welcome, ${firstName || 'there'}!

${roleCopy}

Verify your email: ${verifyUrl}

This link expires in 48 hours. If you didn't create a Jobseekers.ph account, you can ignore this message.`;
  return { html, text };
}

async function sendVerificationEmail({ to, firstName, role, verifyPath }) {
  const verifyUrl = BASE_URL + verifyPath;
  const client = getClient();

  if (!client) {
    console.log(`\n  [mail/console] To: ${to}\n  [mail/console] Verify link: ${verifyUrl}\n  [mail/console] (set RESEND_API_KEY to send real emails)\n`);
    return { ok: true, dev: true };
  }

  const { html, text } = renderVerifyEmail({ firstName, verifyUrl, role });
  try {
    const result = await client.emails.send({
      from: MAIL_FROM,
      to,
      subject: 'Verify your Jobseekers.ph account',
      html,
      text,
    });
    if (result.error) {
      console.error('[mail] send failed:', result.error);
      return { ok: false, error: result.error };
    }
    console.log(`[mail] sent verification to ${to} (id=${result.data && result.data.id})`);
    return { ok: true, id: result.data && result.data.id };
  } catch (err) {
    console.error('[mail] send threw:', err && err.message ? err.message : err);
    return { ok: false, error: err };
  }
}

function renderResetEmail({ firstName, resetUrl }) {
  const name = firstName ? escapeHtml(firstName) : 'there';
  const html = `<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background:#F8FAFC;font-family:Inter,Arial,sans-serif;color:#1E293B;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F8FAFC;padding:32px 16px;">
      <tr><td align="center">
        <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:16px;border:1px solid #E2E8F0;overflow:hidden;">
          <tr><td style="padding:28px 32px;border-bottom:1px solid #E2E8F0;">
            <div style="font-family:Poppins,Arial,sans-serif;font-weight:800;font-size:20px;color:#0F172A;">
              Jobseekers<span style="color:#4F46E5;">.ph</span>
            </div>
          </td></tr>
          <tr><td style="padding:32px;">
            <h1 style="font-family:Poppins,Arial,sans-serif;font-size:22px;color:#0F172A;margin:0 0 12px;">Reset your password</h1>
            <p style="font-size:15px;line-height:1.6;color:#334155;margin:0 0 20px;">Hi ${name}, we got a request to reset your Jobseekers.ph password. Tap the button to pick a new one.</p>
            <p style="margin:0 0 24px;">
              <a href="${resetUrl}" style="display:inline-block;background:#4F46E5;color:#fff;text-decoration:none;padding:14px 24px;border-radius:9999px;font-weight:600;font-size:15px;">Reset my password</a>
            </p>
            <p style="font-size:13px;line-height:1.6;color:#64748B;margin:0 0 8px;">Or paste this link into your browser:</p>
            <p style="font-size:12px;line-height:1.5;color:#64748B;word-break:break-all;margin:0 0 24px;">
              <a href="${resetUrl}" style="color:#4F46E5;">${resetUrl}</a>
            </p>
            <p style="font-size:12px;line-height:1.6;color:#94A3B8;margin:0;">This link expires in 2 hours. If you didn't ask to reset your password, you can safely ignore this email.</p>
          </td></tr>
          <tr><td style="padding:20px 32px;background:#F8FAFC;border-top:1px solid #E2E8F0;font-size:12px;color:#94A3B8;text-align:center;">
            © Jobseekers.ph · Philippines' VA marketplace
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>`;
  const text = `Hi ${firstName || 'there'},

We got a request to reset your Jobseekers.ph password.

Reset it here: ${resetUrl}

This link expires in 2 hours. If you didn't ask to reset your password, you can ignore this message.`;
  return { html, text };
}

async function sendPasswordResetEmail({ to, firstName, resetPath }) {
  const resetUrl = BASE_URL + resetPath;
  const client = getClient();

  if (!client) {
    console.log(`\n  [mail/console] To: ${to}\n  [mail/console] Reset link: ${resetUrl}\n  [mail/console] (set RESEND_API_KEY to send real emails)\n`);
    return { ok: true, dev: true };
  }

  const { html, text } = renderResetEmail({ firstName, resetUrl });
  try {
    const result = await client.emails.send({
      from: MAIL_FROM,
      to,
      subject: 'Reset your Jobseekers.ph password',
      html,
      text,
    });
    if (result.error) {
      console.error('[mail] reset send failed:', result.error);
      return { ok: false, error: result.error };
    }
    console.log(`[mail] sent reset to ${to} (id=${result.data && result.data.id})`);
    return { ok: true, id: result.data && result.data.id };
  } catch (err) {
    console.error('[mail] reset send threw:', err && err.message ? err.message : err);
    return { ok: false, error: err };
  }
}

// ================================
// Generic notification email helper
// ================================
// Used for in-app events we also want to email (new application, new
// message, status change, etc.). Keeps a consistent branded shell.

function renderGenericEmail({ heading, firstName, intro, ctaLabel, ctaUrl, body }) {
  const name = firstName ? escapeHtml(firstName) : 'there';
  const safeHeading = escapeHtml(heading || 'Jobseekers.ph update');
  const safeIntro = escapeHtml(intro || '');
  const safeBody  = body ? escapeHtml(body) : '';
  const safeLabel = escapeHtml(ctaLabel || 'Open Jobseekers.ph');
  const html = `<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background:#F8FAFC;font-family:Inter,Arial,sans-serif;color:#1E293B;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F8FAFC;padding:32px 16px;">
      <tr><td align="center">
        <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:16px;border:1px solid #E2E8F0;overflow:hidden;">
          <tr><td style="padding:28px 32px;border-bottom:1px solid #E2E8F0;">
            <div style="font-family:Poppins,Arial,sans-serif;font-weight:800;font-size:20px;color:#0F172A;">
              Jobseekers<span style="color:#4F46E5;">.ph</span>
            </div>
          </td></tr>
          <tr><td style="padding:32px;">
            <h1 style="font-family:Poppins,Arial,sans-serif;font-size:22px;color:#0F172A;margin:0 0 12px;">${safeHeading}</h1>
            <p style="font-size:15px;line-height:1.6;color:#334155;margin:0 0 8px;">Hi ${name},</p>
            <p style="font-size:15px;line-height:1.6;color:#334155;margin:0 0 20px;">${safeIntro}</p>
            ${safeBody ? `<blockquote style="margin:0 0 20px;padding:12px 16px;background:#F1F5F9;border-left:3px solid #4F46E5;border-radius:4px;font-size:14px;color:#334155;">${safeBody}</blockquote>` : ''}
            ${ctaUrl ? `<p style="margin:0 0 24px;">
              <a href="${ctaUrl}" style="display:inline-block;background:#4F46E5;color:#fff;text-decoration:none;padding:14px 24px;border-radius:9999px;font-weight:600;font-size:15px;">${safeLabel}</a>
            </p>` : ''}
            <p style="font-size:12px;line-height:1.6;color:#94A3B8;margin:0;">You're getting this because you have an active Jobseekers.ph account. You can turn off transactional emails in Settings.</p>
          </td></tr>
          <tr><td style="padding:20px 32px;background:#F8FAFC;border-top:1px solid #E2E8F0;font-size:12px;color:#94A3B8;text-align:center;">
            © Jobseekers.ph · Philippines' VA marketplace
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>`;
  const text = `Hi ${firstName || 'there'},\n\n${intro || ''}\n${body ? '\n> ' + body + '\n' : ''}${ctaUrl ? '\n' + (ctaLabel || 'Open') + ': ' + ctaUrl : ''}\n\n—\nJobseekers.ph`;
  return { html, text, subject: heading || 'Jobseekers.ph update' };
}

async function sendNotificationEmail({ to, firstName, heading, intro, ctaLabel, ctaPath, body, subject }) {
  const client = getClient();
  const ctaUrl = ctaPath ? BASE_URL + ctaPath : null;

  if (!client) {
    console.log(`\n  [mail/console] To: ${to}\n  [mail/console] Subject: ${subject || heading}\n  [mail/console] Intro: ${intro}\n  [mail/console] CTA: ${ctaUrl || '(none)'}\n`);
    return { ok: true, dev: true };
  }

  const r = renderGenericEmail({ heading, firstName, intro, ctaLabel, ctaUrl, body });
  try {
    const result = await client.emails.send({
      from: MAIL_FROM,
      to,
      subject: subject || r.subject,
      html: r.html,
      text: r.text,
    });
    if (result.error) {
      console.error('[mail/notify] send failed:', result.error);
      return { ok: false, error: result.error };
    }
    return { ok: true, id: result.data && result.data.id };
  } catch (err) {
    console.error('[mail/notify] threw:', err && err.message ? err.message : err);
    return { ok: false, error: err };
  }
}

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendNotificationEmail,
};
