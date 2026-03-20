import express from "express";
import { ImapFlow } from "imapflow";
import nodemailer from "nodemailer";
import cors from "cors";
import helmet from "helmet";

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: "5mb" }));

const PORT = process.env.PORT || 3001;
const PROXY_SECRET = process.env.PROXY_SECRET || "";
const TLS_SECURE = process.env.TLS_REJECT_UNAUTHORIZED !== "false"; // default: true (secure)

// ── Auth middleware ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  if (PROXY_SECRET) {
    const token = req.headers["x-proxy-secret"];
    if (token !== PROXY_SECRET) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  }
  next();
}
app.use(authMiddleware);

// ── Helpers ──────────────────────────────────────────────────
function decryptPassword(encrypted) {
  try { return atob(encrypted); } catch { return encrypted; }
}

function getImapConfig(conn) {
  return {
    host: conn.imap_host,
    port: conn.imap_port || 993,
    secure: conn.use_ssl !== false,
    auth: {
      user: conn.email,
      pass: decryptPassword(conn.encrypted_password),
    },
    logger: false,
    tls: { rejectUnauthorized: TLS_SECURE },
    greetTimeout: 15000,
    socketTimeout: 30000,
  };
}

function getSmtpConfig(conn) {
  return {
    host: conn.smtp_host,
    port: conn.smtp_port || 587,
    secure: (conn.smtp_port || 587) === 465,
    auth: {
      user: conn.email,
      pass: decryptPassword(conn.encrypted_password),
    },
    tls: { rejectUnauthorized: TLS_SECURE },
  };
}

// ── Email validation ────────────────────────────────────────
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ── Extract detailed error info from ImapFlow ────────────────
function formatImapError(err, host) {
  const details = {
    message: err.message || "Unknown error",
    code: err.code || null,
    responseStatus: err.responseStatus || null,
    responseText: err.responseText || null,
    command: err.command || null,
    host,
  };

  let msg = "";

  if (err.code === "ENOTFOUND" || err.code === "EAI_AGAIN") {
    msg = `Serveur IMAP introuvable: ${host}. Vérifiez le nom d'hôte.`;
  } else if (err.code === "ECONNREFUSED") {
    msg = `Connexion refusée par ${host}. Vérifiez le port et SSL.`;
  } else if (err.code === "ETIMEDOUT" || err.code === "ESOCKET") {
    msg = `Timeout de connexion vers ${host}. Vérifiez le port (993 pour SSL, 143 sans SSL).`;
  } else if (err.responseText?.includes("AUTHENTICATIONFAILED") || err.responseText?.includes("LOGIN")) {
    msg = `Authentification échouée sur ${host}. Vérifiez email/mot de passe. Si vous utilisez Gmail/Outlook, un mot de passe d'application est requis.`;
  } else if (err.message?.includes("Command failed")) {
    const respText = err.responseText || "";
    if (respText) {
      msg = `Commande IMAP échouée sur ${host}: ${respText}`;
    } else {
      msg = `Commande IMAP échouée sur ${host}. Causes possibles: (1) mot de passe incorrect, (2) IMAP non activé sur le compte, (3) mot de passe d'application requis.`;
    }
  } else {
    msg = `Erreur IMAP (${host}): ${err.message}`;
  }

  return { msg, details };
}

// ── Format SMTP error with details ──────────────────────────
function formatSmtpError(err, host) {
  const details = {
    message: err.message || "Unknown error",
    code: err.code || null,
    responseCode: err.responseCode || null,
    command: err.command || null,
    host,
  };

  let msg = "";
  let httpStatus = 502;

  if (err.responseCode === 535 || err.code === "EAUTH" || err.message?.includes("authentication")) {
    msg = `Authentification SMTP échouée sur ${host}. Vérifiez email/mot de passe.`;
    httpStatus = 401;
  } else if (err.code === "ECONNREFUSED") {
    msg = `Connexion SMTP refusée par ${host}. Vérifiez le port.`;
  } else if (err.code === "ETIMEDOUT" || err.code === "ESOCKET") {
    msg = `Timeout SMTP vers ${host}. Vérifiez le port (587 pour TLS, 465 pour SSL).`;
  } else {
    msg = `Envoi SMTP échoué (${host}): ${err.message}`;
  }

  return { msg, details, httpStatus };
}

// ── POST /test ───────────────────────────────────────────────
app.post("/test", async (req, res) => {
  const { connection } = req.body;
  if (!connection?.imap_host) {
    return res.status(400).json({ error: "Connection config required" });
  }

  const config = getImapConfig(connection);
  console.log(`[test] Connecting to ${connection.imap_host}:${config.port} as ${connection.email}`);

  const client = new ImapFlow(config);
  client.on('error', (err) => console.error(`[test] ImapFlow error: ${err.code || err.message}`));
  try {
    await client.connect();
    const mailboxes = await client.list();
    await client.logout();
    console.log(`[test] Success: ${mailboxes.length} mailboxes found`);
    res.json({
      connected: true,
      server: connection.imap_host,
      mailboxes_count: mailboxes.length,
    });
  } catch (err) {
    const { msg, details } = formatImapError(err, connection.imap_host);
    console.error(`[test] IMAP error:`, JSON.stringify(details, null, 2));
    res.status(502).json({
      error: msg,
      details,
    });
  }
});

// ── POST /fetch ──────────────────────────────────────────────
app.post("/fetch", async (req, res) => {
  const { connection, folder = "INBOX", limit = 30, offset = 0, since, include_body = true, search_message_id } = req.body;
  if (!connection?.imap_host) {
    return res.status(400).json({ error: "Connection config required" });
  }

  const client = new ImapFlow(getImapConfig(connection));

  // Prevent unhandled 'error' events from crashing the process
  client.on('error', (err) => {
    console.error(`[fetch] ImapFlow background error: ${err.code || err.message}`);
  });

  try {
    await client.connect();
    const lock = await client.getMailboxLock(folder);

    try {
      const status = await client.status(folder, { messages: true, unseen: true });
      const total = status.messages || 0;

      if (total === 0) {
        lock.release();
        await client.logout();
        return res.json({ emails: [], total: 0, folder });
      }

      const emails = [];
      let range;
      let useUid = false;

      // ── Priority 1: search by Message-ID header ──
      if (search_message_id) {
        try {
          const uids = await client.search({ header: { 'Message-ID': search_message_id } }, { uid: true });
          if (uids.length > 0) {
            range = uids.join(',');
            useUid = true;
            console.log(`[fetch] Found ${uids.length} message(s) for Message-ID search`);
          } else {
            console.warn(`[fetch] No message found for Message-ID: ${search_message_id}`);
            lock.release();
            await client.logout();
            return res.json({ emails: [], total, folder, unseen: status.unseen || 0 });
          }
        } catch (searchErr) {
          console.warn(`[fetch] Message-ID search failed: ${searchErr.message}, falling back to sequence`);
          // Fall through to sequence-based fetch
        }
      }

      // ── Priority 2: search by SINCE date ──
      if (!range && since) {
        const sinceDate = new Date(since);
        sinceDate.setDate(sinceDate.getDate() - 1);
        try {
          const uids = await client.search({ since: sinceDate }, { uid: true });
          if (uids.length === 0) {
            lock.release();
            await client.logout();
            return res.json({ emails: [], total: 0, folder });
          }
          const selectedUids = uids.slice(-limit);
          range = selectedUids.join(',');
          useUid = true;
        } catch (searchErr) {
          console.warn(`[fetch] SINCE search failed, falling back to sequence: ${searchErr.message}`);
        }
      }

      // ── Priority 3: sequence-based range (default) ──
      if (!range) {
        const end = Math.max(1, total - offset);
        const start = Math.max(1, end - limit + 1);
        if (end < 1 || start > total) {
          lock.release();
          await client.logout();
          return res.json({ emails: [], total, folder, unseen: status.unseen || 0 });
        }
        range = `${start}:${end}`;
      }

      console.log(`[fetch] Fetching range="${range}" useUid=${useUid} folder=${folder}`);

      // ── Charset mapping for Node.js Buffer.toString() ──────────
      const CHARSET_TO_NODE = {
        'utf-8': 'utf-8', 'utf8': 'utf-8',
        'iso-8859-1': 'latin1', 'iso_8859-1': 'latin1', 'latin1': 'latin1', 'latin-1': 'latin1',
        'iso-8859-15': 'latin1', 'latin9': 'latin1',
        'windows-1252': 'latin1', 'cp1252': 'latin1',
        'us-ascii': 'ascii', 'ascii': 'ascii',
      };

      function resolveNodeEncoding(charset) {
        if (!charset) return 'utf-8';
        const key = charset.toLowerCase().trim().replace(/['"]/g, '');
        return CHARSET_TO_NODE[key] || 'utf-8';
      }

      function extractCharset(structure) {
        if (!structure) return null;
        const params = structure.parameters || structure.params || {};
        return params.charset || params.CHARSET || null;
      }

      function decodeBuffer(buf, charset) {
        const encoding = resolveNodeEncoding(charset);
        if (encoding === 'latin1') {
          try {
            const bytes = new Uint8Array(buf);
            const decoder = new TextDecoder(charset?.toLowerCase()?.includes('1252') ? 'windows-1252' : 'iso-8859-1', { fatal: false });
            return decoder.decode(bytes);
          } catch (e) {
            console.warn(`[fetch] TextDecoder fallback for charset ${charset}:`, e.message);
            return buf.toString('latin1');
          }
        }
        return buf.toString(encoding);
      }

      function findBodyParts(structure, prefix = "") {
        const parts = { textPart: "", htmlPart: "", textCharset: null, htmlCharset: null };
        if (!structure) return parts;

        if (!structure.childNodes || structure.childNodes.length === 0) {
          const ct = (structure.type || "").toLowerCase();
          const partNum = prefix || "1";
          const cs = extractCharset(structure);
          if (ct === "text/plain" && !parts.textPart) { parts.textPart = partNum; parts.textCharset = cs; }
          if (ct === "text/html" && !parts.htmlPart) { parts.htmlPart = partNum; parts.htmlCharset = cs; }
          return parts;
        }

        for (let i = 0; i < structure.childNodes.length; i++) {
          const child = structure.childNodes[i];
          const childNum = prefix ? `${prefix}.${i + 1}` : `${i + 1}`;
          const ct = (child.type || "").toLowerCase();
          const cs = extractCharset(child);

          if (ct === "text/plain" && !parts.textPart) {
            parts.textPart = childNum;
            parts.textCharset = cs;
          } else if (ct === "text/html" && !parts.htmlPart) {
            parts.htmlPart = childNum;
            parts.htmlCharset = cs;
          }

          if (child.childNodes && child.childNodes.length > 0) {
            const sub = findBodyParts(child, childNum);
            if (!parts.textPart && sub.textPart) { parts.textPart = sub.textPart; parts.textCharset = sub.textCharset; }
            if (!parts.htmlPart && sub.htmlPart) { parts.htmlPart = sub.htmlPart; parts.htmlCharset = sub.htmlCharset; }
          }
        }
        return parts;
      }

      // ── First pass: fetch envelope + bodyStructure ──
      const msgMetas = [];
      for await (const msg of client.fetch(range, {
        envelope: true,
        bodyStructure: true,
        flags: true,
        source: false,
        uid: useUid,
      })) {
        const { textPart, htmlPart, textCharset, htmlCharset } = findBodyParts(msg.bodyStructure);
        msgMetas.push({ msg, textPart: textPart || "1", htmlPart, textCharset, htmlCharset });
      }

      // ── Second pass: fetch body parts ──
      for (const { msg, textPart, htmlPart, textCharset, htmlCharset } of msgMetas) {
        const env = msg.envelope;
        const from = env.from?.[0] || {};
        const to = env.to?.[0] || {};

        let bodyText = "";
        let bodyHtml = "";

        if (include_body) {
          const partsToFetch = new Set([textPart]);
          if (htmlPart) partsToFetch.add(htmlPart);

          try {
            for await (const partMsg of client.fetch(msg.seq.toString(), {
              bodyParts: [...partsToFetch],
            })) {
              if (partMsg.bodyParts) {
                const tp = partMsg.bodyParts.get(textPart);
                if (tp) bodyText = decodeBuffer(tp, textCharset);
                if (htmlPart) {
                  const hp = partMsg.bodyParts.get(htmlPart);
                  if (hp) bodyHtml = decodeBuffer(hp, htmlCharset);
                }
              }
            }
          } catch (partErr) {
            console.warn(`[fetch] Body part fetch failed for seq ${msg.seq}, falling back to part 1:`, partErr.message);
            try {
              for await (const fallback of client.fetch(msg.seq.toString(), {
                bodyParts: ["1"],
              })) {
                const p = fallback.bodyParts?.get("1");
                if (p) bodyText = decodeBuffer(p, textCharset);
              }
            } catch (fallbackErr) {
              console.warn(`[fetch] Fallback body fetch also failed for seq ${msg.seq}:`, fallbackErr.message);
            }
          }

          const BODY_CAP = 150_000;
          if (bodyText.length > BODY_CAP) bodyText = bodyText.slice(0, BODY_CAP) + "\n<!-- truncated -->";
          if (bodyHtml.length > BODY_CAP) bodyHtml = bodyHtml.slice(0, BODY_CAP) + "\n<!-- truncated -->";
        }

        const snippetSource = bodyText || bodyHtml.replace(/<[^>]+>/g, ' ');

        emails.push({
          message_id: env.messageId || msg.uid.toString(),
          from_address: from.address || "",
          from_name: from.name || from.address?.split("@")[0] || "",
          to_address: to.address || "",
          subject: env.subject || "(sans objet)",
          snippet: snippetSource.slice(0, 200).replace(/\n/g, " ").trim(),
          body_text: include_body ? (bodyText || null) : null,
          body_html: include_body ? (bodyHtml || null) : null,
          date: env.date?.toISOString() || new Date().toISOString(),
          is_read: msg.flags?.has("\\Seen") || false,
          is_starred: msg.flags?.has("\\Flagged") || false,
          priority: msg.flags?.has("\\Important") ? "urgent" : "normal",
          has_attachments: (msg.bodyStructure?.childNodes?.length || 0) > 1,
          uid: msg.uid,
        });
      }

      emails.reverse();
      res.json({ emails, total, folder, unseen: status.unseen || 0 });
    } finally {
      lock.release();
    }

    await client.logout();
  } catch (err) {
    const { msg, details } = formatImapError(err, connection.imap_host);
    console.error(`[fetch] IMAP error:`, JSON.stringify(details, null, 2));
    res.status(502).json({ error: msg, details });
    // Try to disconnect gracefully
    try { await client.logout(); } catch (_) {}
  }
});

// ── POST /send ───────────────────────────────────────────────
app.post("/send", async (req, res) => {
  const { connection, to, subject, body, reply_to_message_id } = req.body;
  if (!connection?.smtp_host || !to || !subject) {
    return res.status(422).json({ error: "connection, to, subject required" });
  }

  // Validate email format
  if (!EMAIL_REGEX.test(to)) {
    return res.status(422).json({ error: `Invalid email address: ${to}` });
  }

  try {
    const transporter = nodemailer.createTransport(getSmtpConfig(connection));
    const info = await transporter.sendMail({
      from: connection.email,
      to,
      subject,
      text: body,
      ...(reply_to_message_id && { inReplyTo: reply_to_message_id }),
    });
    res.json({ sent: true, messageId: info.messageId });
  } catch (err) {
    const { msg, details, httpStatus } = formatSmtpError(err, connection.smtp_host);
    console.error(`[send] SMTP error:`, JSON.stringify(details, null, 2));
    res.status(httpStatus).json({ error: msg, details });
  }
});

// ── POST /folders ────────────────────────────────────────────
app.post("/folders", async (req, res) => {
  const { connection } = req.body;
  if (!connection?.imap_host) {
    return res.status(400).json({ error: "Connection config required" });
  }

  const client = new ImapFlow(getImapConfig(connection));
  client.on('error', (err) => console.error(`[folders] ImapFlow error: ${err.code || err.message}`));
  try {
    await client.connect();
    const mailboxes = await client.list();
    await client.logout();

    const folders = mailboxes.map((m) => ({
      name: m.name,
      path: m.path,
      delimiter: m.delimiter,
      specialUse: m.specialUse || null,
      flags: [...(m.flags || [])],
    }));
    res.json({ folders });
  } catch (err) {
    const { msg, details } = formatImapError(err, connection.imap_host);
    console.error(`[folders] IMAP error:`, JSON.stringify(details, null, 2));
    res.status(502).json({ error: msg, details });
  }
});

// ── POST /update ─────────────────────────────────────────────
app.post("/update", async (req, res) => {
  const { connection, email_id, is_read, is_starred, move_to_folder } = req.body;
  if (!connection?.imap_host) {
    return res.status(400).json({ error: "Connection config required" });
  }

  const client = new ImapFlow(getImapConfig(connection));
  client.on('error', (err) => console.error(`[update] ImapFlow error: ${err.code || err.message}`));
  try {
    await client.connect();
    const lock = await client.getMailboxLock("INBOX");

    try {
      const uid = parseInt(email_id);
      if (isNaN(uid)) throw new Error("Invalid email_id");

      if (is_read !== undefined) {
        if (is_read) {
          await client.messageFlagsAdd(uid.toString(), ["\\Seen"], { uid: true });
        } else {
          await client.messageFlagsRemove(uid.toString(), ["\\Seen"], { uid: true });
        }
      }

      if (is_starred !== undefined) {
        if (is_starred) {
          await client.messageFlagsAdd(uid.toString(), ["\\Flagged"], { uid: true });
        } else {
          await client.messageFlagsRemove(uid.toString(), ["\\Flagged"], { uid: true });
        }
      }

      if (move_to_folder) {
        await client.messageMove(uid.toString(), move_to_folder, { uid: true });
      }
    } finally {
      lock.release();
    }

    await client.logout();
    res.json({ updated: true });
  } catch (err) {
    const { msg } = formatImapError(err, connection.imap_host);
    console.error(`[update] IMAP error:`, err.message);
    res.status(502).json({ error: msg });
  }
});

// ── Health check ─────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "email-imap-proxy", version: "1.2.0", timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`📧 Email IMAP/SMTP proxy v1.2.0 running on port ${PORT}`);
  console.log(`   TLS rejectUnauthorized: ${TLS_SECURE}`);
});
