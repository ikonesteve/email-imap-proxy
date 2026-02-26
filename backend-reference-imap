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
    tls: { rejectUnauthorized: false },
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
    tls: { rejectUnauthorized: false },
  };
}

// ── POST /test ───────────────────────────────────────────────
app.post("/test", async (req, res) => {
  const { connection } = req.body;
  if (!connection?.imap_host) {
    return res.status(400).json({ error: "Connection config required" });
  }

  const client = new ImapFlow(getImapConfig(connection));
  try {
    await client.connect();
    const mailboxes = await client.list();
    await client.logout();
    res.json({
      connected: true,
      server: connection.imap_host,
      mailboxes_count: mailboxes.length,
    });
  } catch (err) {
    res.status(502).json({
      error: `IMAP connection failed: ${err.message}`,
      host: connection.imap_host,
    });
  }
});

// ── POST /fetch ──────────────────────────────────────────────
app.post("/fetch", async (req, res) => {
  const { connection, folder = "INBOX", limit = 30, offset = 0 } = req.body;
  if (!connection?.imap_host) {
    return res.status(400).json({ error: "Connection config required" });
  }

  const client = new ImapFlow(getImapConfig(connection));
  try {
    await client.connect();
    const lock = await client.getMailboxLock(folder);

    try {
      const status = await client.status(folder, { messages: true, unseen: true });
      const total = status.messages || 0;
      const start = Math.max(1, total - offset - limit + 1);
      const end = Math.max(1, total - offset);

      if (total === 0) {
        return res.json({ emails: [], total: 0, folder });
      }

      const emails = [];
      const range = `${start}:${end}`;

      for await (const msg of client.fetch(range, {
        envelope: true,
        bodyStructure: true,
        flags: true,
        source: false,
        bodyParts: ["1"], // text part
      })) {
        const env = msg.envelope;
        const from = env.from?.[0] || {};
        const to = env.to?.[0] || {};

        let bodyText = "";
        if (msg.bodyParts) {
          const part = msg.bodyParts.get("1");
          if (part) bodyText = part.toString();
        }

        emails.push({
          message_id: env.messageId || msg.uid.toString(),
          from_address: from.address || "",
          from_name: from.name || from.address?.split("@")[0] || "",
          to_address: to.address || "",
          subject: env.subject || "(sans objet)",
          snippet: bodyText.slice(0, 200).replace(/\n/g, " ").trim(),
          body_text: bodyText,
          date: env.date?.toISOString() || new Date().toISOString(),
          is_read: msg.flags?.has("\\Seen") || false,
          is_starred: msg.flags?.has("\\Flagged") || false,
          priority: msg.flags?.has("\\Important") ? "urgent" : "normal",
          has_attachments: (msg.bodyStructure?.childNodes?.length || 0) > 1,
          uid: msg.uid,
        });
      }

      emails.reverse(); // newest first
      res.json({ emails, total, folder, unseen: status.unseen || 0 });
    } finally {
      lock.release();
    }

    await client.logout();
  } catch (err) {
    res.status(502).json({ error: `IMAP fetch failed: ${err.message}` });
  }
});

// ── POST /send ───────────────────────────────────────────────
app.post("/send", async (req, res) => {
  const { connection, to, subject, body, reply_to_message_id } = req.body;
  if (!connection?.smtp_host || !to || !subject) {
    return res.status(400).json({ error: "connection, to, subject required" });
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
    res.status(502).json({ error: `SMTP send failed: ${err.message}` });
  }
});

// ── POST /folders ────────────────────────────────────────────
app.post("/folders", async (req, res) => {
  const { connection } = req.body;
  if (!connection?.imap_host) {
    return res.status(400).json({ error: "Connection config required" });
  }

  const client = new ImapFlow(getImapConfig(connection));
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
    res.status(502).json({ error: `IMAP list failed: ${err.message}` });
  }
});

// ── POST /update ─────────────────────────────────────────────
app.post("/update", async (req, res) => {
  const { connection, email_id, is_read, is_starred, move_to_folder } = req.body;
  if (!connection?.imap_host) {
    return res.status(400).json({ error: "Connection config required" });
  }

  const client = new ImapFlow(getImapConfig(connection));
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
    res.status(502).json({ error: `IMAP update failed: ${err.message}` });
  }
});

// ── Health check ─────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "email-imap-proxy", timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`📧 Email IMAP/SMTP proxy running on port ${PORT}`);
});
