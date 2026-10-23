"use strict";

const net = require("node:net");
const tls = require("node:tls");
const os = require("node:os");

const timeoutMs = 20000;

function hasLineBreak(value) {
  return /[\r\n\u0000]/.test(value);
}

function validAddress(value) {
  return typeof value === "string" && value.length <= 254 && !hasLineBreak(value) &&
    /^[^\s@<>()",;:\\]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(value) &&
    value.split("@")[1].includes(".");
}

function encodeHeader(value) {
  const clean = String(value).replace(/[\r\n\u0000]+/g, " ").trim();
  return /^[\x20-\x7e]*$/.test(clean)
    ? clean
    : `=?UTF-8?B?${Buffer.from(clean, "utf8").toString("base64")}?=`;
}

function buildMessage({ from, fromName, to, subject, text }) {
  const sender = fromName
    ? `${encodeHeader(fromName).replace(/[",<>]/g, "")} <${from}>`
    : from;
  const domain = from.split("@")[1];
  const body = String(text).replace(/\r?\n/g, "\r\n");
  const wrapped = Buffer.from(body, "utf8").toString("base64").replace(/.{1,76}/g, "$&\r\n");
  return [
    `From: ${sender}`,
    `To: ${to}`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${Date.now().toString(36)}.${Math.random().toString(36).slice(2)}@${domain}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    wrapped,
  ].join("\r\n");
}

class SmtpSession {
  constructor(socket) {
    this.buffer = "";
    this.waiters = [];
    this.error = null;
    this.attach(socket);
  }

  attach(socket) {
    this.socket = socket;
    socket.setEncoding("utf8");
    socket.setTimeout(timeoutMs, () => this.fail(new Error("The mail server timed out.")));
    socket.on("data", (chunk) => {
      this.buffer += chunk;
      if (this.buffer.length > 65536) this.fail(new Error("The mail server sent too much data."));
      this.flush();
    });
    socket.on("error", (error) => this.fail(error));
    socket.on("close", () => this.fail(new Error("The mail server closed the connection.")));
  }

  fail(error) {
    if (!this.error) this.error = error;
    this.socket.destroy();
    this.waiters.splice(0).forEach((waiter) => waiter.reject(this.error));
  }

  flush() {
    while (this.waiters.length) {
      const lines = this.buffer.split("\r\n");
      const complete = lines.slice(0, -1);
      const end = complete.findIndex((line) => /^\d{3}( |$)/.test(line));
      if (end < 0) return;
      const reply = complete.slice(0, end + 1);
      this.buffer = lines.slice(end + 1).join("\r\n");
      const code = Number(reply[end].slice(0, 3));
      this.waiters.shift().resolve({ code, lines: reply.map((line) => line.slice(4)) });
    }
  }

  read() {
    if (this.error) return Promise.reject(this.error);
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
      this.flush();
    });
  }

  async command(line, expected) {
    if (this.error) throw this.error;
    this.socket.write(`${line}\r\n`);
    return this.expect(expected);
  }

  async expect(expected) {
    const reply = await this.read();
    if (!expected.includes(reply.code)) {
      throw new Error(`Mail server replied ${reply.code}: ${reply.lines.join(" ").slice(0, 200)}`);
    }
    return reply;
  }
}

function connect(config) {
  return new Promise((resolve, reject) => {
    const options = { host: config.host, port: config.port, servername: net.isIP(config.host) ? undefined : config.host };
    const socket = config.security === "tls"
      ? tls.connect({ ...options, minVersion: "TLSv1.2" })
      : net.connect(options);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("Could not connect to the mail server."));
    }, timeoutMs);
    socket.once(config.security === "tls" ? "secureConnect" : "connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function sendMail(config, message) {
  if (![message.from, message.to].every(validAddress)) {
    throw new Error("Invalid sender or recipient address.");
  }
  const socket = await connect(config);
  let session = new SmtpSession(socket);
  try {
    await session.expect([220]);
    const hello = os.hostname().replace(/[^A-Za-z0-9.-]/g, "") || "localhost";
    let ehlo = await session.command(`EHLO ${hello}`, [250]);
    if (config.security === "starttls") {
      if (!ehlo.lines.some((line) => /^STARTTLS$/i.test(line))) {
        throw new Error("The mail server does not support STARTTLS.");
      }
      await session.command("STARTTLS", [220]);
      const secure = tls.connect({
        socket,
        servername: net.isIP(config.host) ? undefined : config.host,
        minVersion: "TLSv1.2",
      });
      await new Promise((resolve, reject) => {
        secure.once("secureConnect", resolve);
        secure.once("error", reject);
      });
      session.socket.removeAllListeners("data");
      session.socket.removeAllListeners("close");
      session.socket.removeAllListeners("error");
      session = new SmtpSession(secure);
      ehlo = await session.command(`EHLO ${hello}`, [250]);
    }
    if (config.username) {
      const methods = ehlo.lines.find((line) => /^AUTH\s/i.test(line)) || "";
      if (/\bPLAIN\b/i.test(methods)) {
        const token = Buffer.from(`\0${config.username}\0${config.password}`).toString("base64");
        await session.command(`AUTH PLAIN ${token}`, [235]);
      } else if (/\bLOGIN\b/i.test(methods)) {
        await session.command("AUTH LOGIN", [334]);
        await session.command(Buffer.from(config.username).toString("base64"), [334]);
        await session.command(Buffer.from(config.password).toString("base64"), [235]);
      } else {
        throw new Error("The mail server offers no supported login method.");
      }
    }
    await session.command(`MAIL FROM:<${message.from}>`, [250]);
    await session.command(`RCPT TO:<${message.to}>`, [250, 251]);
    await session.command("DATA", [354]);
    const data = buildMessage(message).replace(/^\./gm, "..");
    await session.command(`${data}\r\n.`, [250]);
    await session.command("QUIT", [221]).catch(() => {});
  } finally {
    session.socket.destroy();
  }
}

module.exports = { sendMail, validAddress };
