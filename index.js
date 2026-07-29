//@ts-check
"use strict";

/**
 * @typedef {import('@zone-eu/types').AnyRecord} AnyRecord
 * @typedef {import('@zone-eu/types').Envelope} Envelope
 * @typedef {import('@zone-eu/types').SmtpSession} SmtpSession
 * @typedef {import('@zone-eu/types').ZoneMtaPluginTools} ZoneMtaPluginTools
 * @typedef {{getConnection?: (session: SmtpSession) => KirinConnection}} PluginManagerOptions
 * @typedef {ZoneMtaPluginTools & {manager?: {options?: PluginManagerOptions}}} PluginTools
 * @typedef {{get(name: string): string, add(name: string, value: string | number | Buffer, index?: number): void, remove(name: string): void}} MessageHeaders
 * @typedef {{header: MessageHeaders | false, getMessageBuffer(): Buffer}} KirinTransaction
 * @typedef {{transaction: KirinTransaction | false, results: Map<string, unknown>, remote?: {is_private?: boolean}}} KirinConnection
 * @typedef {{host: string, port: number, unixSocket: string, timeout: number, addHeaders: 'always' | 'never' | 'sometimes', subject: string, dkim: {enabled: boolean}, header: {bar: string, report: string, score: string}, check: {authenticated: boolean, privateIp: boolean, localIp: boolean}, reject: {message: string, spam: boolean, authenticated: boolean}, rewriteSubject: {enabled: boolean}, milterHeaders: {enabled: boolean}, smtpMessage: {enabled: boolean}, softReject: {enabled: boolean, message: string}, defer: {error: boolean, timeout: boolean}, spamBar: {positive: string, negative: string, neutral: string}}} RspamdConfig
 * @typedef {{headers: Record<string, string | string[]>, host?: string, port?: number, socketPath?: string}} RspamdRequestOptions
 * @typedef {{name?: string, score?: number}} RspamdSymbol
 * @typedef {AnyRecord & {error?: unknown, action?: string, score?: number, subject?: string, symbols?: Record<string, RspamdSymbol>, messages?: unknown, milter?: {remove_headers?: Record<string, unknown>, add_headers?: Record<string, unknown>}, 'dkim-signature'?: string}} RspamdResponse
 * @typedef {AnyRecord & {symbols: Record<string, number>, emit?: boolean, time?: number}} RspamdLog
 * @typedef {{data: RspamdResponse, log: RspamdLog} | {error: string}} ParsedRspamdResponse
 */

const net = require("node:net");
const DSN = require("haraka-dsn");

const PLUGIN_NAME = "rspamd";

/** @type {RspamdConfig} */
const DEFAULT_CONFIG = {
  host: "localhost",
  port: 11333,
  unixSocket: "",
  timeout: 29,
  addHeaders: "sometimes",
  subject: "[SPAM] %s",
  dkim: {
    enabled: true,
  },
  header: {
    bar: "",
    report: "",
    score: "",
  },
  check: {
    authenticated: false,
    privateIp: false,
    localIp: false,
  },
  reject: {
    message: "Detected as spam",
    spam: true,
    authenticated: false,
  },
  rewriteSubject: {
    enabled: true,
  },
  milterHeaders: {
    enabled: true,
  },
  smtpMessage: {
    enabled: true,
  },
  softReject: {
    enabled: true,
    message: "Deferred by policy",
  },
  defer: {
    error: false,
    timeout: false,
  },
  spamBar: {
    positive: "+",
    negative: "-",
    neutral: "/",
  },
};

/**
 * @param {PluginTools['config']} input
 * @returns {RspamdConfig}
 */
const getConfig = (input) => {
  const source = /** @type {RspamdConfig} */ (
    /** @type {unknown} */ (input === true ? {} : input)
  );

  return {
    ...DEFAULT_CONFIG,
    ...source,
    dkim: { ...DEFAULT_CONFIG.dkim, ...source.dkim },
    header: { ...DEFAULT_CONFIG.header, ...source.header },
    check: { ...DEFAULT_CONFIG.check, ...source.check },
    reject: { ...DEFAULT_CONFIG.reject, ...source.reject },
    rewriteSubject: {
      ...DEFAULT_CONFIG.rewriteSubject,
      ...source.rewriteSubject,
    },
    milterHeaders: { ...DEFAULT_CONFIG.milterHeaders, ...source.milterHeaders },
    smtpMessage: { ...DEFAULT_CONFIG.smtpMessage, ...source.smtpMessage },
    softReject: { ...DEFAULT_CONFIG.softReject, ...source.softReject },
    defer: { ...DEFAULT_CONFIG.defer, ...source.defer },
    spamBar: { ...DEFAULT_CONFIG.spamBar, ...source.spamBar },
  };
};

/**
 * Prevents request metadata from injecting additional HTTP headers.
 *
 * @param {unknown} value
 * @returns {string}
 */
const cleanHeaderValue = (value) =>
  String(value ?? "").replace(/[\r\n]+/g, " ");

/**
 * @param {RspamdRequestOptions} options
 * @param {Buffer} body
 * @returns {Buffer}
 */
const buildHttpRequest = (options, body) => {
  const host = options.socketPath
    ? "localhost"
    : `${options.host}:${options.port}`;
  const lines = [
    "POST /checkv2 HTTP/1.1",
    `Host: ${host}`,
    "Content-Type: message/rfc822",
    `Content-Length: ${body.length}`,
    "Connection: close",
  ];

  for (const [key, value] of Object.entries(options.headers)) {
    for (const entry of Array.isArray(value) ? value : [value]) {
      lines.push(`${key}: ${cleanHeaderValue(entry)}`);
    }
  }

  lines.push("", "");
  return Buffer.concat([Buffer.from(lines.join("\r\n"), "utf8"), body]);
};

/**
 * @param {Buffer} body
 * @returns {Buffer}
 */
const decodeChunkedBody = (body) => {
  /** @type {Buffer[]} */
  const chunks = [];
  let offset = 0;

  while (offset < body.length) {
    const lineEnd = body.indexOf("\r\n", offset);
    if (lineEnd < 0) {
      throw new Error("Invalid chunked HTTP response");
    }

    const size = Number.parseInt(
      body.subarray(offset, lineEnd).toString("ascii").split(";")[0],
      16,
    );
    if (!Number.isFinite(size)) {
      throw new Error("Invalid chunk size in HTTP response");
    }

    offset = lineEnd + 2;
    if (size === 0) {
      return Buffer.concat(chunks);
    }
    if (offset + size + 2 > body.length) {
      throw new Error("Incomplete chunked HTTP response");
    }

    chunks.push(body.subarray(offset, offset + size));
    offset += size + 2;
  }

  throw new Error("Incomplete chunked HTTP response");
};

/**
 * @param {Buffer} response
 * @returns {string}
 */
const getHttpResponseBody = (response) => {
  const separator = response.indexOf("\r\n\r\n");
  if (separator < 0) {
    throw new Error("Invalid HTTP response: no header/body separator");
  }

  const rawHeaders = response.subarray(0, separator).toString("latin1");
  const body = response.subarray(separator + 4);
  return (
    /^transfer-encoding:\s*chunked\s*$/im.test(rawHeaders)
      ? decodeChunkedBody(body)
      : body
  ).toString("utf8");
};

/**
 * @param {RspamdRequestOptions} options
 * @param {Buffer} body
 * @param {number} timeout
 * @returns {Promise<string>}
 */
const requestRspamd = (options, body, timeout) =>
  new Promise((resolve, reject) => {
    const socket = options.socketPath
      ? net.createConnection(options.socketPath)
      : net.createConnection(
          /** @type {number} */ (options.port),
          /** @type {string} */ (options.host),
        );
    const request = buildHttpRequest(options, body);
    let response = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => {
      const error = /** @type {Error & {code?: string}} */ (
        new Error("socket timeout")
      );
      error.code = "ETIMEDOUT";
      socket.destroy(error);
    }, timeout);
    timer.unref();

    /**
     * @param {Error} err
     */
    const fail = (err) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      reject(err);
    };

    socket.once("connect", () => socket.write(request));
    socket.on("data", (chunk) => {
      response = Buffer.concat([
        response,
        Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
      ]);
    });
    socket.once("end", () => {
      if (settled) {
        return;
      }
      try {
        const responseBody = getHttpResponseBody(response);
        settled = true;
        clearTimeout(timer);
        resolve(responseBody);
      } catch (err) {
        fail(/** @type {Error} */ (err));
      }
    });
    socket.once("error", fail);
    socket.once("close", () => {
      if (!settled) {
        fail(new Error("Rspamd connection closed without a response"));
      }
    });
  });

/**
 * @param {string | false | undefined} address
 * @returns {boolean}
 */
const isLocalAddress = (address) => {
  if (!address) {
    return false;
  }

  const normalized = address
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/^::ffff:/, "");
  return (
    normalized === "::1" ||
    normalized === "0:0:0:0:0:0:0:1" ||
    /^127(?:\.\d{1,3}){3}$/.test(normalized)
  );
};

/**
 * @param {KirinConnection} connection
 * @param {Envelope} envelope
 * @param {RspamdConfig} config
 * @returns {string | false}
 */
const getSkipReason = (connection, envelope, config) => {
  if (!config.check.authenticated && envelope.user) {
    return "authed";
  }

  const isLocal = isLocalAddress(envelope.origin);
  if (!config.check.localIp && isLocal) {
    return "local_ip";
  }
  if (!config.check.privateIp && connection.remote?.is_private) {
    if (!(config.check.localIp && isLocal)) {
      return "private_ip";
    }
  }

  return false;
};

/**
 * @param {KirinConnection} connection
 * @param {Envelope} envelope
 * @param {RspamdConfig} config
 * @returns {RspamdRequestOptions}
 */
const getRequestOptions = (connection, envelope, config) => {
  /** @type {Record<string, string | string[]>} */
  const headers = {};
  const recipients = (
    Array.isArray(envelope.to) ? envelope.to : envelope.to ? [envelope.to] : []
  ).map(cleanHeaderValue);
  const authenticatedUser = cleanHeaderValue(envelope.user || "");
  const from = cleanHeaderValue(envelope.from || "");
  const fcrdns = connection.results.get("fcrdns");
  const fcrdnsHost =
    fcrdns &&
    typeof fcrdns === "object" &&
    Array.isArray(/** @type {AnyRecord} */ (fcrdns).fcrdns)
      ? /** @type {AnyRecord} */ (fcrdns).fcrdns[0]
      : false;
  const spf = connection.results.get("spf");
  const spfResult =
    spf && typeof spf === "object"
      ? /** @type {AnyRecord} */ (spf).result
      : false;

  if (authenticatedUser) headers.User = authenticatedUser;
  if (envelope.origin) headers.IP = cleanHeaderValue(envelope.origin);
  if (fcrdnsHost || envelope.originhost)
    headers.Hostname = cleanHeaderValue(fcrdnsHost || envelope.originhost);
  if (envelope.transhost) headers.Helo = cleanHeaderValue(envelope.transhost);
  if (spfResult)
    headers.SPF = cleanHeaderValue(String(spfResult).toLowerCase());
  if (from) headers.From = from;
  if (recipients.length) {
    headers.Rcpt = recipients;
    if (recipients.length === 1) headers["Deliver-To"] = recipients[0];
  }
  if (envelope.id) headers["Queue-Id"] = cleanHeaderValue(envelope.id);

  if (envelope.tls && typeof envelope.tls === "object") {
    if (envelope.tls.name)
      headers["TLS-Cipher"] = cleanHeaderValue(envelope.tls.name);
    if (envelope.tls.version)
      headers["TLS-Version"] = cleanHeaderValue(envelope.tls.version);
  }

  return config.unixSocket
    ? { headers, socketPath: config.unixSocket }
    : {
        headers,
        host: config.host,
        port: config.port,
      };
};

/**
 * @param {RspamdResponse} data
 * @param {PluginTools} app
 * @returns {RspamdLog}
 */
const getCleanResult = (data, app) => {
  /** @type {Record<string, number>} */
  const symbols = {};
  /** @type {RspamdLog} */
  const clean = { symbols };

  for (const value of Object.values(data.symbols || {})) {
    if (value.name && value.score !== undefined) {
      symbols[value.name] = value.score;
    } else {
      app.logger.error(PLUGIN_NAME, "Invalid Rspamd symbol", value);
    }
  }

  for (const key of ["action", "is_skipped", "required_score", "score"]) {
    if (["boolean", "number", "string"].includes(typeof data[key])) {
      clean[key] = data[key];
    }
  }

  for (const key of ["urls", "emails", "messages"]) {
    if (Array.isArray(data[key]) && data[key].length) {
      clean[key] = data[key].join(",");
    }
  }

  return clean;
};

/**
 * @param {string} rawData
 * @param {PluginTools} app
 * @returns {ParsedRspamdResponse}
 */
const parseResponse = (rawData, app) => {
  if (!rawData) {
    return { error: "empty response" };
  }

  let parsed;
  try {
    parsed = JSON.parse(rawData);
  } catch (err) {
    return {
      error: `parse failure: ${err instanceof Error ? err.message : err}`,
    };
  }

  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    !Object.keys(parsed).length
  ) {
    return { error: "invalid response" };
  }

  const data = /** @type {RspamdResponse} */ (parsed);
  if (Object.keys(data).length === 1 && data.error) {
    return { error: String(data.error) };
  }

  return {
    data,
    log: getCleanResult(data, app),
  };
};

/**
 * @param {MessageHeaders} headers
 * @param {RspamdResponse} data
 * @param {RspamdConfig} config
 */
const rewriteSubject = (headers, data, config) => {
  if (!config.rewriteSubject.enabled || data.action !== "rewrite subject") {
    return;
  }

  const oldSubject = headers.get("Subject");
  const newSubject = String(data.subject || config.subject).replace(
    "%s",
    String(oldSubject),
  );
  headers.remove("Subject");
  headers.add("Subject", newSubject);
};

/**
 * @param {PluginTools} app
 * @param {MessageHeaders} headers
 * @param {RspamdResponse} data
 * @param {RspamdConfig} config
 */
const applyMilterHeaders = (app, headers, data, config) => {
  if (!config.milterHeaders.enabled || !data.milter) {
    return;
  }

  for (const key of Object.keys(data.milter.remove_headers || {})) {
    headers.remove(key);
  }

  try {
    if (data.milter.add_headers) {
      app.logger.verbose(
        PLUGIN_NAME,
        `milter.add_headers: ${JSON.stringify(data.milter.add_headers)}`,
      );
    }
    for (const [key, input] of Object.entries(data.milter.add_headers || {})) {
      for (const headerValue of Array.isArray(input) ? input : [input]) {
        const value =
          headerValue && typeof headerValue === "object"
            ? headerValue.value
            : headerValue;
        if (value !== undefined && value !== null) {
          headers.add(key, String(value));
        }
      }
    }
  } catch (err) {
    app.logger.error(PLUGIN_NAME, `milter.add_headers error: ${err}`);
  }
};

/**
 * @param {RspamdResponse} data
 * @param {RspamdConfig} config
 * @returns {boolean}
 */
const wantsHeadersAdded = (data, config) =>
  config.addHeaders === "always" ||
  (config.addHeaders === "sometimes" && data.action === "add header");

/**
 * @param {MessageHeaders} headers
 * @param {RspamdResponse} data
 * @param {RspamdConfig} config
 */
const addRspamdHeaders = (headers, data, config) => {
  if (!wantsHeadersAdded(data, config)) {
    return;
  }

  if (config.header.bar) {
    let count = 1;
    let character = config.spamBar.neutral || "/";
    if (Number(data.score) >= 1) {
      count = Math.floor(Number(data.score));
      character = config.spamBar.positive || "+";
    } else if (Number(data.score) <= -1) {
      count = Math.floor(Number(data.score) * -1);
      character = config.spamBar.negative || "-";
    }
    headers.remove(config.header.bar);
    headers.add(config.header.bar, character.repeat(count));
  }

  if (config.header.report) {
    const report = Object.values(data.symbols || {})
      .filter((symbol) => symbol.score)
      .map((symbol) => `${symbol.name}(${symbol.score})`)
      .join(" ");
    headers.remove(config.header.report);
    headers.add(config.header.report, report);
  }

  if (config.header.score) {
    headers.remove(config.header.score);
    headers.add(config.header.score, `${data.score}`);
  }
};

/**
 * @param {MessageHeaders} headers
 * @param {RspamdResponse} data
 * @param {RspamdConfig} config
 */
const addDkimHeader = (headers, data, config) => {
  if (config.dkim.enabled && data["dkim-signature"]) {
    headers.add("DKIM-Signature", data["dkim-signature"]);
  }
};

/**
 * @param {RspamdResponse} data
 * @param {RspamdConfig} config
 * @returns {string | undefined}
 */
const getSmtpMessage = (data, config) => {
  if (
    !config.smtpMessage.enabled ||
    !data.messages ||
    typeof data.messages !== "object"
  ) {
    return;
  }
  const messages = /** @type {AnyRecord} */ (data.messages);
  return messages.smtp_message ? String(messages.smtp_message) : undefined;
};

/**
 * @param {RspamdResponse} data
 * @param {Envelope} envelope
 * @param {RspamdConfig} config
 * @returns {boolean}
 */
const wantsReject = (data, envelope, config) => {
  if (data.action !== "reject") {
    return false;
  }
  return envelope.user ? config.reject.authenticated : config.reject.spam;
};

/**
 * @param {PluginTools} app
 * @param {Envelope} envelope
 * @param {number} code
 * @param {string} message
 * @returns {Error}
 */
const smtpReject = (app, envelope, code, message) =>
  app.reject(
    envelope,
    PLUGIN_NAME,
    "",
    `${code} ${String(message).replace(/^\d{3}\s+/, "")}`,
  );

/**
 * @param {PluginTools} app
 * @param {RspamdResponse} data
 * @param {RspamdLog} log
 */
const logResult = (app, data, log) => {
  /** @type {AnyRecord} */
  const entry = {
    short_message: `rspamd results (score: ${data.score})`,
    ...log,
  };
  delete entry.symbols;

  for (const [key, value] of Object.entries(data.symbols || {})) {
    entry[`_RSPAMD_${key.toUpperCase()}`] = value.score;
  }

  try {
    app.loggelf(entry);
  } catch (err) {
    app.logger.error(PLUGIN_NAME, `Rspamd GELF logging failed: ${err}`);
  }
};

/**
 * @param {PluginTools} app
 * @param {RspamdConfig} config
 * @param {Envelope} envelope
 * @param {SmtpSession} session
 * @returns {Promise<void>}
 */
const scanMessage = async (app, config, envelope, session) => {
  const getConnection = app.manager?.options?.getConnection;
  if (typeof getConnection !== "function") {
    throw new Error("Kirin connection resolver is not configured");
  }

  const connection = getConnection(session);
  const transaction = connection.transaction;
  if (!transaction) {
    return;
  }

  if (!transaction.header) {
    return;
  }

  const skip = getSkipReason(connection, envelope, config);
  if (skip) {
    connection.results.set(PLUGIN_NAME, { skip });
    return;
  }

  const start = Date.now();
  let rawData;
  try {
    rawData = await requestRspamd(
      getRequestOptions(connection, envelope, config),
      transaction.getMessageBuffer(),
      config.timeout * 1000,
    );
  } catch (err) {
    if (connection.transaction !== transaction || !transaction.header) {
      return;
    }
    const error = /** @type {Error & {code?: string}} */ (err);
    connection.results.set(PLUGIN_NAME, { err: error.message });

    if (error.code === "ETIMEDOUT") {
      if (config.defer.timeout) {
        throw smtpReject(app, envelope, 450, "Rspamd scan timeout");
      }
      return;
    }
    if (config.defer.error) {
      throw smtpReject(app, envelope, 450, "Rspamd scan error");
    }
    return;
  }

  if (connection.transaction !== transaction || !transaction.header) {
    return;
  }
  const headers = transaction.header;
  const response = parseResponse(rawData, app);
  if ("error" in response) {
    connection.results.set(PLUGIN_NAME, { err: response.error });
    if (config.defer.error) {
      throw smtpReject(app, envelope, 450, "Rspamd scan error");
    }
    return;
  }

  response.log.emit = true;
  response.log.time = (Date.now() - start) / 1000;
  connection.results.set(PLUGIN_NAME, {
    ...response.log,
    symbols: response.data.symbols || response.log.symbols,
  });
  logResult(app, response.data, response.log);

  const smtpMessage = getSmtpMessage(response.data, config);
  rewriteSubject(headers, response.data, config);

  if (config.softReject.enabled && response.data.action === "soft reject") {
    const dsn = DSN.sec_unauthorized(
      smtpMessage || config.softReject.message,
      451,
    );
    throw smtpReject(app, envelope, dsn.code, dsn.reply);
  }
  if (wantsReject(response.data, envelope, config)) {
    throw smtpReject(app, envelope, 550, smtpMessage || config.reject.message);
  }

  addDkimHeader(headers, response.data, config);
  applyMilterHeaders(app, headers, response.data, config);
  addRspamdHeaders(headers, response.data, config);
};

/** @type {import('@zone-eu/types').ZoneMtaPluginModule['title']} */
module.exports.title = PLUGIN_NAME;

/** @type {import('@zone-eu/types').ZoneMtaPluginModule['init']} */
module.exports.init = async (app) => {
  const plugin = /** @type {PluginTools} */ (app);
  const config = getConfig(plugin.config);

  /** @type {import('@zone-eu/types').ZoneMtaHookHandler<'smtp:data'>} */
  const onSmtpData = (envelope, session) =>
    scanMessage(plugin, config, envelope, session);
  plugin.addHook("smtp:data", onSmtpData);
};
