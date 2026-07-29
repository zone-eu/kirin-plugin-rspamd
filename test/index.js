//@ts-check
"use strict";

const assert = require("node:assert/strict");
const net = require("node:net");
const { afterEach, describe, it } = require("node:test");
const {
  clearInterval,
  clearTimeout,
  setInterval,
  setTimeout,
} = require("node:timers");
const pluginModule = require("..");

/** @type {Set<import('node:net').Server>} */
const servers = new Set();
/** @type {Set<import('node:net').Socket>} */
const sockets = new Set();

afterEach(async () => {
  for (const socket of sockets) {
    socket.destroy();
  }
  await Promise.all(
    Array.from(
      servers,
      (server) =>
        new Promise((resolve) => server.close(() => resolve(undefined))),
    ),
  );
  sockets.clear();
  servers.clear();
});

/**
 * @param {import('node:net').Server} server
 * @returns {import('node:net').Server}
 */
const trackServer = (server) => {
  servers.add(server);
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  return server;
};

/**
 * @param {unknown} error
 * @param {number} responseCode
 * @param {string} message
 * @returns {boolean}
 */
const isResponseError = (error, responseCode, message) =>
  error instanceof Error &&
  "responseCode" in error &&
  error.responseCode === responseCode &&
  error.message === message;

class TestHeaders {
  /**
   * @param {Record<string, string | string[]>} values
   */
  constructor(values) {
    /** @type {Map<string, string[]>} */
    this.values = new Map();
    for (const [key, value] of Object.entries(values)) {
      this.values.set(
        key.toLowerCase(),
        Array.isArray(value) ? value : [value],
      );
    }
  }

  /**
   * @param {string} name
   * @returns {string}
   */
  get(name) {
    return this.values.get(name.toLowerCase())?.[0] || "";
  }

  /**
   * @param {string} name
   * @returns {string[]}
   */
  get_all(name) {
    return this.values.get(name.toLowerCase()) || [];
  }

  /**
   * @param {string} name
   * @param {unknown} value
   */
  add(name, value) {
    const key = name.toLowerCase();
    this.values.set(key, [...(this.values.get(key) || []), String(value)]);
  }

  /**
   * @param {string} name
   */
  remove(name) {
    this.values.delete(name.toLowerCase());
  }

  /**
   * @returns {Buffer}
   */
  build() {
    return Buffer.from(
      Array.from(this.values)
        .flatMap(([key, values]) => values.map((value) => `${key}: ${value}`))
        .join("\r\n") + "\r\n\r\n",
    );
  }
}

/**
 * @param {Record<string, unknown>} [changes]
 */
const createContext = (changes = {}) => {
  const headers = new TestHeaders({
    Subject: "Original subject",
    "X-Remove": "old",
  });
  const results = new Map();
  const transaction = {
    header: headers,
    getMessageBuffer() {
      return Buffer.concat([headers.build(), Buffer.from("Message body")]);
    },
  };
  const session = {
    id: "session-id",
    remoteAddress: "192.0.2.10",
    clientHostname: "client.example",
    hostNameAppearsAs: "münchen.example",
    secure: true,
    tlsOptions: {
      name: "IGNORED_SESSION_CIPHER",
      version: "IGNORED_SESSION_VERSION",
    },
    envelope: {
      mailFrom: {
        address: "séndér@bücher.example",
      },
      rcptTo: [
        {
          address: "one@example.com",
        },
        {
          address: "twö@example.com",
        },
      ],
    },
  };
  /** @type {{transaction: typeof transaction | false, results: Map<string, unknown>, remote: {is_private: boolean}}} */
  const connection = {
    transaction,
    results,
    remote: {
      is_private: false,
    },
  };
  const envelope = {
    id: "queue-id",
    sessionId: "session-id",
    interface: "kirin",
    from: "séndér@bücher.example",
    to: ["one@example.com", "twö@example.com"],
    origin: "192.0.2.10",
    originhost: "client.example",
    transhost: "münchen.example",
    transtype: "ESMTP",
    user: false,
    tls: {
      name: "TLS_AES_256_GCM_SHA384",
      version: "TLSv1.3",
    },
    time: Date.now(),
  };

  Object.assign(connection, changes.connection);
  Object.assign(session, changes.session);
  Object.assign(envelope, changes.envelope);
  return { connection, envelope, headers, results, session, transaction };
};

/**
 * @param {ReturnType<typeof createContext>} context
 * @param {Record<string, unknown>} config
 */
const initialize = async (context, config) => {
  /** @type {Function | undefined} */
  let dataHook;
  /** @type {Record<string, unknown>[]} */
  const logs = [];
  const app = {
    config,
    logger: {
      info() {},
      error() {},
      verbose() {},
    },
    manager: {
      options: {
        getConnection() {
          return context.connection;
        },
      },
    },
    /**
     * @param {string} name
     * @param {Function} handler
     */
    addHook(name, handler) {
      assert.equal(name, "smtp:data");
      dataHook = handler;
    },
    /**
     * @param {unknown} _envelope
     * @param {unknown} _description
     * @param {unknown} _messageInfo
     * @param {unknown} responseText
     */
    reject(_envelope, _description, _messageInfo, responseText) {
      const match = String(responseText).match(/^(\d{3})\s+(.*)$/s);
      const error = /** @type {Error & {responseCode: number}} */ (
        new Error(match ? match[2] : String(responseText))
      );
      error.responseCode = match ? Number(match[1]) : 550;
      return error;
    },
    /**
     * @param {Record<string, unknown>} entry
     */
    loggelf(entry) {
      logs.push(entry);
    },
  };

  await pluginModule.init(
    /** @type {import('@zone-eu/types').ZoneMtaPluginTools} */ (
      /** @type {unknown} */ (app)
    ),
    () => {},
  );
  assert(dataHook);
  return {
    logs,
    run: () =>
      /** @type {Function} */ (dataHook)(context.envelope, context.session),
  };
};

/**
 * @param {string | Record<string, unknown>} response
 * @param {{deferResponse?: boolean}} [options]
 * @returns {Promise<{port: number, request: Promise<Buffer>, respond(): Promise<void>}>}
 */
const createRspamdServer = async (response, options = {}) => {
  /** @type {(value: Buffer) => void} */
  let resolveRequest;
  const request = new Promise((resolve) => {
    resolveRequest = resolve;
  });
  /** @type {(() => void) | undefined} */
  let sendResponse;
  /** @type {(() => void) | undefined} */
  let resolveResponseReady;
  const responseReady = new Promise((resolve) => {
    resolveResponseReady = () => resolve(undefined);
  });
  const body =
    typeof response === "string" ? response : JSON.stringify(response);
  const server = trackServer(
    net.createServer((socket) => {
      let input = Buffer.alloc(0);
      let replied = false;
      socket.on("data", (chunk) => {
        input = Buffer.concat([
          input,
          Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
        ]);
        const separator = input.indexOf("\r\n\r\n");
        if (separator < 0) {
          return;
        }
        const headerText = input.subarray(0, separator).toString("utf8");
        const contentLength = Number(
          headerText.match(/^Content-Length:\s*(\d+)$/im)?.[1] || 0,
        );
        if (replied || input.length < separator + 4 + contentLength) {
          return;
        }
        replied = true;
        resolveRequest(input);
        sendResponse = () =>
          socket.end(
            `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
          );
        resolveResponseReady?.();
        if (!options.deferResponse) {
          sendResponse?.();
        }
      });
    }),
  );
  await new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve(undefined)),
  );
  const address = server.address();
  assert(address && typeof address === "object");
  return {
    port: address.port,
    request,
    async respond() {
      await responseReady;
      sendResponse?.();
    },
  };
};

describe("kirin-plugin-rspamd", () => {
  it("exports a ZoneMTA plugin", () => {
    assert.equal(pluginModule.title, "rspamd");
    assert.equal(typeof pluginModule.init, "function");
  });

  it("sends Kirin metadata and applies accepted Rspamd changes", async () => {
    const server = await createRspamdServer({
      action: "add header",
      score: 2.4,
      required_score: 5,
      symbols: {
        TEST_SYMBOL: {
          name: "TEST_SYMBOL",
          score: 2.4,
        },
      },
      "dkim-signature": "v=1; a=rsa-sha256",
      milter: {
        remove_headers: {
          "X-Remove": 0,
        },
        add_headers: {
          "X-New": [{ value: "first" }, "second"],
        },
      },
    });
    const context = createContext();
    const plugin = await initialize(context, {
      host: "127.0.0.1",
      port: server.port,
      header: {
        bar: "X-Rspamd-Bar",
        report: "X-Rspamd-Report",
        score: "X-Rspamd-Score",
      },
    });

    await plugin.run();
    const request = (await server.request).toString("utf8");

    assert.match(request, /^POST \/checkv2 HTTP\/1\.1\r\n/);
    assert.match(request, /\r\nIP: 192\.0\.2\.10\r\n/);
    assert.match(request, /\r\nHostname: client\.example\r\n/);
    assert.match(request, /\r\nHelo: münchen\.example\r\n/);
    assert.match(request, /\r\nFrom: séndér@bücher\.example\r\n/);
    assert.match(
      request,
      /\r\nRcpt: one@example\.com\r\nRcpt: twö@example\.com\r\n/,
    );
    assert.match(request, /\r\nQueue-Id: queue-id\r\n/);
    assert.match(request, /\r\nTLS-Cipher: TLS_AES_256_GCM_SHA384\r\n/);
    assert.match(request, /\r\nTLS-Version: TLSv1\.3\r\n/);

    assert.equal(context.headers.get("X-Remove"), "");
    assert.deepEqual(context.headers.get_all("X-New"), ["first", "second"]);
    assert.equal(context.headers.get("DKIM-Signature"), "v=1; a=rsa-sha256");
    assert.equal(context.headers.get("X-Rspamd-Bar"), "++");
    assert.equal(context.headers.get("X-Rspamd-Report"), "TEST_SYMBOL(2.4)");
    assert.equal(context.headers.get("X-Rspamd-Score"), "2.4");
    assert.equal(context.results.get("rspamd").score, 2.4);
    assert.equal(context.results.get("rspamd").symbols.TEST_SYMBOL.score, 2.4);
    assert.equal(plugin.logs[0]._RSPAMD_TEST_SYMBOL, 2.4);
  });

  it("sends SPF and prefers forward-confirmed reverse DNS results", async () => {
    const server = await createRspamdServer({
      action: "no action",
      score: 0,
      symbols: {},
    });
    const context = createContext();
    context.results.set("spf", { result: "PASS" });
    context.results.set("fcrdns", { fcrdns: ["verified.example"] });
    const plugin = await initialize(context, {
      host: "127.0.0.1",
      port: server.port,
    });

    await plugin.run();
    const request = (await server.request).toString("utf8");

    assert.match(request, /\r\nSPF: pass\r\n/);
    assert.match(request, /\r\nHostname: verified\.example\r\n/);
    assert.doesNotMatch(request, /\r\nHostname: client\.example\r\n/);
  });

  it("rewrites the subject requested by Rspamd", async () => {
    const server = await createRspamdServer({
      action: "rewrite subject",
      score: 6,
      subject: "[JUNK] %s",
      symbols: {},
    });
    const context = createContext();
    const plugin = await initialize(context, {
      host: "127.0.0.1",
      port: server.port,
    });

    await plugin.run();
    assert.equal(context.headers.get("Subject"), "[JUNK] Original subject");
  });

  it("uses Rspamd SMTP messages for hard and soft rejects", async () => {
    const hardServer = await createRspamdServer({
      action: "reject",
      score: 15,
      symbols: {},
      messages: {
        smtp_message: "Blocked by Rspamd",
      },
    });
    const hardContext = createContext();
    const hardPlugin = await initialize(hardContext, {
      host: "127.0.0.1",
      port: hardServer.port,
    });

    await assert.rejects(hardPlugin.run(), (error) =>
      isResponseError(error, 550, "Blocked by Rspamd"),
    );

    const softServer = await createRspamdServer({
      action: "soft reject",
      score: 10,
      symbols: {},
      messages: {
        smtp_message: "Try again later",
      },
    });
    const softContext = createContext();
    const softPlugin = await initialize(softContext, {
      host: "127.0.0.1",
      port: softServer.port,
    });

    await assert.rejects(softPlugin.run(), (error) =>
      isResponseError(error, 451, "4.7.1 Try again later"),
    );
  });

  it("skips authenticated and private clients by default", async () => {
    const authenticated = createContext({
      envelope: {
        user: "user@example.com",
      },
    });
    const authenticatedPlugin = await initialize(authenticated, {
      host: "invalid.example",
    });
    await authenticatedPlugin.run();
    assert.deepEqual(authenticated.results.get("rspamd"), { skip: "authed" });

    const privateClient = createContext();
    privateClient.connection.remote.is_private = true;
    const privatePlugin = await initialize(privateClient, {
      host: "invalid.example",
    });
    await privatePlugin.run();
    assert.deepEqual(privateClient.results.get("rspamd"), {
      skip: "private_ip",
    });
  });

  it("fails open on invalid replies unless defer.error is enabled", async () => {
    const openServer = await createRspamdServer("not json");
    const openContext = createContext();
    const openPlugin = await initialize(openContext, {
      host: "127.0.0.1",
      port: openServer.port,
    });
    await openPlugin.run();
    assert.match(openContext.results.get("rspamd").err, /^parse failure:/);

    const closedServer = await createRspamdServer("not json");
    const closedContext = createContext();
    const closedPlugin = await initialize(closedContext, {
      host: "127.0.0.1",
      port: closedServer.port,
      defer: {
        error: true,
      },
    });
    await assert.rejects(closedPlugin.run(), (error) =>
      isResponseError(error, 450, "Rspamd scan error"),
    );
  });

  it("can defer timed-out scans", async () => {
    const server = trackServer(
      net.createServer({ allowHalfOpen: true }, (socket) => {
        socket.on("data", () => {});
      }),
    );
    await new Promise((resolve) =>
      server.listen(0, "127.0.0.1", () => resolve(undefined)),
    );
    const address = server.address();
    assert(address && typeof address === "object");
    const context = createContext();
    const plugin = await initialize(context, {
      host: "127.0.0.1",
      port: address.port,
      timeout: 0.03,
      defer: {
        timeout: true,
      },
    });

    await assert.rejects(plugin.run(), (error) =>
      isResponseError(error, 450, "Rspamd scan timeout"),
    );
    assert.deepEqual(context.results.get("rspamd"), { err: "socket timeout" });
  });

  it("enforces an absolute timeout while Rspamd is sending data", async () => {
    let chunksSent = 0;
    const server = trackServer(
      net.createServer((socket) => {
        /** @type {NodeJS.Timeout | undefined} */
        let interval;
        /** @type {NodeJS.Timeout | undefined} */
        let safetyTimer;
        socket.on("data", () => {
          socket.write(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
          );
          interval = setInterval(() => {
            chunksSent++;
            socket.write("1\r\n{\r\n");
          }, 5);
          interval.unref?.();
          safetyTimer = setTimeout(() => socket.end("0\r\n\r\n"), 300);
          safetyTimer.unref?.();
        });
        socket.once("close", () => {
          if (interval) {
            clearInterval(interval);
          }
          if (safetyTimer) {
            clearTimeout(safetyTimer);
          }
        });
      }),
    );
    await new Promise((resolve) =>
      server.listen(0, "127.0.0.1", () => resolve(undefined)),
    );
    const address = server.address();
    assert(address && typeof address === "object");
    const context = createContext();
    const plugin = await initialize(context, {
      host: "127.0.0.1",
      port: address.port,
      timeout: 0.1,
    });

    await plugin.run();

    assert(chunksSent > 1);
    assert.deepEqual(context.results.get("rspamd"), { err: "socket timeout" });
  });

  it("does not apply a response to a stale transaction", async () => {
    const server = await createRspamdServer(
      {
        action: "rewrite subject",
        score: 6,
        subject: "[STALE] %s",
        symbols: {},
      },
      { deferResponse: true },
    );
    const context = createContext();
    const plugin = await initialize(context, {
      host: "127.0.0.1",
      port: server.port,
    });

    const runPromise = plugin.run();
    await server.request;
    context.connection.transaction = false;
    await server.respond();
    await runPromise;

    assert.equal(context.headers.get("Subject"), "Original subject");
    assert.equal(context.results.has("rspamd"), false);
    assert.deepEqual(plugin.logs, []);
  });
});
