# Rspamd plugin for Kirin

`kirin-plugin-rspamd` scans incoming messages with Rspamd through
Kirin's `smtp:data` hook. Rspamd request metadata comes directly from the
Kirin envelope passed to the hook:

- Rspamd `/checkv2` requests over TCP or a Unix socket
- sender, recipients, queue ID, origin, hostname, HELO, authenticated user,
  and TLS metadata from the Kirin envelope
- authenticated, local-IP, and private-IP skip rules
- hard reject and soft reject actions
- configurable fail-open or temporary-failure behavior
- subject rewriting, DKIM signatures, and milter header changes
- `X-Rspamd-Bar`, `X-Rspamd-Report`, and `X-Rspamd-Score` headers
- results stored in Kirin's shared per-message results map under `rspamd`

Copy [`kirin-plugin-rspamd.toml`](kirin-plugin-rspamd.toml) into the Kirin
plugin configuration directory.

The plugin defaults to `localhost:11333`, a 29-second timeout, and fail-open
behavior for Rspamd connection errors and timeouts. Set `defer.error` or
`defer.timeout` to `true` to return a temporary SMTP failure instead. Keep
Kirin's `smtp.dataHookTimeout` greater than this plugin's `timeout`.

`addHeaders` accepts:

- `"always"` to add the configured Rspamd headers to every scanned message
- `"never"` to disable those generated headers
- `"sometimes"` to add them only for Rspamd's `add header` action

Rspamd-provided milter header changes remain controlled separately by
`milterHeaders.enabled`.

Configuration uses the camelCase keys shown in
[`kirin-plugin-rspamd.toml`](kirin-plugin-rspamd.toml). The plugin merges
these values with its defaults.

## License

kirin-plugin-rspamd is licensed under the [European Union Public License 1.2](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12) or later.

> kirin-plugin-rspamd is part of the Zone Mail Suite (ZMS), a suite of programs and modules for an efficient, fast, and modern email server.

Copyright (c) 2026 Zone Media OÜ.
