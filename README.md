# wp-plugin-audit

WordPress powers a large share of the web and most of its vulnerabilities live in plugins. wp-plugin-audit reads a plugin's PHP and flags the classic mistakes (SQL injection, XSS, object injection, missing nonce and capability checks, unauthenticated AJAX that writes, path traversal), with a fix for each.

**Live demo:** https://jvch0512.github.io/wp-plugin-audit/ (a report on the synthetic plugins in `examples/`)

PHP 8.1+, no dependencies, offline.

## Use

```bash
php bin/wp-plugin-audit path/to/plugin
php bin/wp-plugin-audit path/to/plugin --json
php bin/wp-plugin-audit path/to/plugin --html > report.html
php bin/wp-plugin-audit path/to/plugin --fail-on high     # exit 1 in CI
```

See [examples](examples) (one intentionally vulnerable plugin, one clean) and [docs/sample-output.txt](docs/sample-output.txt).

## Rules

| Rule | Severity | Catches |
|---|---|---|
| WP001 | high | SQL built from request data without `$wpdb->prepare()`, including values that flow through a variable |
| WP002 | high | request data echoed without escaping |
| WP003 | critical | `eval`, `assert`, shell execution functions |
| WP004 | high | `unserialize()` on request data without `allowed_classes` |
| WP005 | high | AJAX handlers with no capability or nonce check |
| WP006 | high | `wp_ajax_nopriv_*` handlers that write data |
| WP007 | medium | include or file operations from request data |
| WP008 | medium | REST routes with `__return_true` permission callback |
| WP009 | medium | uploads moved without type validation |
| WP010 | low | files without an `ABSPATH` guard |

## Limits

- Pattern matching with light taint tracking, not a full PHP data-flow engine. It will miss flows through functions and objects and can flag code that is guarded elsewhere. Treat findings as review leads.
- It does not know WordPress core, other plugins or server configuration.
- Use it as a first pass before a manual review or a dynamic test, not as a certificate.

## Where it fits

Agencies and hosting providers vetting plugins, procurement and M&A due diligence on WordPress estates, and a fixed-price "plugin security review" service.

## Tests

```bash
php tests/run.php   # 21 checks
```

MIT.
