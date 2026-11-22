# ssh-connector – switch to a current phpseclib without local changes

**Status:** planned (2026-11-17)
**Code reference:** `alpha` `72fbd62`

Goal: `type=ssh-connector` (and every other SSH / phpseclib user) runs on a current phpseclib release. The library is
used **unchanged** – no manual edits inside the pan-os-php repo.

## Current state

The copy in `phpseclib/` (repo root) is **phpseclib 1.0.19 (2020)** with local edits (see `phpseclib/version`).
Diff against upstream tag `1.0.19`:

| File | Local change | Kind |
|---|---|---|
| `Net/SSH2.php` | `include_once 'Math/…'` / `'Crypt/…'` → `'phpseclib/Math/…'` / `'phpseclib/Crypt/…'` | include path |
| `Net/SSH2.php` | `_keyboard_interactive_process()`: on `NET_SSH2_MSG_USERAUTH_SUCCESS` also `$this->bitmap \|= NET_SSH2_MASK_LOGIN;` ("added swaschkut 20201015") | **functional** – login via keyboard-interactive (PAN-OS) |
| `File/ANSI.php` | `htmlspecialchars()` → `PH::panosphp_htmlspecialchars()` | functional, dependency on pan-os-php |
| `Crypt/Hash.php`, `Crypt/Rijndael.php` | added `public $name;` / `public $key_size;` | PHP 8.2+ dynamic property deprecation |
| `Net/SFTP.php`, `Net/SFTP/Stream.php`, `Net/SSH1.php`, `Net/SSH2.php` | `echo` → `print` | style (pan-os-php rule "no echo") |
| `Crypt/*`, `Math/BigInteger.php`, `System/SSH/Agent.php` | `echo` → `print` in doc comments only | comments |

Notes:
- upstream `_keyboard_interactive_process()` still returns without setting the login bit in 1.0.31 and 3.0.58 –
  test with PAN-OS whether the edit is still needed with 3.x; if yes: report upstream, not patch locally
- the dynamic property and `echo` edits are not needed with a current release

### Who uses phpseclib

| Code | Uses |
|---|---|
| `utils/lib/RUNSSH.php` | `Net_SSH2` – connect, login, `read()` / `write()` command loop |
| `utils/lib/SSH_CONNECTOR__.php` (`type=ssh-connector`) | `RUNSSH`; `Crypt_RSA::loadKey()` for login with private key |
| `utils/lib/GARPSEND.php` (`type=gratuitous-arp`) | `RUNSSH` |
| `utils/lib/UTIL.php` | `require_once` `Net/SSH2.php`, `Crypt/RSA.php` for all types |
| `lib/pan_php_framework.php` → `lib/helper-classes/cidr.php` | `Math_BigInteger` in `inet_ptoi()` / `inet_itop()` – only fallback when `bcadd()` is missing; `ext-bcmath` is required in `composer.json` and `install.sh` |
| `utils/develop/cyclePanorama_ssh.php` | ssh to all firewalls of a Panorama (see [TODO-develop-scripts.md](../TODO-develop-scripts.md)) |
| `docker/Dockerfile*` | `COPY phpseclib …` |

## Target

phpseclib releases today (tags): 1.0.31, 2.0.56, **3.0.58**, **4.0.3**.

| | 3.0.x | 4.0.x |
|---|---|---|
| PHP | >= 5.6.1 | >= 8.1 |
| namespace | `phpseclib3\` | `phpseclib4\` |
| dependencies | `paragonie/constant_time_encoding`, `paragonie/random_compat` | `paragonie/constant_time_encoding`, `symfony/polyfill-php82` |

pan-os-php requires PHP >= 8.5 (`composer.json`), so both fit. 3.0 is the long-running line; 4.0 is new.

API changes for pan-os-php (1.0 → 3.x / 4.x):
- `new Net_SSH2($ip, $port, $timeout)` → `new \phpseclib3\Net\SSH2(...)`
- `new Crypt_RSA(); ->loadKey($key)` → `\phpseclib3\Crypt\PublicKeyLoader::load($key [, $passphrase])`
- `read()` / `write()` / `setTimeout()` stay; check prompt / pager handling in `RUNSSH` (`set cli pager off`,
  `configure`, `$setcommandMaxLine`)
- `Math_BigInteger` fallback in `cidr.php`: remove (bcmath is required) instead of porting

## Plan

1. decide the delivery (open decision 1)
2. add phpseclib as dependency (`composer.json` `require`), no copy with edits
3. switch `RUNSSH.php`, `SSH_CONNECTOR__.php` (private key), `UTIL.php` / `GARPSEND.php` includes to the
   namespaced classes / autoloader
4. `cidr.php`: drop the `Math_BigInteger` branch, `lib/pan_php_framework.php`: drop the `require_once`
5. `File/ANSI.php` (with the `PH::panosphp_htmlspecialchars` edit) is not used by pan-os-php – nothing to port
6. test against PAN-OS firewall and Panorama: password login (keyboard-interactive), private key login,
   `type=ssh-connector` with op and configure commands, `type=gratuitous-arp`
7. remove `phpseclib/` folder, update `docker/Dockerfile*` (`COPY phpseclib`), install scripts, `README` /
   `READMEdocker.md`

## Open decisions

1. Delivery: `composer install` (vendor not in git; install scripts, Docker and `update_pan-os-php.sh` have to run it)
   **or** vendor the **unchanged** release into the repo (e.g. `vendor/` committed, only updated by composer) – the
   second keeps "git clone and run" working.
2. phpseclib 3.0 or 4.0.
3. If the keyboard-interactive fix is still needed with 3.x / 4.x: workaround in `RUNSSH` (e.g. check
   `isAuthenticated()` / login method) or upstream issue / PR.
