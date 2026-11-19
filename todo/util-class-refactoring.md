# `UTIL.php`: structure review and refactoring

**Status:** review done (2026-11-18), nothing implemented
**Code reference:** `alpha` `93a0187`, `utils/lib/UTIL.php` (2828 lines, 41 methods, 56 public properties)
**Related:** `lib/misc-classes/PH.php` (`$supportedUTILTypes`, dispatcher), `utils/lib/UTIL_GET_ACTION_FILTER.php`,
[shell-autocompletion.md](shell-autocompletion.md), [api-rest.md](api-rest.md),
[ui-config-in-browser.md](ui-config-in-browser.md)

## Result of the review

`UTIL.php` works; no functional bug was found, and there are no undeclared (dynamic) properties (PHP 8.2+). The open
points are structure and maintainability. Ordered by benefit:

### 1. Type chains are maintained twice

`supportedActions()` and `extracting_actions()` each hold an `elseif( $this->utilType == '…' )` chain over the same 35
types (176 comparisons on `utilType` in the whole file). Both chains are consistent today, but every new type has to be
added in several places (plus `PH::$supportedUTILTypes` and the dispatcher in `PH.php`).

* [ ] one table `type => CallContext class` (static array or small registry class), used by `supportedActions()`,
  `extracting_actions()`, `listactions()`, `listfilters()`
* [ ] `extracting_actions()`: `new $class( … )` from the table instead of the chain
* [ ] check whether the dispatcher in `PH.php` (`type => util class`) can use the same registry

### 2. Everything is loaded on every call

About 60 `require_once` at the top of the file (migration parser, phpseclib, GCP, Git, …). Every call loads 433 files,
also `type=address`. Measured: about 66 ms on top of 69 ms for the framework, 29 MB peak – no performance problem, but
needless coupling: a parse error in a rarely used class breaks every call.

* [ ] load a util class only when its type is called (in the dispatcher), or an autoloader for `utils/lib` / `utils/common`
* [ ] phpseclib / migration parser / GCP only for the types that need them (see also
  [ssh-connector-phpseclib.md](ssh-connector-phpseclib.md))

### 3. Very long methods

| Method | Lines |
|---|---|
| `location_filter_object()` | 256 |
| `inputValidation()` | 199 |
| `help()` | 180 |
| `location_filter()` | 177 |
| `extracting_actions()` | 150 |
| `save_our_work()` | 112 |
| `location_filter_scm_object()` | 105 |

* [ ] `location_filter()`, `location_filter_object()`, `location_filter_scm_object()` overlap – merge the common part
  (location list handling `shared` / `any` / `all`, `,` and `:` syntax) into one helper
* [ ] `inputValidation()`: split per input kind (file, `api://`, SCM / fawkes / buckbeak)
* [ ] `help()`: text per argument from the `supportedArguments` data instead of code

### 4. Error handling with `exit()`

28 `exit()` and 13 `derr()` calls directly in the class. This makes the class hard to test and is a problem for API / UI
use. Exception support exists (`useException()`, `enableExceptionSupport()`) but is not used throughout.

* [ ] replace `exit()` in the class by exceptions; exit only in the CLI entry point
* [ ] tests of `UTIL` methods without a sub-process (today every test calls `pan-os-php.php` via `exec`)

### 5. Small items

* [ ] 36 lines of commented-out code
* [ ] constructor: `$tmp_ph = new PH( $argv, $argc )` is created only for its side effects – make this an explicit
  static call
* [ ] 56 public properties: reduce to what the util classes really use from outside

### 6. Added 2026-11-18: `UTIL::$sharedConfig`

For the config-viewer prototype ([ui-config-in-browser.md](ui-config-in-browser.md)) `UTIL` can reuse a configuration
that is already loaded in the same process (`inputValidation()`, `determineConfigType()`, `load_config()`,
`__destruct()`; `null` = unchanged behaviour).

* [ ] review the hook; with the type table (item 1) and exceptions instead of `exit()` (item 4) a clean
  "run on a loaded configuration" entry point can replace it – the viewer then needs no forked trial run
* [ ] `PH::$JSON_OUT` / `$JSON_TMP` / `$JSON_OUTlog` are static and must be reset by the caller between two runs in
  one process (the worker does) – belongs into the entry point

## Order

1 (type table) first – small, removes the double maintenance and is the base for per-type data in
`util_action_filter.json` ([shell-autocompletion.md](shell-autocompletion.md)). Then 2, 4, 3.

## Rule

No output change: after every step the comparison alpha ↔ beta and `tests/test_actions.php`, `tests/test_filters.php`,
`tests/test_utilscripts.php` must give the same result as before.
