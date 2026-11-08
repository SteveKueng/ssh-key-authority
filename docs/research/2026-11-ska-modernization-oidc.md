# SKA modernization: PHP 8, OIDC (Authentik), Docker hardening

Research date: 2026-11-08. Scope: fork `SteveKueng/ssh-key-authority` (HEAD `3a56782`, last pushed 2025-08-17).

Decisions already taken (from the maintainer), and assumed throughout:

- IdP: **Authentik** (self-hosted).
- Deprovisioning: **periodic sync from the Authentik API** (cron, same model as `scripts/ldap_update.php`).
- LDAP stays as an **optional** auth backend; the backend is selectable (`ldap` | `oidc`).
- Deployment: **Docker only**.
- Issues are filed in the fork `SteveKueng/ssh-key-authority`.

Sources are primary (official docs, GitHub repos/API, release notes, RFCs). Repo findings are cited as `file:line` at HEAD `3a56782`.

---

## Summary: top 10 findings

1. **The fork is missing an upstream security fix.** Upstream commit `aa71765` (2025-09-06, PR #78) fixes a privilege escalation: any authenticated user could POST to `/groups/{group}/access_rules/{id}` and rewrite the `authorized_keys` options for every member of that group ([advisory](https://github.com/operasoftware/ssh-key-authority/wiki/SKA-security-advisory:-insufficient-validation-of-group-access-rule-edit-privileges)). It is not in this fork's history (`git log` has no such commit). Two later upstream fixes are missing too: `fda9081` and `d5b1fb7` (2026-07-09) ([commits](https://api.github.com/repos/operasoftware/ssh-key-authority/commits?per_page=8)). **Merge upstream first.**
2. **Upstream is alive but barely maintained.** It is not archived. It gets a few commits a year, has no releases and has 22 open issues/PRs ([repo API](https://api.github.com/repos/operasoftware/ssh-key-authority)). It has no PHP 8 declaration, no OIDC and no Docker. The two forks worth tracking are `leitwerk-de/leitwerk-key-authority` (LDAP groups, key supervision, composer) and its descendant `Msprg/ssh-key-authority` (PHP 8.2+, Debian 12 Docker image with nginx/php-fpm/supervisor/tini and a HEALTHCHECK). **Neither has OIDC.**
3. **PHP 7.4 has been EOL since 2022-11-28** ([php.net/eol](https://www.php.net/eol.php)). PHP 8.2 goes EOL on 2026-12-31. **Target PHP 8.4** (security support to 2028-12-31) or 8.5 (to 2029-12-31) ([supported versions](https://www.php.net/supported-versions.php)). `php:8.4-apache` is built on Debian **trixie** ([official-images](https://raw.githubusercontent.com/docker-library/official-images/master/library/php)).
4. **The biggest PHP 8 risk is `core.php:22`/`core.php:48-50`.** The global error handler turns *every* notice, warning and E_DEPRECATED into an `ErrorException`. `set_error_handler` runs regardless of `error_reporting` ([manual](https://www.php.net/manual/en/function.set-error-handler.php)), so each PHP 8.1+ deprecation (null passed to an internal function, and so on) becomes an HTTP 500 or a crashed sync. Fix: skip `E_DEPRECATED`/`E_USER_DEPRECATED` in the handler and log them instead.
5. **Concrete PHP 8 breakers in the code** (details in section 2):
   - `ldap.php:55`: `ldap_sort`, removed in 8.0. It is dead code today because no caller passes `$sort`, but delete it.
   - `model/user.php:323,394`: `reset()` on a possible `false`, which is a TypeError in 8.x.
   - `core.php:69-72`: catches `ErrorException`, but since 8.1 mysqli throws `mysqli_sql_exception`, so `DBConnectionFailedException` is never raised ([8.1 migration](https://www.php.net/manual/en/migration81.incompatible.php)).
   - `scripts/ldap_update.php:59-70`: `$rcpt` is undefined when `user_superior` is not set.
6. **libssh2 no longer needs a source build.** Trixie ships `libssh2-1t64` **1.11.1** ([packages.debian.org](https://packages.debian.org/search?keywords=libssh2-1&searchon=names&suite=all&section=all)), the latest upstream release (2024-10-16), with RSA-SHA2 and Terrapin strict-KEX ([libssh2 changes](https://libssh2.org/changes.html)). PECL `ssh2` **1.5.0** (2026-04-04) requires PHP ≥ 8.0 and adds `ssh2_set_timeout`/keepalive ([pecl](https://pecl.php.net/package/ssh2), [changelog](https://pecl.php.net/package-changelog.php?package=ssh2)). Drop the unpinned `git clone libssh2` HEAD build.
7. **OIDC: use Apache `mod_auth_openidc`.** It is packaged in trixie (`2.4.17-1+deb13u1`) and installs straight into `php:*-apache`, whose Apache is the Debian `apache2` package ([php Dockerfile](https://raw.githubusercontent.com/docker-library/php/master/8.4/trixie/apache/Dockerfile), [packages](https://packages.debian.org/search?keywords=libapache2-mod-auth-openidc&searchon=names&suite=all&section=all)). It sets `REMOTE_USER` from a chosen claim (`OIDCRemoteUserClaim`) ([auth_openidc.conf](https://raw.githubusercontent.com/OpenIDC/mod_auth_openidc/master/auth_openidc.conf)). The app change is roughly one line: read `$_SERVER['REMOTE_USER']`, which both LDAP Basic auth and OIDC set, instead of `PHP_AUTH_USER`, which PHP fills only for HTTP Basic/Digest ([PHP manual](https://www.php.net/manual/en/reserved.variables.server.php)). Note that upstream mod_auth_openidc 2.4.20.4 (2026-11-01) fixed several GHSAs. Watch for the Debian DSA, or use the upstream `.deb` ([releases](https://api.github.com/repos/OpenIDC/mod_auth_openidc/releases?per_page=3)).
8. **LDAP is used for directory lookups as well as login.** `UserDirectory::get_user_by_uid()` (`model/userdirectory.php:85-100`) queries LDAP to create users that *admins* type in: adding a group member, a server admin or a reassignment (`views/group.php:57,92`, `views/groups.php:25`, `views/servers.php:30`, `views/serveraccount.php:51`, `views/user.php:32,51`). Login only creates *new* users. Existing users are refreshed only by the `ldap_update.php` cron. So the work is a **directory backend abstraction** (LDAP | Authentik API) used by lookup, the admin refresh and the cron. That is more important than consuming login claims.
9. **The Authentik API covers deprovisioning.**
   - `GET /api/v3/core/users/` filters on `is_active`, `type`, `username`, `groups_by_name`, `include_groups` and paginates.
   - User objects carry `username`, `name`, `email`, `is_active`, `groups_obj`, `type` and `uuid`.
   - Auth is `Authorization: Bearer <token>`. A service account plus token comes from `POST /api/v3/core/users/service_account/`; tokens expire by default after 360 days.

   Sources: [schema.yml](https://api.goauthentik.io/schema.yml), [API auth](https://api.goauthentik.io/authentication/). Authentik ≥ 2025.10 also sends **OIDC back-channel logout** when an admin deactivates a user or deletes a session ([single logout](https://docs.goauthentik.io/add-secure-apps/providers/single-logout/)). mod_auth_openidc handles that at `<redirect_uri>?logout=backchannel` ([wiki FAQ 9](https://github.com/OpenIDC/mod_auth_openidc/wiki#9-how-do-i-logout-users)), which gives web-session revocation within seconds.
10. **The Docker/CI setup has concrete defects:**
    - The image `git clone`s `master` at build time, so the image doesn't match the commit being built.
    - CI pushes `:latest` on every `pull_request` too.
    - `--with-libdir=lib/x86_64-linux-gnu` blocks arm64.
    - `entrypoint.sh:14-15` misspells the user and the glob (`key-sync` vs `keys-sync`), so the private-key `chmod 600` never matches.
    - `sleep 5` stands in for a DB wait, there is no HEALTHCHECK, and build tools are left in the runtime image.
    - `PassEnv LDAP_BIND_PW` exposes the bind password to every PHP request's environment.

---

## 1. Upstream status and forks

### Upstream `operasoftware/ssh-key-authority`

| Item | Value | Source |
|---|---|---|
| Archived | no | [repo API](https://api.github.com/repos/operasoftware/ssh-key-authority) |
| Last push | 2026-07-09 | same |
| Stars / forks | 486 / 81 | same |
| Open issues + PRs | 22 (19 issues, 3 PRs) | same; [repo page](https://github.com/operasoftware/ssh-key-authority) |
| Releases | none | [repo page](https://github.com/operasoftware/ssh-key-authority) |
| README requirements | still "PHP 5.6 or higher", LDAP required | [repo page](https://github.com/operasoftware/ssh-key-authority) |

Latest upstream commits ([commits API](https://api.github.com/repos/operasoftware/ssh-key-authority/commits?per_page=8)):

| Commit | Date | Change | In this fork? |
|---|---|---|---|
| `d5b1fb7` | 2026-07-09 | Fix force_disable logic (#82); touches `model/user.php`, `views/user.php` | **no** |
| `fda9081` | 2026-07-09 | Hide user settings tab for non-admins (#81); touches `templates/user.php` | **no** |
| `2c197c9` | 2025-09-15 | README link to new advisory | **no** |
| `aa71765` | 2025-09-06 | **Security:** restrict group access-rule option edits to admins (+8 lines in `views/access_options.php`) | **no** |
| `d8263bf`, `b6e3507`, `9b8de6f`, `5de0e9c` | 2023-12-22 | jQuery 3.7.1, preg_split fix, missing global, null-string handling (`hesc()` uses `?? ''`) | yes (`5de0e9c`, `b6e3507` present) |

**Security advisories** ([wiki](https://github.com/operasoftware/ssh-key-authority/wiki)):

- 2017-11-08, "SSH port redirection attack". This is old and the fork is based on later code.
- 2025-09-15, "Insufficient validation of group access rule edit privileges". The endpoint `/groups/{group}/access_rules/{id}` accepted POSTs from any authenticated user, who could overwrite `authorized_keys` options for all group members. It is fixed by `aa71765` ([advisory](https://github.com/operasoftware/ssh-key-authority/wiki/SKA-security-advisory:-insufficient-validation-of-group-access-rule-edit-privileges)). **This fork is vulnerable** until it merges upstream. After merging, check the group access-rule options in the DB for unexpected changes. That check is our recommendation, not part of the advisory.

Open upstream issues relevant here ([issues API](https://api.github.com/repos/operasoftware/ssh-key-authority/issues?state=open)):

- #62 "openssh 8.8 not working anymore": `ssh-rsa`/SHA-1 is disabled in OpenSSH 8.8, and libssh2 1.11 fixes it. This is very likely why the fork builds libssh2 from source.
- #58 / #2 "Logout button".
- #29 "Docker".
- #25 / #21 "Is LDAP required? / basic auth alternative".

### Notable forks

There are 81 forks. Most are zero-change clones; their `pushed_at` equals an upstream push ([forks API](https://api.github.com/repos/operasoftware/ssh-key-authority/forks?sort=stargazers&per_page=15)). The ones with real divergence:

| Fork | Last push | Divergence | What changed | Source |
|---|---|---|---|---|
| `leitwerk-de/leitwerk-key-authority` | 2026-10-26 | 180 ahead / 24 behind | LDAP group mapping by GUID and nested groups; key creation dates; keeps deleted keys; external-key supervision (scans target servers); status file on targets; composer. Latest commits (2024-07) say "Changes for PHP8.3 update" and "deprecated null since PHP8.1". LDAP only, no Docker. | [compare](https://api.github.com/repos/operasoftware/ssh-key-authority/compare/master...leitwerk-de:leitwerk-key-authority:master), [repo](https://github.com/leitwerk-de/leitwerk-key-authority) |
| `Msprg/ssh-key-authority` | 2026-10-07 | 290 ahead / 66 behind; contains the leitwerk work | **PHP 8.2+** (2026-02-09, "Update dependencies and base PHP requirement to 8.2"); a **Docker image** on `debian:12-slim` + nginx + php-fpm + Debian `php-ssh2` + cron + supervisor + **tini**, with a `HEALTHCHECK`, `COPY .` instead of git clone, a `SKA_VERSION` build arg and `docker-compose.yml.example`; LDAPS config; PHPStan. Still LDAP only, and still has `@ldap_sort` (dead code). | [Dockerfile](https://github.com/Msprg/ssh-key-authority/blob/master/Dockerfile), [repo](https://github.com/Msprg/ssh-key-authority) |
| `mettke/ssh-key-authority` | 2021-06-30 | separate lineage | env-var handling, systemd ordering after MariaDB | [repo](https://github.com/mettke/ssh-key-authority) |

No fork offers OIDC or SAML. The Msprg Dockerfile is a useful reference for packaging, but its base (Debian 12 PHP 8.2) reaches php.net EOL on 2026-12-31.

**Recommendation:** merge upstream `master` (security fix). Don't rebase onto leitwerk/Msprg: they are hundreds of commits apart with different features. Cherry-pick ideas from them (Docker layout, PHP 8 null fixes) instead.

---

## 2. PHP upgrade path

### Version facts

| Component | Current in fork | Latest / recommended | Source |
|---|---|---|---|
| PHP | 7.4 (EOL 2022-11-28, last 7.4.33) | **8.4** (active to 2026-12-31, security to 2028-12-31) or 8.5 (security to 2029-12-31). 8.2 EOL 2026-12-31, 8.3 security-only to 2027-12-31 | [eol](https://www.php.net/eol.php), [supported](https://www.php.net/supported-versions.php) |
| Docker base | `php:7.4-apache` (Debian bullseye) | `php:8.4-apache-trixie` (= `8.4-apache`, currently 8.4.27); bookworm variants also exist; bare `apache` = 8.5 | [official-images](https://raw.githubusercontent.com/docker-library/official-images/master/library/php), [versions.json](https://github.com/docker-library/php/blob/master/versions.json) |
| pecl ssh2 | 1.3.1 (beta, 2021) | **1.5.0** stable (2026-04-04), PHP ≥ 8.0; fixes an ECDSA pubkey auth crash and a segfault on disconnect with open SFTP streams; adds `ssh2_set_timeout`, `ssh2_keepalive_*`; PIE-compatible (PECL is deprecated in favour of PIE) | [pecl](https://pecl.php.net/package/ssh2), [changelog](https://pecl.php.net/package-changelog.php?package=ssh2) |
| libssh2 | git HEAD (unpinned) | **1.11.1** (2024-10-16). Trixie ships `libssh2-1t64 1.11.1-1+deb13u2`; bookworm only 1.10.0 | [libssh2.org](https://libssh2.org/), [changes](https://libssh2.org/changes.html), [Debian](https://packages.debian.org/search?keywords=libssh2-1&searchon=names&suite=all&section=all) |

libssh2 1.11.0 added RSA-SHA2 key upgrading (needed for OpenSSH ≥ 8.8 targets, upstream issue #62). 1.11.1 adds the Terrapin strict-KEX mitigation, disables DSA by default and adds ChaCha20-Poly1305 ([changes](https://libssh2.org/changes.html)). On trixie, `apt-get install libssh2-1-dev` plus `pecl install ssh2-1.5.0` replaces the source build.

### Code scan: PHP 8.x incompatibilities and risks

This is a manual static scan (no PHP binary available locally). Grep found **no** `each()`, `create_function`, `money_format`, `utf8_encode/decode`, `strftime`, `FILTER_SANITIZE_STRING`, `"${var}"` interpolation (8.2), implicitly-nullable typed params (8.4) or `E_STRICT` usage.

Dynamic properties (8.2): every class that assigns undeclared `$this->x` extends `Record`/`Entity`, which defines `__set` (`model/record.php:110`). Classes with a magic `__set` are exempt from the 8.2 deprecation, so no hits there. Remaining risk is external assignment to non-Record objects, so run PHPStan or PHPCompatibility in CI to confirm.

| # | File:line | Issue | PHP version | Severity | Fix |
|---|---|---|---|---|---|
| 1 | `core.php:22`, `core.php:48-50` | `exception_error_handler` throws on **all** error levels, including E_DEPRECATED. The handler runs regardless of `error_reporting()` ([set_error_handler](https://www.php.net/manual/en/function.set-error-handler.php)), so every 8.1+ deprecation becomes a 500 or a dead sync worker. | 8.1+ | **High** (amplifier) | Return `false` (log) for `E_DEPRECATED`/`E_USER_DEPRECATED`; keep throwing for warnings. Run CI with deprecations visible. |
| 2 | `ldap.php:53-56` | `@ldap_sort()` was removed in 8.0 ([manual](https://www.php.net/manual/en/function.ldap-sort.php)); calling it is a fatal `Error`. No caller passes `$sort` today (`model/user.php:322,339,393`), so it is dead code. | 8.0 | Medium (latent) | Delete the sort loop, or `usort()` after `ldap_get_entries`. |
| 3 | `model/user.php:323`, `model/user.php:394` | `reset($ldapusers)` where `LDAP::search()` returns `false` on failure (`ldap.php:78`). `reset(false)` is a TypeError in 8.x. | 8.0 | Medium | `if($ldapusers && ($ldapuser = reset($ldapusers)))` or make `search()` throw. |
| 4 | `model/user.php:339-348` | `foreach($ldapgroups …)` on a possible `false` gives a warning, which the handler turns into an exception (in 7.4 too). | all | Low | Same as #3. |
| 5 | `core.php:68-75` | `new mysqli()` failure: since 8.1 the default reporting mode is exceptions, so `mysqli_sql_exception` is thrown and `catch(ErrorException)` misses it. `DBConnectionFailedException` is never raised. `report_mode` is set *after* connecting. | 8.1 | Medium | Call `mysqli_report(MYSQLI_REPORT_ERROR\|MYSQLI_REPORT_STRICT)` before connecting; catch `mysqli_sql_exception`. ([migration81](https://www.php.net/manual/en/migration81.incompatible.php)) |
| 6 | `core.php:101` | `$args[0][0]` on an empty string: "Uninitialized string offset" was promoted to Warning in 8.0, which becomes an exception. Callers pass non-empty strings, so low risk. | 8.0 | Low | `str_starts_with($args[0], '/')`. |
| 7 | `scripts/ldap_update.php:59-70` | `$rcpt` is only assigned when `user_superior` is set; otherwise `is_null($rcpt)` reads an undefined variable (Warning in 8.0, Notice in 7.4). Either way the handler throws, so orphan mails crash the cron when `user_superior` is unset. | all (worse in 8) | Medium | Initialise `$rcpt = null;`. |
| 8 | `requesthandler.php:48` and others | `$_POST['csrf_token']` and many `$_POST[...]`/`trim($_POST[...])` reads without `isset` (`views/server.php:69,91,162`, `views/group.php:57-149`, `views/groups.php:19,25`, …). An undefined index is a Warning in 8.0 (Notice in 7.4), so exceptions in both. Under 8.1, `trim(null)` is also deprecated. | 8.0/8.1 | Low to medium | `$_POST['x'] ?? ''`. |
| 9 | `templates/*.php`, e.g. `templates/functions.php:79-88` | `urlencode($event->server->hostname)` etc. on nullable DB fields. Passing null to internal string functions is deprecated in 8.1, which becomes an exception via #1. `out()`/`hesc()` already guard null (`core.php:116,159`). | 8.1 | Medium (needs runtime test) | Fix #1 first, then fix the hits that show up in logs. |
| 10 | `model/record.php:135` | `!=` comparison between DB strings and PHP values: 8.0 changed number-to-non-numeric-string comparison ([migration80](https://www.php.net/manual/en/migration80.incompatible.php)). Could create spurious "changed" events. | 8.0 | Low | Use typed comparison where semantics are known. |
| 11 | `model/user.php:272,282` | CSRF token = `hash(sha512, mt_rand())`, which is not a CSPRNG. Not a PHP 8 issue, but cheap to fix during the upgrade. | n/a | Medium (security) | `bin2hex(random_bytes(32))`. |
| 12 | `scripts/sync.php:275` + `migrations/002.php` (fork commit `523ffa6`) | The fork changed the host-key fingerprint to `SSH2_FINGERPRINT_MD5\|SSH2_FINGERPRINT_SHA1` (MD5=0, so this is SHA1, 40 hex chars) and widened the column by **editing migration 002 in place**. Existing databases that already ran 002 keep `char(32)`: the SHA1 string is truncated or rejected, and existing MD5 fingerprints no longer match, so every server fails with "host key verification failed". | n/a | Medium | Add a new migration `004` that ALTERs the column; document a fingerprint reset. Consider SHA256 when available. |

Also needed: `docker-php-ext-install ldap mysqli mbstring pcntl` works unchanged on 8.4 (mbstring needs `libonig-dev`). Upstream PR #52 "MySQL TLS" is still open if needed.

---

## 3. OIDC without AD/LDAP (Authentik)

### 3a. Apache `mod_auth_openidc` (recommended)

**Availability.**

- The `php:*-apache` images install Debian's `apache2` and use mpm_prefork ([Dockerfile](https://raw.githubusercontent.com/docker-library/php/master/8.4/trixie/apache/Dockerfile)), so `apt-get install libapache2-mod-auth-openidc` works.
- Versions: trixie `2.4.17-1+deb13u1`, bookworm `2.4.12.3-2+deb12u5`, forky/sid `2.4.20.3-1` ([Debian](https://packages.debian.org/search?keywords=libapache2-mod-auth-openidc&searchon=names&suite=all&section=all), [security tracker](https://security-tracker.debian.org/tracker/source-package/libapache2-mod-auth-openidc)).
- Upstream v2.4.20.4 (2026-11-01) fixed several security issues, among them GHSA-j3g4-73w8-p842, GHSA-gwg9-pmp9-m6wv, GHSA-98m5-m556-8684 and an unauthenticated front-channel logout ([releases](https://api.github.com/repos/OpenIDC/mod_auth_openidc/releases?per_page=3)).
- Upstream publishes `.deb`s for recent Debian/Ubuntu on GitHub Releases ([wiki FAQ 11](https://github.com/OpenIDC/mod_auth_openidc/wiki#11-where-can-i-get-binary-packages)). Decide between the Debian package (tracks DSAs) and pinning the upstream `.deb`.

**Identity hand-off** ([auth_openidc.conf](https://raw.githubusercontent.com/OpenIDC/mod_auth_openidc/master/auth_openidc.conf)):

- `OIDCRemoteUserClaim <claim>[@] [regex] [subst]` sets `REMOTE_USER`. The default is `sub@` (sub plus issuer). For SKA use **`OIDCRemoteUserClaim preferred_username`**, so `REMOTE_USER` equals the Authentik username, which is the `uid` SKA stores and shows.
- `OIDCPassClaimsAs [none|headers|environment|both]` (default `both`); claims arrive as `OIDC_CLAIM_<name>` (`OIDCClaimPrefix`). Multi-valued claims are joined with `OIDCClaimDelimiter` (default `,`). Group names containing commas would be ambiguous, so either set another delimiter or use `OIDCPassUserInfoAs json`, which passes `OIDC_userinfo_json`.
- Recommend `OIDCPassClaimsAs environment` (no headers). The module scrubs client-sent `OIDC_*` headers anyway ([wiki FAQ 6](https://github.com/OpenIDC/mod_auth_openidc/wiki)).
- PHP reads `$_SERVER['REMOTE_USER']` ([wiki FAQ 10](https://github.com/OpenIDC/mod_auth_openidc/wiki)). `PHP_AUTH_USER` is only populated for HTTP Basic/Digest ([PHP manual](https://www.php.net/manual/en/reserved.variables.server.php)). With LDAP Basic auth Apache sets `REMOTE_USER` too, so `requesthandler.php:23-24` can switch to `REMOTE_USER` for both backends.

**Authorization in Apache** ([Authorization wiki](https://github.com/OpenIDC/mod_auth_openidc/wiki/Authorization)): `Require claim <claim>:<value>` and regex `Require claim "name~regex"`. Several `Require claim` lines are OR'ed. Use `Require valid-user` and keep role logic in SKA, or gate on an "ska-users" group with `Require claim groups:ska-users`. Authentik's default `profile` scope returns group **names** in a `groups` claim ([property mappings](https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/)).

**Sessions** ([auth_openidc.conf](https://raw.githubusercontent.com/OpenIDC/mod_auth_openidc/master/auth_openidc.conf)):

- `OIDCSessionType server-cache` (default) with `OIDCCacheType shm` (default) is fine for a single container. Sessions are lost on restart, which is acceptable because users just SSO again. `redis`/`memcache`/`file` are available for multi-replica setups.
- `OIDCSessionInactivityTimeout` defaults to 300 s, which is short for an admin UI; set 1800–3600.
- `OIDCSessionMaxDuration` defaults to 8 h.
- `OIDCCryptoPassphrase` must be set from a secret. If unset, a random one is generated at start, which invalidates state on restart.
- `OIDCRedirectURI` must be a protected vanity path (for example `/oidc/redirect_uri`). Because SKA uses `FallbackResource /init.php`, it must not be routed into PHP.
- Behind a TLS-terminating proxy, set `OIDCXForwardedHeaders X-Forwarded-Proto X-Forwarded-Host`.

**Logout** ([wiki FAQ 9](https://github.com/OpenIDC/mod_auth_openidc/wiki#9-how-do-i-logout-users)):

- Link to `<OIDCRedirectURI>?logout=<url-encoded unprotected page>`. This closes upstream issues #2 and #58 (logout button), which Basic auth could never offer.
- With `OIDCProviderMetadataURL` discovery, the module also redirects to the OP's end-session endpoint. Authentik's is `/application/o/<slug>/end-session/` ([Authentik OAuth2](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)).
- Back-channel: register `<OIDCRedirectURI>?logout=backchannel` as the provider's back-channel logout URI. Authentik ≥ 2025.10 sends it whenever an admin deactivates a user or deletes a session ([single logout](https://docs.goauthentik.io/add-secure-apps/providers/single-logout/)).

**Authentik provider settings** ([OAuth2 provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/), [schema SubModeEnum](https://api.goauthentik.io/schema.yml)):

- Discovery URL: `https://<authentik>/application/o/<slug>/.well-known/openid-configuration`.
- Default scopes are `openid profile email entitlements offline_access`.
- `sub` mode can be `hashed_user_id | user_id | user_uuid | user_username | user_email | user_upn`. Keep the stable default `sub` and use `preferred_username` for `REMOTE_USER`. Optionally store `sub` or `uuid` to make username renames safe.
- Claims reach the ID token only if "Include claims in id_token" is enabled. Otherwise they come from userinfo, which mod_auth_openidc calls by default.

### 3b. In-app PHP libraries

| Library | Status | Source |
|---|---|---|
| `jumbojett/OpenID-Connect-PHP` | Not archived. Last push 2026-08-17, last release v1.0.2 (2024-09-13), 138 open issues. Slow release cadence. | [repo API](https://api.github.com/repos/jumbojett/OpenID-Connect-PHP), [releases](https://api.github.com/repos/jumbojett/OpenID-Connect-PHP/releases?per_page=3) |
| `league/oauth2-client` | Active: 2.9.1 (2026-09-16, Guzzle 8), 2.9.0 added PHP 8.5. It is OAuth2 only: ID-token validation, discovery and JWKS would need extra code or packages. | [releases](https://api.github.com/repos/thephpleague/oauth2-client/releases?per_page=3), [repo API](https://api.github.com/repos/thephpleague/oauth2-client) |

SKA has no composer setup, no session layer (it relies entirely on Apache auth per request) and no login or logout pages. An in-app client would add all of that: composer, PHP sessions, a callback route, ID-token validation, cookie flags and logout.

**Recommendation: `mod_auth_openidc`.** The app keeps its "web server authenticates, PHP trusts the user variable" model. The PHP diff is small: `REMOTE_USER`, a new auth realm, a directory backend. Session, crypto, PKCE and back-channel logout are handled by a maintained C module. LDAP stays selectable by swapping the Apache config file (`authnz_ldap` vs `auth_openidc`) at container start. **Trade-off:** OIDC protocol security fixes now come through the Debian or upstream package (see the 2.4.20.4 GHSAs), so the image must be rebuilt regularly. Item D3 covers that.

### 3c. Replacing the LDAP-provided functions

What LDAP does today (`model/user.php:301-380`, `scripts/ldap_update.php`):

| Function | LDAP today | Authentik replacement |
|---|---|---|
| uid → user exists? | `ldap_search` on `user_id` | `GET /api/v3/core/users/?username=<uid>` |
| name, email | `user_name`, `user_email` attrs | `name`, `email` fields of the User object |
| active flag | `user_active` attr compared with `user_active_true/false` | `is_active`; optionally also require membership in an "ska-users" group |
| admin | membership of `admin_group_cn` | membership of an Authentik group with the same configured name (`groups_obj[].name`) |
| group sync | `sync_groups[]` mirrored as SKA system groups | same loop, membership taken from `groups_obj` |
| superior | `user_superior` attr (optional) | No standard field. Use `attributes.<key>` if needed, otherwise drop (orphan mails go to `report_address`). |
| deprovision | hourly cron: missing → `active=0`, orphan-server mails | same cron logic driven by API results |

Authentik API facts ([schema.yml](https://api.goauthentik.io/schema.yml) is the public dev schema, `2026.11.0-rc1`; use your instance's `/api/v3/schema/` to match its version, per [api.goauthentik.io](https://api.goauthentik.io/)):

- `GET /api/v3/core/users/` filters on `username`, `email`, `is_active`, `type` (`internal|external|service_account|internal_service_account`), `groups_by_name`, `groups_by_pk`, `include_groups` and `last_updated__gt`. It paginates with `page`/`page_size` and returns `pagination{next,count,total_pages…}` plus `results`.
- User fields include `pk`, `username`, `name`, `is_active`, `email`, `groups`, `groups_obj`, `attributes`, `uid`, `path`, `type` and `uuid`.
- Auth uses the `Authorization: Bearer <token>` header with a static API token. Tokens can expire and auto-rotate ([API auth](https://api.goauthentik.io/authentication/)).
- `POST /api/v3/core/users/service_account/` creates a service account and token. Request fields are `name`, `create_group`, `expiring` (default true) and `expires` ("if not provided, valid for 360 days"). The response includes `token`. Token intents include `api`.
- Users can't be granted permissions directly. Grant `view_user`/`view_group` through a role or group ([user ops](https://docs.goauthentik.io/users-sources/user/user_basic_operations/)).
- Deactivating a user in Authentik revokes their sessions and blocks authentication (same source).

**Deprovisioning design (periodic sync, as decided):**

1. Add a directory interface with two implementations, LDAP and Authentik. It is used by `UserDirectory::get_user_by_uid()` for unknown users, by the admin "refresh" action (`views/user.php:51`) and by the cron.
2. Generalize `scripts/ldap_update.php` into a `directory_update.php` that dispatches on the backend. For OIDC it pages through `core/users/?type=internal&include_groups=true`, builds a username → user map and applies the existing logic: missing or `!is_active` → `active=0`, update name/email/admin/sync_groups, send orphan mails.
3. Because SSH access only disappears when `syncd` rewrites `authorized_keys`, run the directory sync more often than hourly (for example every 10–15 min). It is cheap: one paged API call.
4. Add back-channel logout (3a) so web sessions die immediately. This doesn't touch the SKA DB `active` flag.

**Alternatives** (not chosen, for reference):

- **SCIM 2.0** ([RFC 7643](https://datatracker.ietf.org/doc/html/rfc7643), [RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644)): SKA would expose `/Users` and `/Groups`. The Authentik SCIM provider pushes on change and runs a full sync hourly, authenticated with a static token ([Authentik SCIM](https://docs.goauthentik.io/add-secure-apps/providers/scim/)). Lowest latency, but SKA would have to implement a SCIM server. That is Large; defer.
- Other IdPs: the same directory interface could later get a Keycloak Admin REST ([docs](https://www.keycloak.org/docs-api/latest/rest-api/index.html)) or Microsoft Graph `GET /users` ([docs](https://learn.microsoft.com/en-us/graph/api/user-list)) implementation. Not researched further here.

**Login-time changes:**

- `requesthandler.php:23-24`: read `$_SERVER['REMOTE_USER'] ?? $_SERVER['PHP_AUTH_USER']`.
- `requesthandler.php:64`: allow `auth_realm` `'OIDC'` as well as `'LDAP'`. Add `'OIDC'` to the enum with a **new** migration (`migrations/002.php:252` defines `enum('LDAP','local','external')`). Same for the realm checks in `scripts/ldap_update.php:39` and `templates/user.php:25,221`.
- Optional: refresh name, email and groups for existing users from `OIDC_CLAIM_*` at login. Today existing users are only refreshed by cron, because `get_user_by_uid` returns DB rows without LDAP (`model/userdirectory.php:85-103`).
- `keys-sync` user: `ldap_update.php:26` and `sync.php:66` call `get_user_by_uid('keys-sync')`, which hits the directory if the user is missing. Make the directory lookup tolerate it, or create it as `local`.

**API / script authentication without LDAP Basic:**

- The bundled scripts (`scripts/*.php`) don't call HTTP; they `require core.php` directly, so they are unaffected.
- External automation that POSTs with `X-Bypass-CSRF-Protection: 1` (`requesthandler.php:46`) currently uses Basic auth. With OIDC, browsers can't do that. Options:
  - **(a)** If the LDAP backend is also present, keep a separate `<Location /api>`-style vhost or alias with `authnz_ldap` Basic for machine users.
  - **(b)** Protect an alias with **mod_oauth2** (`libapache2-mod-oauth2`: trixie 4.0.0, [Debian](https://packages.debian.org/search?keywords=libapache2-mod-oauth2&searchon=names&suite=all&section=all)). It supersedes mod_auth_openidc's deprecated OAuth RS mode ([auth_openidc.conf](https://raw.githubusercontent.com/OpenIDC/mod_auth_openidc/master/auth_openidc.conf)). It would validate Authentik **client_credentials** JWTs; Authentik issues them for a service-account username plus app-password token, and other hosts can validate them with the provider's signing key ([machine-to-machine](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/client_credentials/)). `REMOTE_USER` is mapped from the token's username claim.
  - **(c)** In-app API tokens (Large; not needed now).
- In every case, accept the CSRF bypass header **only** when `AUTH_TYPE` is not the cookie-based OIDC session.
- Check whether anyone uses this today before building it (YAGNI).

---

## 4. Docker deployment stability and hardening

Current state: `docker/Dockerfile`, `docker/entrypoint.sh`, `docker/cron`, `docker/ldap-docker.conf`, `.github/workflows/docker-image.yml`.

| Problem | Where | Fix | Source |
|---|---|---|---|
| Image content isn't the built commit: `git clone ${SYSTEM}` of the default branch at build time. CI builds with `context: ./docker`. | `Dockerfile` `RUN git clone ${SYSTEM} /ska`; workflow `context: ./docker` | Build context `.`, `COPY` the repo (`.dockerignore` excludes `config/config.ini`, `config/keys-sync*`, `.git`). Msprg does exactly this. | [Msprg Dockerfile](https://github.com/Msprg/ssh-key-authority/blob/master/Dockerfile) |
| Unpinned libssh2 HEAD source build plus build tools left in the image | `Dockerfile` libssh2 block | On trixie, `libssh2-1-dev` (1.11.1) + `pecl install ssh2-1.5.0`; multi-stage build or purge build deps | [Debian](https://packages.debian.org/search?keywords=libssh2-1&searchon=names&suite=all&section=all), [pecl](https://pecl.php.net/package/ssh2) |
| Floating base `php:7.4-apache` (EOL) | `Dockerfile:1` | `php:8.4-apache-trixie`, optionally pinned by digest and bumped by Dependabot/Renovate | [official-images](https://raw.githubusercontent.com/docker-library/official-images/master/library/php) |
| amd64-only: `--with-libdir=lib/x86_64-linux-gnu` | `Dockerfile:43` | `--with-libdir="lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)"`; build `linux/amd64,linux/arm64` with buildx (QEMU is bundled in BuildKit) | [multi-platform](https://docs.docker.com/build/building/multi-platform/); `8.4-apache` images exist for amd64, arm64v8 and others ([official-images](https://raw.githubusercontent.com/docker-library/official-images/master/library/php)) |
| Wrong user and glob: `chown key-sync …`, `chmod 600 /ska/config/key-sync*`. The user is `keys-sync`, the files are `keys-sync*`, so the chmod never matches. | `entrypoint.sh:14-15` | Fix names; fail hard if the key is missing or world-readable | — |
| `sleep 5` DB wait | `entrypoint.sh` | Loop on a real check (for example `php -r 'new mysqli(...)'`), with timeout; plus compose `depends_on: db: condition: service_healthy` and a DB healthcheck | [compose services](https://docs.docker.com/reference/compose-file/services/) |
| No HEALTHCHECK | `Dockerfile` | `HEALTHCHECK CMD curl -fsS http://127.0.0.1/…` on an unauthenticated path. Every path is protected today, so add a tiny static `/healthz` excluded from auth. Optionally also check that the syncd PID is alive. | [compose healthcheck](https://docs.docker.com/reference/compose-file/services/), Msprg Dockerfile |
| Apache + cron + syncd in one container, managed by a shell script. cron runs `ldap_update` and a syncd watchdog; syncd is started before Apache; `tail -f &` | `entrypoint.sh`, `docker/cron` | Docker recommends one concern per container, or a process manager (supervisord) or `--init` when several processes are needed. Pragmatic choice: **one image, several services in compose** with the same image and different `command:` (`web` = apache2-foreground, `syncd` = `syncd.php` in foreground, `cron` = directory sync loop). Each gets its own restart policy and logs. Alternatively keep one container with supervisord + tini as Msprg does. | [multi-service container](https://docs.docker.com/engine/containers/multi-service_container/) |
| Secrets in `config.ini` inside the image path; entrypoint parses it with `awk`; `PassEnv LDAP_BIND_PW` exposes the bind password to every PHP request environment | `entrypoint.sh:3-6`, `ldap-docker.conf:1-4` | Mount `config.ini` and keys read-only (or as compose `secrets` under `/run/secrets/`); keep `OIDCCryptoPassphrase`, the OIDC client secret and the Authentik API token in secret files (`exec:` or an `Include`d generated conf); don't `PassEnv` passwords | [compose secrets](https://docs.docker.com/reference/compose-file/services/), [auth_openidc.conf](https://raw.githubusercontent.com/OpenIDC/mod_auth_openidc/master/auth_openidc.conf) (`OIDCCryptoPassphrase exec:`) |
| HTTP only, port 80, Basic credentials in clear unless a proxy terminates TLS | `Dockerfile` vhost | Document a mandatory TLS reverse proxy; OIDC: `OIDCXForwardedHeaders` | [auth_openidc.conf](https://raw.githubusercontent.com/OpenIDC/mod_auth_openidc/master/auth_openidc.conf) |
| CI pushes `:latest` on every push **and pull_request**; no version tags; no arm64 | `docker-image.yml` | `docker/metadata-action` tags: `type=ref,event=branch`, `type=ref,event=pr`, `type=semver,pattern={{version}}`, `{{major}}.{{minor}}`, `type=sha`; `latest` only for tags or the default branch; `push: ${{ github.event_name != 'pull_request' }}`; `platforms: linux/amd64,linux/arm64`. Also scheduled rebuilds (weekly) for base and mod_auth_openidc security updates. | [metadata-action](https://github.com/docker/metadata-action) |
| Auth backend fixed in the image | `Dockerfile` vhost + `ldap-docker.conf` | Ship `auth-ldap.conf` and `auth-oidc.conf`; the entrypoint enables one based on `SKA_AUTH_BACKEND=ldap\|oidc` | — |

---

## Recommended work items

Sizes: S ≤ 1 day, M = 2–4 days, L = 1–2 weeks. "Dep" = depends on.

### Milestone 0: Security and correctness (do now)

| ID | Title | Why | Size | Dep |
|---|---|---|---|---|
| S1 | Merge upstream `operasoftware/master` (`aa71765`, `fda9081`, `d5b1fb7`) | Fixes the 2025-09 privilege escalation on group access-rule options; brings in the force_disable fix | S | — |
| S2 | Audit group access-rule options after merge | The vulnerable endpoint was reachable by any user | S | S1 |
| S3 | Fix `entrypoint.sh` keys-sync chown/chmod typos | The private key's permissions are never tightened | S | — |
| S4 | New migration `004` for the `rsa_key_fingerprint` width; document the fingerprint reset | Editing 002 in place doesn't reach existing DBs; MD5→SHA1 change breaks host-key checks | S | — |
| S5 | CSRF token from `random_bytes` | `mt_rand` isn't a CSPRNG | S | — |

### Milestone 1: PHP 8.4 + image rebase

| ID | Title | Why | Size | Dep |
|---|---|---|---|---|
| P1 | Error handler: don't throw on `E_DEPRECATED`; log instead | Otherwise every 8.1+ deprecation is fatal | S | — |
| P2 | Fix PHP 8 breakers: remove `ldap_sort`, guard `reset()`/`foreach` on false, mysqli 8.1 exception, `$rcpt` init, `path_join` offset, `$_POST` `??` defaults | Listed in section 2, rows 2–8 | M | P1 |
| P3 | Rebase image on `php:8.4-apache-trixie`; Debian libssh2 1.11.1 + pecl `ssh2-1.5.0`; multi-arch libdir | PHP 7.4 EOL; reproducible build; arm64 | M | P1 |
| P4 | CI lint: `php -l` on 8.4 plus PHPStan or PHPCompatibility | Catches the remaining 8.x issues (dynamic props, null args) | S | P3 |
| P5 | Smoke test in CI: compose up (db + ska), migrations, `/healthz`, one sync against a throwaway sshd container | Proves ssh2 1.5.0 + libssh2 1.11 + OpenSSH ≥ 8.8 (upstream #62) | M | P3, D2 |

### Milestone 2: Docker hardening

| ID | Title | Why | Size | Dep |
|---|---|---|---|---|
| D1 | Build from repo context with `COPY` + `.dockerignore`; drop the build-time `git clone` | Image matches the commit; no secrets in the image | S | — |
| D2 | `/healthz` + HEALTHCHECK; real DB wait loop; compose example with `service_healthy` | Replaces `sleep 5`; orchestrator-visible health | S | D1 |
| D3 | CI: metadata-action tags (semver/sha/branch), no push on PR, amd64+arm64, weekly scheduled rebuild | Stops `:latest` drift and PR pushes; picks up base and mod_auth_openidc security updates | S | P3 |
| D4 | Split processes: same image, `web` / `syncd` / `cron` services in compose (or supervisord + tini) | Independent restarts and logs; no shell watchdog | M | D2 |
| D5 | Secrets via mounted files/compose secrets; remove `awk` config parsing and the `PassEnv` bind password | Credential exposure | S | D1 |
| D6 | Pluggable auth conf: `SKA_AUTH_BACKEND=ldap\|oidc` selects the Apache conf at start | LDAP stays optional | S | D1 |

### Milestone 3: OIDC login (Authentik)

| ID | Title | Why | Size | Dep |
|---|---|---|---|---|
| O1 | `auth-oidc.conf` with mod_auth_openidc: discovery URL, `OIDCRemoteUserClaim preferred_username`, `OIDCPassClaimsAs environment`, cache/session timeouts, crypto passphrase from secret, redirect URI excluded from `FallbackResource` | Core login | M | D6, P3 |
| O2 | `requesthandler.php`: use `REMOTE_USER` (fallback `PHP_AUTH_USER`); accept realm `OIDC`; migration adding `'OIDC'` to the `auth_realm` enum; update realm checks in templates and scripts | Minimal app change | S | O1 |
| O3 | Logout button → `<redirect_uri>?logout=…` (OIDC only) | Upstream #2/#58; RP-initiated logout | S | O1 |
| O4 | Back-channel logout: register `?logout=backchannel` in Authentik | Instant session kill on deactivation (Authentik ≥ 2025.10) | S | O1 |
| O5 | Authentik setup doc: provider, scopes, groups claim, `admin_group_cn` and `sync_groups` mapping, service account | Reproducible setup | S | O1 |

### Milestone 4: Directory backend + deprovisioning

| ID | Title | Why | Size | Dep |
|---|---|---|---|---|
| A1 | Extract a directory interface from `User::get_details_from_ldap`; split out shared group/admin sync logic | Lookup, refresh and cron all depend on LDAP today | M | P2 |
| A2 | Authentik directory implementation: `core/users` lookup by username, paged list, `is_active`, `groups_obj`; bearer token from secret file; timeouts | Admin "add user by uid" and deprovisioning without LDAP | M | A1, O5 |
| A3 | `directory_update.php` (generalized `ldap_update.php`) with backend dispatch; cron every 10–15 min; orphan-server mails without `user_superior` | Periodic deprovisioning, as decided | M | A2 |
| A4 | Optional: refresh name, email and groups from `OIDC_CLAIM_*` / `OIDC_userinfo_json` at login | Fresher roles between syncs | S | O2, A1 |
| A5 | Service-account token rotation runbook (default expiry 360 days) | Sync silently breaks when the token expires; alert on 401 | S | A2 |

### Milestone 5: Machine API (only if needed)

| ID | Title | Why | Size | Dep |
|---|---|---|---|---|
| M1 | Inventory who uses `X-Bypass-CSRF-Protection` + Basic today | YAGNI check before building anything | S | — |
| M2 | Bearer-token API alias via mod_oauth2 validating Authentik client_credentials JWTs; honor the CSRF bypass only for bearer auth | Automation without LDAP Basic | M | M1, O1 |
| M3 | SCIM 2.0 server endpoint (instead of polling) | Lower deprovisioning latency | L | A1 (defer) |

### Open questions

- Username stability: is the Authentik `username` immutable in your org? If not, store `sub`/`uuid` as well (schema change) and key on it.
- mod_auth_openidc source: the Debian trixie package (2.4.17, DSA-driven) or a pinned upstream `.deb` (2.4.20.4 with the Nov 2026 fixes)?
- Run the web, syncd and cron containers as separate compose services (D4), or keep one container with supervisord?
