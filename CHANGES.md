# CHANGES

## 1.2.43 (May 11, 2023)

* [TECH] Bump version to `1.2.43`.
* [HOTFIX] Fix Windows 11 version detection.
* [HOTFIX] Fix plugins directory location on Windows.
* Add reboot check.
* Ping plugin Windows compatibility fixes:
  * handle newer Windows behavior with additional fallback logic.
  * improve parsing for non-English OS output where `"Average"` differs.
* Source commits include: `c0a0370`, `af9f0ba`, `17e7c52`, `4033b2a`, `49dfa0a`, `55ef514`.

## 1.2.42 (Apr 24/25, 2023)

* [TECH] Bump version to `1.2.42`.
* [HOTFIX] Remove unused variable declaration.
* Add/extend monitoring plugins and integrations:
  * BitNinja monitoring plugin.
  * Plesk Cgroups Manager plugin updates.
  * Fail2ban monitoring.
  * BIND monitoring.
  * Bird monitoring.
  * Users monitoring.
  * Postfix MTA plugin.
  * Dovecot plugin.
  * ProFTP plugin (initially added as `ftp.py`, then renamed to `proftp.py`).
* Plugin fixes:
  * `mdstat`: remove `sudo`.
  * `dirsize`: change to collect total size.
* Miscellaneous fixes:
  * configuration variable additions.
  * URL / broken-link fixes.
  * general maintenance and merge syncs from upstream PRs.

## 1.2.32

* [*] Updated the installation instructions.
