# php-pins

Find every PHP version your repositories pin, and what PHP2Shell
([CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp))
means for each one.

It is one POSIX shell script with one awk program. It reads the files under the
folders you name and prints every PHP version they set, with what to do about
each. It makes no network connection, runs nothing it finds and writes no files.

## Run it

```sh
curl -fsSLO https://raw.githubusercontent.com/arvion-ai/php-pins/main/php-pins.sh
sh php-pins.sh ~/code/shop ~/code/api
```

Every repository in a folder at once:

```sh
sh php-pins.sh ~/code/*/
```

Read it before you run it; it is one file. The same file is served at
<https://arvion.ai/tools/php-pins.sh>, and <https://arvion.ai/tools/php-pins>
shows its SHA-256, so you can check a download with `shasum -a 256 php-pins.sh`
(macOS) or `sha256sum php-pins.sh` (Linux).

Set `NO_COLOR=1` for output without colours.

## What it prints

One line per pin, worst first: what to do, where it is, what it says, and why.
These lines come from the test repository in `tests/fixtures/shop`:

```
shop
  EOL      Dockerfile:3                       php:8.1-fpm-alpine                    PHP 8.1 is past end of life and gets no official fix. This tag is no longer rebuilt. Move to 8.2 or newer.
  UPDATE   compose.yaml:13                    php:8.3-fpm-alpine3.18                The alpine3.18 variant is not built any more, so this tag may not have the fix. Use a current one: trixie, bookworm, alpine3.24, alpine3.23.
  UPDATE   docker/Dockerfile.prod:1           php:8.3.35-apache                     Pinned below the fix. Change to 8.3.36 or newer.
  REBUILD  compose.yaml:3                     wordpress:php8.3-apache               This tag has carried PHP 8.3.36 since 21 Oct 2026. Pull and rebuild.
  CHECK    .github/workflows/ci.yml:8         php-version 8.3                       The runner may have an older PHP 8.3. Print php -v in the job; 8.3.36 has the fix.
  CHECK    docker/Dockerfile.alpine:2         package php83                         Installed from distribution packages. Update them and rebuild; distributions backport fixes, so their security notice says which build has it.
  OK       .php-version:1                     8.4.27                                Has the fix (8.4.27 or newer).
  NOTE     composer.json:5                    require php ^7.4 || ^8.0              The code still declares support for PHP 7.4, which is past end of life.
  ...

  34 pins in 17 files: 9 end of life, 7 to update, 4 to rebuild, 11 to check, 2 ok, 1 note
```

| Label | Meaning |
|---|---|
| `EOL` | The branch is past end of life and gets no official fix. Move to a supported branch. |
| `UPDATE` | Pinned to a version, digest, OS variant or WordPress release that doesn't have the fix. Change the pin. |
| `REBUILD` | The tag already carries the fixed PHP. Pull and rebuild, or the old image keeps running. |
| `CHECK` | The file can't say which PHP runs: a third-party image, a CI runner, distribution packages, DDEV or your host. Run `php -v` there. |
| `OK` | Pinned to a release with the fix. |
| `NOTE` | Composer settings. They install no PHP, but say which versions your code supports or targets. A note repeated across many `composer.json` files prints once, with a count. |

## What it reads

- Dockerfiles: `FROM` lines with `ARG` defaults filled in, `ENV PHP_VERSION`, and PHP installed with apt (`php8.3-cli`) or apk (`php83-fpm`)
- Compose, Kubernetes, GitLab CI and other YAML: `image:`, `container:` and `docker://` references
- GitHub, Forgejo and Gitea workflows: setup-php's `php-version` and matrix lists
- `composer.json`: `require.php` and `config.platform.php`
- `devcontainer.json`, `.php-version`, `.tool-versions` and `mise.toml`
- DDEV, Lando, Laravel Sail, Platform.sh and Upsun settings

It skips `.git`, `vendor` and `node_modules`, and files over 1 MB.

## A pin that says OK is not proof

The script reads what your files say. Linux distributions backport fixes
without changing the version number, and a server can run something other than
what a file pins. `php -v` on the server and your vendor's security notice are
the final word.

## Where it runs

macOS and Linux, with the `sh` and `awk` they already have. Its output is
byte-identical under dash, bash 5, bash 3.2 (the `/bin/sh` on macOS), zsh and
BusyBox sh, and with BWK awk (the one on macOS), gawk, mawk and BusyBox awk.
On Windows, use WSL.

## Tests

```sh
sh tests/run.sh
```

It runs the script on the repositories in `tests/fixtures` and compares the
output with `tests/fixtures/expected.txt`. Set `PHP_PINS_SH` to try another
shell, for example `PHP_PINS_SH=zsh sh tests/run.sh`.

## Keeping it current

The facts the verdicts rest on sit at the top of `php-pins.sh`, dated by
`DATA_AS_OF`: the fixed release on each PHP branch, the last day each branch
gets security fixes, the day the official images were rebuilt, the OS variants
the official `php` image is still built on, and the WordPress release the
official `wordpress` image builds. When one of them changes, update it there
and in `tests/fixtures/expected.txt`.

## Something wrong?

If the script misses a pin or gives a wrong verdict, open an issue with the
line it printed (or should have printed) and the line of the file it read.
Remove anything private first. You can also write to hello@arvion.ai.

## License

MIT, see [LICENSE](LICENSE). Made by [Arvion](https://arvion.ai).
