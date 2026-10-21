# em-macos-fix

Check and fix macOS `curl` trust for the [eMudhra intermediate CA compromise](https://emudhra.we-have-a-problem.com/) (Oct 2026).

Keychain-based apps (Safari, Chrome) are already protected on an up-to-date macOS. The built-in `/usr/bin/curl` uses `/etc/ssl/cert.pem`, which still trusts the affected roots.

## Check

```sh
CURL=/usr/bin/curl sh check-emudhra.sh
```

`REJECTED` = good, `TRUSTED` = bad, `ERR(n)` = couldn't check.

## Fix

```sh
sh fix-emudhra-certpem-safe.sh           # dry run, changes nothing
sh fix-emudhra-certpem-safe.sh --apply   # confirm each cert, then type YES
```

Removes `AAA Certificate Services` and `emSign ECC Root CA - G3` from `/etc/ssl/cert.pem`. A timestamped backup is made first and the undo command is printed at the end.

## Alternative

Use Homebrew curl, which uses the patched `ca-certificates`:

```sh
brew install curl ca-certificates
export PATH="$(brew --prefix curl)/bin:$PATH"
```