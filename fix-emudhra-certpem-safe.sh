#!/bin/sh
# fix-emudhra-certpem-safe.sh
#
# Removes the roots affected by the eMudhra intermediate CA compromise
# (https://emudhra.we-have-a-problem.com/) from macOS /etc/ssl/cert.pem,
# the bundle used by /usr/bin/curl and other LibreSSL tools (not the Keychain).
#
# Safe by default:
#   sh fix-emudhra-certpem-safe.sh            dry run: lists matches, changes NOTHING
#   sh fix-emudhra-certpem-safe.sh --apply    asks per certificate, then once more
#                                             before writing; backs up first
#   ... [--apply] /path/to/bundle.pem         operate on another file
#
# Safety measures:
#   - nothing is written unless --apply is given AND you confirm twice
#   - confirmations are read from the terminal, so piping "yes" can't bypass them
#   - shows SHA-256 fingerprints so you can check what is being removed
#   - timestamped backup, verified byte-for-byte before the file is touched
#   - checks that every remaining certificate still parses before installing
#   - verifies the installed file matches what was checked; prints undo command

set -eu

APPLY=0
FILE=/etc/ssl/cert.pem
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    -*) echo "Unknown option: $arg" >&2; exit 2 ;;
    *) FILE=$arg ;;
  esac
done

# Subject lines (macOS "=== /C=.../CN=..." header) of the certificates to remove
PAT='^=== .*/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$'

die() { echo "ERROR: $*" >&2; exit 1; }
ask() {  # ask "question" -> 0 if the user typed the expected answer ($2, default y)
  want=${2:-y}
  printf '%s ' "$1" > /dev/tty
  read -r reply < /dev/tty || return 1
  [ "$reply" = "$want" ]
}

# ---------- pre-flight checks ----------
[ -f "$FILE" ] || die "$FILE not found."
[ -r "$FILE" ] || die "$FILE is not readable."
grep -q 'BEGIN CERTIFICATE' "$FILE" || die "$FILE does not look like a PEM bundle."
grep -q '^=== ' "$FILE" || die "$FILE has no '=== subject' headers; this script only understands the macOS cert.pem layout."
OPENSSL=$(command -v openssl || true)
[ -n "$OPENSSL" ] || echo "Warning: openssl not found; fingerprints and parse checks will be skipped."

# List matching blocks as "index<TAB>subject" (index = position among all === headers)
list_matches() {
  awk -v pat="$PAT" '/^=== /{ n++; if ($0 ~ pat) { sub(/^=== /, ""); print n "\t" $0 } }' "$FILE"
}
# Print the PEM of block number $1
extract_pem() {
  awk -v want="$1" '
    /^=== /{ n++ }
    n == want && /-----BEGIN CERTIFICATE-----/ { p = 1 }
    p { print }
    p && /-----END CERTIFICATE-----/ { exit }
  ' "$FILE"
}
# Write $FILE without the blocks whose indices are in $1 (comma separated).
# A block = its "### issuer" line + "=== subject" line + everything up to the next header.
filter_out() {
  awk -v drop="$1" '
    BEGIN { k = split(drop, a, ","); for (i = 1; i <= k; i++) d[a[i]] = 1 }
    function flush() { if (have) { if (!skip) print hold; have = 0 } }
    /^### / { flush(); hold = $0; have = 1; skip = 0; next }
    /^=== / { n++; skip = (n in d); if (have && !skip) print hold; have = 0
              if (!skip) print; next }
    { flush(); if (!skip) print }
    END { flush() }
  ' "$FILE"
}
count_certs() { grep -c 'BEGIN CERTIFICATE' "$1" || true; }
parsed_certs() {  # how many certificates openssl can actually parse
  "$OPENSSL" crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null \
    | "$OPENSSL" pkcs7 -print_certs -noout 2>/dev/null | grep -c '^subject' || true
}

# ---------- show what matches ----------
MATCHES=$(list_matches)
TOTAL=$(count_certs "$FILE")
echo "Bundle: $FILE ($TOTAL certificates)"
echo

if [ -z "$MATCHES" ]; then
  echo "No affected certificates found. Nothing to do."
  exit 0
fi

echo "Certificates matching the eMudhra advisory:"
echo "$MATCHES" | while IFS="$(printf '\t')" read -r idx subj; do
  echo "  [$idx] $subj"
  if [ -n "$OPENSSL" ]; then
    fp=$(extract_pem "$idx" | "$OPENSSL" x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')
    echo "        SHA-256: ${fp:-<could not parse>}"
  fi
done
echo

if [ "$APPLY" -eq 0 ]; then
  echo "Dry run: nothing was changed."
  if [ "$FILE" = /etc/ssl/cert.pem ]; then
    echo "To remove them, run:  sh $0 --apply"
  else
    echo "To remove them, run:  sh $0 --apply $FILE"
  fi
  exit 0
fi

# ---------- choose, one certificate at a time ----------
( : < /dev/tty ) 2>/dev/null || die "No terminal available for confirmation; refusing to continue."
DROP=""
NDROP=0
TMPLIST=$(mktemp)
TMP=$(mktemp)
trap 'rm -f "$TMPLIST" "$TMP"' EXIT
echo "$MATCHES" > "$TMPLIST"
while IFS="$(printf '\t')" read -r idx subj; do
  if ask "Remove [$idx] $subj ? [y/N]"; then
    DROP="${DROP:+$DROP,}$idx"
    NDROP=$((NDROP + 1))
  else
    echo "  keeping [$idx]"
  fi
done < "$TMPLIST"

[ -n "$DROP" ] || { echo "Nothing selected. No changes made."; exit 0; }

# ---------- build and check the new bundle ----------
filter_out "$DROP" > "$TMP"
AFTER=$(count_certs "$TMP")
[ $((TOTAL - AFTER)) -eq "$NDROP" ] \
  || die "Expected to remove $NDROP certificate(s) but count went $TOTAL -> $AFTER. No changes made."
if [ -n "$OPENSSL" ]; then
  P=$(parsed_certs "$TMP")
  [ "$P" -eq "$AFTER" ] \
    || die "Only $P of $AFTER remaining certificates parse with openssl. No changes made."
fi

echo
echo "Summary: $TOTAL -> $AFTER certificates (removing $NDROP)."
ask "Type YES to write $FILE:" YES || { echo "Aborted. No changes made."; exit 1; }

# ---------- back up, verify backup, install, verify install ----------
BACKUP="$FILE.bak.$(date +%Y%m%d-%H%M%S)"
[ -e "$BACKUP" ] && die "$BACKUP already exists; try again in a second."
sudo cp -p "$FILE" "$BACKUP"
sudo cmp -s "$FILE" "$BACKUP" || die "Backup verification failed. No changes made."

sudo cp "$TMP" "$FILE"    # overwrites in place: keeps original owner and mode
if ! cmp -s "$TMP" "$FILE"; then
  sudo cp -p "$BACKUP" "$FILE"
  die "Written file did not match; restored the backup."
fi

echo "Done. $FILE now has $AFTER certificates."
echo "Backup: $BACKUP"
echo "Undo:   sudo cp -p \"$BACKUP\" \"$FILE\""
echo
echo "Check with (should now fail with a certificate error):"
echo "  /usr/bin/curl https://dv-g3b-emudhra.we-have-a-problem.com/"
