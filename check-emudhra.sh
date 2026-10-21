#!/bin/sh
# Checks whether curl still trusts the compromised eMudhra intermediates.
# Each test host serves a chain through one compromised intermediate.
#   REJECTED = good (certificate error), TRUSTED = bad (connection succeeded)
#
# Usage:
#   sh check-emudhra.sh                         # uses whichever curl is first in PATH
#   CURL=/usr/bin/curl sh check-emudhra.sh      # test macOS curl explicitly
#   CURL="$(brew --prefix curl)/bin/curl" sh check-emudhra.sh   # test Homebrew curl

CURL=${CURL:-curl}

# host | intermediate | root
HOSTS='dv-g3b-emudhra|EM DV TLS CA - G3B|emSign Root TLS CA - G3
dv-g3c-emudhra|EM DV TLS CA - G3C|emSign Root TLS CA - G3
ov-g3b-emudhra|EM OV TLS CA - G3B|emSign Root TLS CA - G3
ov-g3c-emudhra|EM OV TLS CA - G3C|emSign Root TLS CA - G3
ev-g3b-emudhra|EM EV TLS CA - G3B|emSign Root TLS CA - G3
ev-g3c-emudhra|EM EV TLS CA - G3C|emSign Root TLS CA - G3
dv-g3b-aaa-emudhra|EM DV TLS CA - G3B|AAA Certificate Services
dv-g3c-aaa-emudhra|EM DV TLS CA - G3C|AAA Certificate Services
ov-g3b-aaa-emudhra|EM OV TLS CA - G3B|AAA Certificate Services
ov-g3c-aaa-emudhra|EM OV TLS CA - G3C|AAA Certificate Services
ev-g3b-aaa-emudhra|EM EV TLS CA - G3B|AAA Certificate Services
ev-g3c-aaa-emudhra|EM EV TLS CA - G3C|AAA Certificate Services'

echo "Using: $(command -v "$CURL") ($("$CURL" --version | head -n1 | cut -d' ' -f1-5))"
echo

trusted=0 unknown=0
printf '%-9s %-42s %-20s %s\n' RESULT HOST INTERMEDIATE ROOT
while IFS='|' read -r h inter root; do
  host="$h.we-have-a-problem.com"
  "$CURL" -sS -o /dev/null --max-time 10 "https://$host/" 2>/dev/null
  rc=$?
  case $rc in
    0)        res=TRUSTED;  trusted=$((trusted + 1)) ;;   # chain accepted: bad
    60|35|51) res=REJECTED ;;                              # certificate/TLS error: good
    *)        res="ERR($rc)"; unknown=$((unknown + 1)) ;;  # DNS, timeout, etc.
  esac
  printf '%-9s %-42s %-20s %s\n' "$res" "$host" "$inter" "$root"
done <<EOF
$HOSTS
EOF

echo
if [ "$trusted" -gt 0 ]; then
  echo "NOT PROTECTED: $trusted host(s) trusted by this curl."; exit 1
elif [ "$unknown" -gt 0 ]; then
  echo "INCONCLUSIVE: $unknown host(s) could not be checked (network?)."; exit 2
else
  echo "OK: this curl rejects all compromised intermediates."
fi