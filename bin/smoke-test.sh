#!/usr/bin/env bash
# End-to-end check against a running server: sign up, confirm the email
# from the mail log, sign in, and make sure the main protections respond.
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8000}"
MAIL_LOG="${MAIL_LOG:-storage/mail.log}"
JAR="$(mktemp)"
PASSWORD='blue+kettle+under+the+stairs'
EMAIL="smoke$RANDOM@example.com"

csrf_from() { grep -o 'name="_csrf" value="[a-f0-9]*"' | head -1 | sed 's/.*value="\([a-f0-9]*\)"/\1/'; }
status() { curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" "$@"; }
expect() { if [ "$1" != "$2" ]; then echo "FAIL: $3 (expected $2, got $1)"; exit 1; fi; echo "ok: $3"; }

headers="$(curl -s -D - -o /dev/null "$BASE/login")"
echo "$headers" | grep -i '^set-cookie' | grep -qi 'httponly' && echo "ok: session cookie is HttpOnly"
echo "$headers" | grep -i '^set-cookie' | grep -qi 'samesite=lax' && echo "ok: session cookie is SameSite=Lax"
echo "$headers" | grep -qi '^referrer-policy: no-referrer' && echo "ok: referrer policy"

expect "$(curl -s -o /dev/null -w '%{http_code}' -d 'email=a@b.c&password=x' "$BASE/login")" 419 "POST without CSRF token is refused"

token="$(curl -fsS -c "$JAR" -b "$JAR" "$BASE/register" | csrf_from)"
expect "$(status -d "_csrf=$token&name=Smoke+Test&email=$EMAIL&password=$PASSWORD" "$BASE/register")" 303 "register"

token="$(curl -fsS -c "$JAR" -b "$JAR" "$BASE/login" | csrf_from)"
expect "$(status -d "_csrf=$token&email=$EMAIL&password=$PASSWORD" "$BASE/login")" 401 "login before verifying is refused"

link="$(grep -o 'verify-email?token=[a-f0-9]*' "$MAIL_LOG" | tail -1)"
expect "$(status "$BASE/$link")" 303 "verify email"

token="$(curl -fsS -c "$JAR" -b "$JAR" "$BASE/login" | csrf_from)"
expect "$(status -d "_csrf=$token&email=$EMAIL&password=$PASSWORD" "$BASE/login")" 303 "login"

curl -fsS -c "$JAR" -b "$JAR" "$BASE/" | grep -q 'Hello, Smoke Test' && echo "ok: dashboard shows the user"

rm -f "$JAR"
echo "Smoke test passed."
