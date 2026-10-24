#!/bin/sh
# Runs php-pins.sh on the repositories in tests/fixtures and compares its
# output with tests/fixtures/expected.txt. PHP_PINS_SH picks the shell that
# runs the script (default sh), for example "zsh" or "busybox sh".
set -eu
cd "$(dirname "$0")/fixtures"
# shellcheck disable=SC2086 # PHP_PINS_SH may be two words, such as "busybox sh".
actual=$(NO_COLOR=1 ${PHP_PINS_SH:-sh} ../../php-pins.sh shop api)
expected=$(cat expected.txt)
if [ "$actual" = "$expected" ]; then
	echo "ok: output matches tests/fixtures/expected.txt"
else
	printf '%s\n' "$actual" | diff expected.txt - || true
	echo "FAIL: output differs from tests/fixtures/expected.txt" >&2
	exit 1
fi
