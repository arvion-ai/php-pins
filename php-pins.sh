#!/bin/sh
# PHP pin finder, from https://arvion.ai/tools/php-pins
#
# Lists every place a repository sets its PHP version, and what PHP2Shell
# (CVE-2026-109618, CVE-2026-109619) means for each one. It reads:
#   Dockerfiles (FROM with ARG defaults, ENV PHP_VERSION, and PHP packages
#   installed with apt or apk), compose and other YAML files (image:,
#   container:, docker://), GitHub, Forgejo and Gitea workflows (setup-php
#   php-version and matrix lists), devcontainer.json, composer.json
#   (require.php and config.platform.php), .php-version, .tool-versions,
#   mise.toml, DDEV, Lando, Laravel Sail, Platform.sh and Upsun.
#
# It only reads files under the folders you name, skipping .git, vendor and
# node_modules. It sends nothing over the network, runs nothing it finds,
# and writes nothing.
#
# Usage:  sh php-pins.sh [folder ...]     (default: the current folder)
#         NO_COLOR=1 sh php-pins.sh ...   (no colours)
#
# Copyright (c) 2026 Arvion. MIT License; the full text is at the end.

set -eu

# PHP's PHP2Shell fix release on each supported branch (php.net, 21 Oct 2026),
# the last day each branch gets security fixes (php.net/supported-versions.php),
# the day the official php and wordpress images on Docker Hub first shipped
# the fixed PHP, the OS variants the official php image is still built on,
# and the WordPress release the official wordpress image builds. All as of
# DATA_AS_OF; a tag on any other variant or WordPress version no longer moves.
DATA_AS_OF="2026-10-23"
FIXED="8.2.35 8.3.36 8.4.27 8.5.12"
SECURITY_UNTIL="8.2=2026-12-31 8.3=2027-12-31 8.4=2028-12-31 8.5=2029-12-31"
IMAGES_FIXED_ON="2026-10-21"
IMAGE_OS="alpine3.23 alpine3.24 bookworm trixie"
WORDPRESS_LATEST="7.1.3"

usage() {
	cat <<'EOF'
Usage: sh php-pins.sh [folder ...]

Lists where the files in each folder set a PHP version, and what PHP2Shell
means for each one. With no folder, it reads the current one.

It only reads files. It sends nothing over the network and changes nothing.
Set NO_COLOR=1 for output without colours.
EOF
}

case "${1:-}" in
	-h | --help) usage; exit 0 ;;
esac
[ "$#" -gt 0 ] || set -- .

color=0
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then color=1; fi

# The scanner. It reads one file path per line on stdin, opens each file
# itself, and prints one line per pin, worst first. It is one single-quoted
# string, so it holds no apostrophes: bash 3.2, the /bin/sh on macOS, cannot
# parse a here-document inside $( ) that has them. The $ signs in it are awk's.
# It runs with LC_ALL=C so it sorts paths byte by byte; under en_US.UTF-8 the
# awk on macOS orders "Dockerfile" after "docker/", and the output would
# differ from machine to machine.
# shellcheck disable=SC2016
prog='
function day(iso,   p) {
	split(iso, p, "-")
	return (p[3] + 0) " " substr("JanFebMarAprMayJunJulAugSepOctNovDec", (p[2] + 0) * 3 - 2, 3) " " p[1]
}
# Compare versions part by part: -1, 0 or 1. A missing part counts as 0.
function vcmp(a, b,   x, y, n, m, i, p, q) {
	n = split(a, x, "."); m = split(b, y, ".")
	for (i = 1; i <= 3; i++) {
		p = (i <= n) ? x[i] + 0 : 0
		q = (i <= m) ? y[i] + 0 : 0
		if (p < q) return -1
		if (p > q) return 1
	}
	return 0
}
function parts(v,   x) { return v == "" ? 0 : split(v, x, ".") }
function branchof(v,   x, n) { n = split(v, x, "."); return n >= 2 ? x[1] "." x[2] : x[1] }
# The leading 8, 8.3 or 8.3.36 of s, or "".
function leadver(s,   v, x, n) {
	if (!match(s, /^[0-9]+(\.[0-9]+)*/)) return ""
	v = substr(s, 1, RLENGTH)
	n = split(v, x, ".")
	return n > 3 ? x[1] "." x[2] "." x[3] : v
}
# A YAML or Dockerfile value without spaces around it, a trailing comment or quotes.
function unquote(s,   q) {
	sub(/^[ \t]+/, "", s)
	sub(/[ \t]+#.*$/, "", s)
	sub(/[ \t]+$/, "", s)
	q = substr(s, 1, 1)
	if (length(s) >= 2 && (q == "\"" || q == SQ) && substr(s, length(s), 1) == q) s = substr(s, 2, length(s) - 2)
	return s
}
function noquotes(s) { gsub(QUOTES, "", s); return s }
# ${NAME}, ${NAME:-default} and $NAME from the file ARG lines; anything
# unknown stays as ${NAME}.
function resolve(s,   out, inner, name, def, i, val) {
	out = ""
	while (match(s, /\$\{[A-Za-z_][A-Za-z0-9_]*(:?-[^}]*)?\}/)) {
		inner = substr(s, RSTART + 2, RLENGTH - 3)
		out = out substr(s, 1, RSTART - 1)
		s = substr(s, RSTART + RLENGTH)
		i = index(inner, "-")
		if (i) { name = substr(inner, 1, i - 1); def = substr(inner, i + 1); sub(/:$/, "", name) }
		else { name = inner; def = "" }
		if (name in args) val = args[name]
		else if (i) val = def
		else val = "${" name "}"
		out = out val
	}
	s = out s
	out = ""
	while (match(s, /\$[A-Za-z_][A-Za-z0-9_]*/)) {
		name = substr(s, RSTART + 1, RLENGTH - 1)
		out = out substr(s, 1, RSTART - 1) ((name in args) ? args[name] : "${" name "}")
		s = substr(s, RSTART + RLENGTH)
	}
	return out s
}

# Set LABEL and NOTE for one pin. src says where the version came from.
function judge(ver, src, digest,   n, br, fx) {
	JBR = ""
	if (src == "require") { judgerequire(ver); return }
	if (src == "variable") { LABEL = "CHECK"; NOTE = "The version comes from a variable. Check where it is set."; return }
	n = parts(ver)
	if (n == 0 && src == "oldos") { LABEL = "UPDATE"; NOTE = "The " OLDOS " variant is not built any more, so this tag may not have the fix. Use a current one: " CURRENTOS "."; return }
	if (n == 0 && src == "oldwp") { LABEL = "UPDATE"; NOTE = "Tags for WordPress " OLDWP " are not rebuilt any more, so this one may not have the fix. Use wordpress:latest or WordPress " WPLATEST "."; return }
	if (n == 0) {
		if (src == "official" && digest) { LABEL = "UPDATE"; NOTE = "Pinned by digest, so it never changes. Re-pin to a build from after " day(FIXEDON) "."; return }
		if (src == "official") { LABEL = "REBUILD"; NOTE = "Floating tag, rebuilt with the fixed PHP on " day(FIXEDON) ". Pull and rebuild."; return }
		LABEL = "CHECK"; NOTE = "The tag names no PHP version. Run php -v inside the image."; return
	}
	if (n == 1) {
		if (ver + 0 < LOWMAJOR) { eol(ver ".x", src); return }
		if (ver + 0 > NEWMAJOR) { LABEL = "CHECK"; NOTE = "PHP " ver " is not a stable release yet."; return }
		br = NEWEST
	} else {
		br = branchof(ver)
		if (vcmp(br, LOWEST) < 0) { eol(br, src); return }
		if (vcmp(br, NEWEST) > 0) { LABEL = "CHECK"; NOTE = "PHP " br " is not a stable release yet."; return }
	}
	fx = FIX[br]; JBR = br
	# config.platform.php tells Composer which PHP to resolve packages for; it
	# installs nothing, so below an end-of-life branch it is a note.
	if (src == "composer") {
		LABEL = "NOTE"
		NOTE = "Composer resolves packages for PHP " ver "."
		if (n >= 3 && vcmp(ver, fx) < 0) NOTE = NOTE " The servers need " fx " or newer."
		return
	}
	if (n >= 3) {
		if (vcmp(ver, fx) >= 0) { LABEL = "OK"; NOTE = "Has the fix (" fx " or newer)." }
		else { LABEL = "UPDATE"; NOTE = "Pinned below the fix. Change to " fx " or newer." }
		return
	}
	if (src == "oldos") { LABEL = "UPDATE"; NOTE = "The " OLDOS " variant is not built any more, so this tag may not have the fix. Use a current one: " CURRENTOS "."; return }
	if (src == "oldwp") { LABEL = "UPDATE"; NOTE = "Tags for WordPress " OLDWP " are not rebuilt any more, so this one may not have the fix. Use wordpress:php" br " or WordPress " WPLATEST "."; return }
	if (digest && src == "official") { LABEL = "UPDATE"; NOTE = "Pinned by digest, so it never changes. Re-pin to a build from after " day(FIXEDON) "."; return }
	if (digest) { LABEL = "CHECK"; NOTE = "Pinned by digest. Run php -v inside the image; " fx " has the fix."; return }
	if (src == "official") { LABEL = "REBUILD"; NOTE = "This tag has carried PHP " fx " since " day(FIXEDON) ". Pull and rebuild."; return }
	if (src == "sail") { LABEL = "REBUILD"; NOTE = "Sail installs PHP " br " when it builds the image. Rebuild with sail build --no-cache."; return }
	if (src == "ci") { LABEL = "CHECK"; NOTE = "The runner may have an older PHP " br ". Print php -v in the job; " fx " has the fix."; return }
	if (src == "ddev") { LABEL = "CHECK"; NOTE = "DDEV provides this PHP. Update DDEV, restart the project and check php -v."; return }
	if (src == "lando") { LABEL = "CHECK"; NOTE = "Lando provides this PHP. Run lando rebuild and check php -v."; return }
	if (src == "platform") { LABEL = "CHECK"; NOTE = "Your host provides this PHP. Check its PHP2Shell notice."; return }
	if (src == "local") { LABEL = "CHECK"; NOTE = "Run php -v where this file is used; " fx " has the fix."; return }
	if (src == "package") { LABEL = "CHECK"; NOTE = "Installed from distribution packages. Update them and rebuild; distributions backport fixes, so their security notice says which build has it."; return }
	if (src == "source") { LABEL = "CHECK"; NOTE = "Built from source. Check which " br " release the build downloads; " fx " has the fix."; return }
	LABEL = "CHECK"; NOTE = "Third-party image. It gets the fix when its maintainer rebuilds it; run php -v inside it."
}
function eol(br, src) {
	LABEL = "EOL"
	NOTE = "PHP " br " is past end of life and gets no official fix."
	if (src == "official") NOTE = NOTE " This tag is no longer rebuilt."
	if (src == "package") NOTE = NOTE " Some distributions still patch their own builds; check yours."
	NOTE = NOTE " Move to " LOWEST " or newer."
}
function judgerequire(c,   low, v) {
	low = ""
	while (match(c, /[0-9]+(\.[0-9]+)*/)) {
		v = branchof(substr(c, RSTART, RLENGTH))
		c = substr(c, RSTART + RLENGTH)
		if (parts(v) == 1) v = v ".0"
		if (low == "" || vcmp(v, low) < 0) low = v
	}
	LABEL = "NOTE"
	if (low == "") NOTE = "The code sets no lowest PHP version."
	else if (vcmp(low, LOWEST) < 0) NOTE = "The code still declares support for PHP " low ", which is past end of life."
	else NOTE = "The code declares support from PHP " low "."
}

function add(path, ln, what, ver, src, digest) {
	judge(ver, src, digest)
	if (LABEL != "EOL" && JBR in UNTIL && substr(UNTIL[JBR], 1, 4) == substr(ASOF, 1, 4))
		NOTE = NOTE " PHP " JBR " gets security fixes only until " day(UNTIL[JBR]) "."
	N++
	RF[N] = path; RL[N] = ln; RW[N] = what; RB[N] = LABEL; RN[N] = NOTE; RK[N] = rank(LABEL)
	SEEN[path] = 1
}
function rank(l) { return l == "EOL" ? 1 : l == "UPDATE" ? 2 : l == "REBUILD" ? 3 : l == "CHECK" ? 4 : l == "OK" ? 5 : 6 }

# One image reference, from FROM, image:, container: or docker://.
function image(path, ln, ref,   r, digest, i, j, k, c, name, low, tag, ver, src, wp) {
	r = resolve(unquote(ref))
	sub(/^docker:\/\//, "", r)
	digest = 0
	i = index(r, "@")
	if (i) { digest = 1; r = substr(r, 1, i - 1) }
	# The tag follows the last colon, unless that colon is a registry port.
	name = r; tag = ""
	i = 0; j = 0
	for (k = 1; k <= length(r); k++) { c = substr(r, k, 1); if (c == ":") i = k; else if (c == "/") j = k }
	if (i > j) { name = substr(r, 1, i - 1); tag = substr(r, i + 1) }
	low = tolower(name)
	sub(/^(docker\.io|index\.docker\.io|registry-1\.docker\.io)\//, "", low)
	sub(/^library\//, "", low)
	if (index(low, "${")) return
	if (low ~ /^sail-[0-9]/) return
	# Helper images that copy files into a build and run no PHP.
	if (low ~ /(^|\/)php-extension-installer$/) return
	if (low == "php" || low == "wordpress") src = "official"
	else if (low ~ /php/ || low ~ /(^|\/)(wordpress|drupal|joomla|nextcloud|mediawiki|matomo|friendica|yourls|postfixadmin|composer)$/) src = "other"
	else return
	if (index(tag, "${")) { add(path, ln, r, "", "variable", 0); return }
	if (low == "php") ver = leadver(tag)
	else if (match(tag, /php[0-9]+(\.[0-9]+)*/)) ver = leadver(substr(tag, RSTART + 3, RLENGTH - 3))
	else if (match(low, /php[0-9][0-9]/)) ver = substr(low, RSTART + 3, 1) "." substr(low, RSTART + 4, 1)
	else if (low ~ /php/ && low !~ /(^|\/)php(my|pg)admin$/) ver = leadver(tag)
	else ver = ""
	# The leading number of a third-party tag is a PHP version only if it looks like one.
	if (src == "other" && ver != "" && ver + 0 != 5 && ver + 0 != 7 && int(ver + 0) != 8) ver = ""
	if (src == "official" && match(tag, /(alpine[0-9]+\.[0-9]+|bookworm|bullseye|buster|stretch|jessie|trixie)/)) {
		OLDOS = substr(tag, RSTART, RLENGTH)
		if (!(OLDOS in OSOK)) src = "oldos"
	}
	if (low == "wordpress" && tag ~ /^[0-9]/) {
		OLDWP = leadver(tag)
		wp = WPLATEST "."
		if (index(wp, OLDWP ".") != 1) src = "oldwp"
	}
	add(path, ln, r (digest ? "@sha256:..." : ""), ver, src, digest)
}

function scanfile(path,   base, kind, line, ln) {
	base = path; sub(/.*\//, "", base)
	if (base == "composer.json") kind = "composer"
	else if (base ~ /^(Dockerfile|Containerfile)/ || base ~ /\.[Dd]ockerfile$/) kind = "docker"
	else if (base == ".php-version") kind = "phpversion"
	else if (base == ".tool-versions") kind = "toolversions"
	else if (base == "mise.toml" || base == ".mise.toml") kind = "mise"
	else if (base == "devcontainer.json" || base == ".devcontainer.json") kind = "devcontainer"
	else kind = "yaml"
	split("", args); split("", stages); split("", packages)
	inrun = 0
	workflow = (path ~ /(^|\/)\.(github|forgejo|gitea)\/workflows\//)
	ddev = (path ~ /(^|\/)\.ddev\/config[^\/]*\.ya?ml$/)
	lando = (base ~ /^\.lando(\.[^\/]*)?\.ya?ml$/)
	inlist = 0; done = 0
	# composer.json is read as JSON, character by character.
	depth = 0; instr = 0; esc = 0; buf = ""; pending = ""; key = ""; expect = 0
	ln = 0
	while ((getline line < path) > 0) {
		ln++
		sub(/\r$/, "", line)
		if (kind == "composer") json(path, ln, line)
		else if (kind == "docker") dockerline(path, ln, line)
		else if (kind == "yaml") yamlline(path, ln, line)
		else if (kind == "devcontainer") devcontainerline(path, ln, line)
		else if (!done) otherline(path, ln, line, kind)
	}
	close(path)
}

function dockerline(path, ln, L,   t, i, n, w, k, j, img) {
	# A RUN instruction runs on over lines that end in a backslash.
	if (L ~ /^[ \t]*[Rr][Uu][Nn][ \t]/) inrun = 1
	if (inrun) {
		packageline(path, ln, L)
		if (L !~ /\\[ \t]*$/) inrun = 0
		return
	}
	if (L ~ /^[ \t]*[Ee][Nn][Vv][ \t]+PHP_VERSION[ \t=]/) {
		t = L; sub(/^[ \t]*[Ee][Nn][Vv][ \t]+PHP_VERSION[ \t=]+/, "", t)
		sub(/[ \t].*$/, "", t)
		t = resolve(noquotes(t))
		if (index(t, "${")) add(path, ln, "ENV PHP_VERSION " t, "", "variable", 0)
		else if (leadver(t) != "") add(path, ln, "ENV PHP_VERSION " t, leadver(t), "source", 0)
		return
	}
	if (L ~ /^[ \t]*[Aa][Rr][Gg][ \t]+[A-Za-z_][A-Za-z0-9_]*=/) {
		t = L; sub(/^[ \t]*[Aa][Rr][Gg][ \t]+/, "", t)
		i = index(t, "=")
		args[substr(t, 1, i - 1)] = unquote(substr(t, i + 1))
		return
	}
	if (L !~ /^[ \t]*[Ff][Rr][Oo][Mm][ \t]/) return
	t = L; sub(/^[ \t]+/, "", t)
	n = split(t, w, "[ \t]+")
	k = 2
	while (k <= n && w[k] ~ /^--/) k++
	if (k > n) return
	img = w[k]
	if (!(tolower(img) in stages)) image(path, ln, img)
	for (j = k + 1; j < n; j++) if (tolower(w[j]) == "as") stages[tolower(w[j + 1])] = 1
}

# PHP from distribution packages: php8.3-cli on Debian and Ubuntu, php83-fpm
# on Alpine. One pin per branch per file, at the first line that names it.
function packageline(path, ln, L,   w, n, i, tok, br) {
	n = split(L, w, "[ \t]+")
	for (i = 1; i <= n; i++) {
		tok = noquotes(w[i])
		sub(/[;,&|)]+$/, "", tok)
		br = ""
		if (tok ~ /^php[5-8]\.[0-9]+(-[a-z0-9]+)?$/) { br = substr(tok, 4); sub(/-.*$/, "", br) }
		else if (tok ~ /^php[5-8][0-9](-[a-z0-9]+)?$/) br = substr(tok, 4, 1) "." substr(tok, 5, 1)
		if (br == "" || br in packages) continue
		packages[br] = 1
		add(path, ln, "package " tok, br, "package", 0)
	}
}

function devcontainerline(path, ln, L,   t) {
	if (!match(L, /"image"[ \t]*:[ \t]*"[^"]+"/)) return
	t = substr(L, RSTART, RLENGTH)
	sub(/^"image"[ \t]*:[ \t]*"/, "", t); sub(/"$/, "", t)
	image(path, ln, t)
}

function yamlline(path, ln, L,   v, t) {
	if (L ~ /^[ \t]*#/) return
	if (match(L, /^[ \t]*(-[ \t]+)?(image|container):[ \t]*[^ \t]/)) {
		v = L; sub(/^[ \t]*(-[ \t]+)?(image|container):[ \t]*/, "", v)
		v = unquote(v)
		if (v !~ /^[{|>&*]/ && v != "") image(path, ln, v)
	}
	if (match(L, DOCKERURI)) image(path, ln, substr(L, RSTART, RLENGTH))
	if (match(L, TYPEPHP)) {
		t = noquotes(substr(L, RSTART)); sub(/^type:[ \t]*php:/, "", t)
		t = leadver(t)
		if (t != "") add(path, ln, "type: php:" t, t, "platform", 0)
	}
	if (match(L, /sail\/runtimes\/[0-9]+\.[0-9]+/)) {
		t = substr(L, RSTART + 14, RLENGTH - 14)
		add(path, ln, "Sail runtime " t, t, "sail", 0)
	}
	if (ddev && L ~ /^[ \t]*php_version:/) {
		t = L; sub(/^[ \t]*php_version:/, "", t); t = noquotes(unquote(t))
		if (leadver(t) != "") add(path, ln, "php_version " t, leadver(t), "ddev", 0)
	}
	if (lando && L ~ /^[ \t]+php:[ \t]*[^ \t]/) {
		t = L; sub(/^[ \t]+php:/, "", t); t = noquotes(unquote(t))
		if (leadver(t) != "") add(path, ln, "php " t, leadver(t), "lando", 0)
	}
	if (workflow) workflowline(path, ln, L)
}

# GitHub Actions: setup-php php-version, and matrix keys such as php,
# php-version and php-versions, inline [8.2, 8.3] or as a list below the key.
function workflowline(path, ln, L,   v) {
	if (match(L, PHPKEY)) {
		v = unquote(substr(L, RLENGTH + 1))
		inlist = (v == "")
		if (v ~ /^\[/) versionlist(path, ln, v)
		else if (leadver(noquotes(v)) != "") add(path, ln, "php-version " noquotes(v), leadver(noquotes(v)), "ci", 0)
		return
	}
	if (inlist && L ~ /^[ \t]*-[ \t]*[^ \t]/) {
		v = L; sub(/^[ \t]*-[ \t]*/, "", v); v = noquotes(unquote(v))
		if (leadver(v) != "") add(path, ln, "php-version " v, leadver(v), "ci", 0)
		return
	}
	if (L !~ /^[ \t]*$/) inlist = 0
}
# add() runs match() too, so take the rest of the list before calling it.
function versionlist(path, ln, v,   t) {
	while (match(v, /[0-9]+(\.[0-9]+)*/)) {
		t = substr(v, RSTART, RLENGTH)
		v = substr(v, RSTART + RLENGTH)
		add(path, ln, "php-version " t, leadver(t), "ci", 0)
	}
}

function otherline(path, ln, L, kind,   t) {
	if (kind == "phpversion") {
		t = noquotes(unquote(L))
		if (leadver(t) != "") { add(path, ln, t, leadver(t), "local", 0); done = 1 }
	} else if (kind == "toolversions") {
		if (L ~ /^[ \t]*php[ \t]+[0-9]/) {
			t = L; sub(/^[ \t]*php[ \t]+/, "", t); sub(/[ \t].*$/, "", t)
			add(path, ln, "php " t, leadver(t), "local", 0); done = 1
		}
	} else if (L ~ /^[ \t]*"?php"?[ \t]*=/) {
		t = L; sub(/^[ \t]*"?php"?[ \t]*=/, "", t); t = noquotes(unquote(t))
		if (leadver(t) != "") { add(path, ln, "php = " t, leadver(t), "local", 0); done = 1 }
	}
}

# A small JSON reader: enough to know the key path of each string value,
# so "php" under require and under config.platform can be told apart.
function json(path, ln, L,   i, c, n) {
	n = length(L)
	for (i = 1; i <= n; i++) {
		c = substr(L, i, 1)
		if (instr) {
			if (esc) { esc = 0; buf = buf c }
			else if (c == "\\") esc = 1
			else if (c == "\"") {
				instr = 0
				if (expect) { jsonvalue(path, ln, buf); expect = 0 }
				else pending = buf
			} else buf = buf c
			continue
		}
		if (c == "\"") { instr = 1; buf = "" }
		else if (c == ":") { if (pending != "") { key = pending; pending = ""; expect = 1 } }
		else if (c == "{" || c == "[") { depth++; stack[depth] = expect ? key : ""; expect = 0 }
		else if (c == "}" || c == "]") { if (depth > 0) depth--; expect = 0 }
		else if (c == ",") { expect = 0; pending = "" }
	}
}
function jsonvalue(path, ln, v) {
	if (key != "php") return
	if (depth == 2 && stack[2] == "require") add(path, ln, "require php " v, v, "require", 0)
	else if (depth == 3 && stack[3] == "platform" && stack[2] == "config") add(path, ln, "platform php " v, leadver(v), "composer", 0)
}

function pad(s, w) { return w > length(s) ? s sprintf("%" (w - length(s)) "s", "") : s }
function paint(l, s) {
	if (!COLOR) return s
	return sprintf("%c[%sm%s%c[0m", 27, (l == "EOL" || l == "UPDATE") ? "31;1" : (l == "OK") ? "32" : (l == "NOTE") ? "2" : "33", s, 27)
}

BEGIN {
	SQ = sprintf("%c", 39)
	QUOTES = "[\"" SQ "]"
	DOCKERURI = "docker://[^ \t\"" SQ "]+"
	TYPEPHP = "type:[ \t]*[\"" SQ "]?php:[0-9]"
	PHPKEY = "^[ \t]*(-[ \t]+)?php([-_]versions?)?:[ \t]*"
	n = split(UNTILS, f, " ")
	for (i = 1; i <= n; i++) { split(f[i], kv, "="); UNTIL[kv[1]] = kv[2] }
	n = split(OS, f, " ")
	CURRENTOS = ""
	for (i = 1; i <= n; i++) { OSOK[f[i]] = 1; CURRENTOS = f[i] (CURRENTOS == "" ? "" : ", ") CURRENTOS }
	n = split(FIXED, f, " ")
	for (i = 1; i <= n; i++) {
		b = branchof(f[i]); FIX[b] = f[i]
		if (LOWEST == "" || vcmp(b, LOWEST) < 0) LOWEST = b
		if (NEWEST == "" || vcmp(b, NEWEST) > 0) NEWEST = b
	}
	LOWMAJOR = LOWEST + 0; NEWMAJOR = NEWEST + 0
	LOWMAJOR = int(LOWMAJOR); NEWMAJOR = int(NEWMAJOR)
	N = 0
}
{ scanfile($0) }
END {
	if (N == 0) { print "  No PHP version pins found."; exit }
	for (i = 1; i <= N; i++) {
		p = RF[i]
		if (ROOT == ".") sub(/^\.\//, "", p)
		else if (index(p, ROOT "/") == 1) p = substr(p, length(ROOT) + 2)
		sub(/^\/+/, "", p)
		RF[i] = p
	}
	# Worst first, then by file and line.
	for (i = 2; i <= N; i++) {
		for (j = i; j > 1; j--) {
			a = j - 1
			if (RK[a] < RK[j] || (RK[a] == RK[j] && (RF[a] < RF[j] || (RF[a] == RF[j] && RL[a] + 0 <= RL[j] + 0)))) break
			t = RF[a]; RF[a] = RF[j]; RF[j] = t
			t = RL[a]; RL[a] = RL[j]; RL[j] = t
			t = RW[a]; RW[a] = RW[j]; RW[j] = t
			t = RB[a]; RB[a] = RB[j]; RB[j] = t
			t = RN[a]; RN[a] = RN[j]; RN[j] = t
			t = RK[a]; RK[a] = RK[j]; RK[j] = t
		}
	}
	wl = 0; ww = 0
	for (i = 1; i <= N; i++) {
		LOC[i] = RF[i] ":" RL[i]
		if (length(LOC[i]) > wl) wl = length(LOC[i])
		if (length(RW[i]) > ww) ww = length(RW[i])
		COUNT[RB[i]]++
	}
	if (wl > 44) wl = 44
	if (ww > 36) ww = 36
	# A note repeated in many files (one composer.json per package in a
	# monorepo) prints once, with the count; anything to act on prints per pin.
	for (i = 1; i <= N; i++) if (RB[i] == "NOTE") SAME[RW[i] SUBSEP RN[i]]++
	for (i = 1; i <= N; i++) {
		note = RN[i]
		if (RB[i] == "NOTE") {
			k = RW[i] SUBSEP RN[i]
			if (k in SHOWN) continue
			SHOWN[k] = 1
			if (SAME[k] > 1) note = note " Same in " (SAME[k] - 1) " more " (SAME[k] == 2 ? "file." : "files.")
		}
		print "  " paint(RB[i], pad(RB[i], 7)) "  " pad(LOC[i], wl) "  " pad(RW[i], ww) "  " note
	}
	files = 0
	for (p in SEEN) files++
	s = ""
	if (COUNT["EOL"]) s = s ", " COUNT["EOL"] " end of life"
	if (COUNT["UPDATE"]) s = s ", " COUNT["UPDATE"] " to update"
	if (COUNT["REBUILD"]) s = s ", " COUNT["REBUILD"] " to rebuild"
	if (COUNT["CHECK"]) s = s ", " COUNT["CHECK"] " to check"
	if (COUNT["OK"]) s = s ", " COUNT["OK"] " ok"
	if (COUNT["NOTE"]) s = s ", " COUNT["NOTE"] (COUNT["NOTE"] == 1 ? " note" : " notes")
	print ""
	print "  " N (N == 1 ? " pin" : " pins") " in " files (files == 1 ? " file" : " files") ": " substr(s, 3)
}
'

printf 'PHP pin finder (arvion.ai/tools/php-pins). PHP2Shell data as of %s.\n' "$DATA_AS_OF"
rc=0
for root in "$@"; do
	if [ ! -d "$root" ]; then
		printf '\n%s: not a folder\n' "$root" >&2
		rc=1
		continue
	fi
	printf '\n%s\n' "$root"
	find "$root" \( -name .git -o -name node_modules -o -name vendor \) -prune -o -type f -size -2048 \( \
		-name Dockerfile -o -name 'Dockerfile.*' -o -name '*.Dockerfile' -o -name '*.dockerfile' -o -name Containerfile -o \
		-name '*.yml' -o -name '*.yaml' -o -name composer.json -o -name .php-version -o -name .tool-versions -o \
		-name mise.toml -o -name .mise.toml -o -name devcontainer.json -o -name .devcontainer.json \) -print |
		LC_ALL=C sort |
		LC_ALL=C awk -v FIXED="$FIXED" -v UNTILS="$SECURITY_UNTIL" -v FIXEDON="$IMAGES_FIXED_ON" -v OS="$IMAGE_OS" \
			-v WPLATEST="$WORDPRESS_LATEST" -v ASOF="$DATA_AS_OF" -v ROOT="${root%/}" -v COLOR="$color" "$prog"
done
printf '\nPHP2Shell fixed releases: %s. What each line means: https://arvion.ai/tools/php-pins\n' "$(printf '%s' "$FIXED" | sed 's/ /, /g')"
exit "$rc"

# MIT License
#
# Copyright (c) 2026 Arvion
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
