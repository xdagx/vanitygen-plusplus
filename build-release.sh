#!/usr/bin/env bash
#
# build-release.sh - cross-compile release binaries with Zig.
#
# Builds vanitygen++, oclvanitygen++ and keyconv for Linux, Windows and macOS
# from one x86_64 Linux host. Zig is the C cross-compiler; OpenSSL (libcrypto)
# and PCRE are built from source as static libraries for every target. OpenCL
# is linked against a stub/import library, the real driver (libOpenCL.so.1,
# OpenCL.dll, OpenCL.framework) is picked up at runtime.
#
# Usage:   ./build-release.sh [target ...]
# Targets: linux-x86_64 linux-arm64 windows-x86_64 macos-x86_64 macos-arm64
#          (default: all of them)
#
# Downloads and per-target libraries are cached in .deps/, archives are
# written to dist/.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPS=${DEPS:-$ROOT/.deps}
DIST=${DIST:-$ROOT/dist}
JOBS=${JOBS:-$(nproc)}

ZIG_VERSION=0.16.0
ZIG_SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
PCRE_VERSION=8.45
PCRE_SHA256=4dae6fdcd2bb0bb6c37b5f97c33c2be954da743985369cddac3546e3218bffb8
OPENCL_HEADERS_VERSION=2026.05.29
OPENCL_HEADERS_SHA256=d9e6c48357de5002da11ce45de600e0c3ffe6ab4f628a3b9fe2b38603161658a

ALL_TARGETS="linux-x86_64 linux-arm64 windows-x86_64 macos-x86_64 macos-arm64"

ZIG=$DEPS/zig-$ZIG_VERSION/zig

VANITYGEN_SRCS="vanitygen.c pattern.c util.c groestl.c sha3.c ed25519.c stellar.c
	base32.c crc16.c simplevanitygen.c bech32.c segwit_addr.c"
OCLVANITYGEN_SRCS="oclvanitygen.c oclengine.c pattern.c util.c groestl.c sha3.c
	ocled25519engine.c oclvanitygen_ed25519.c stellar.c base32.c crc16.c compat.c"
KEYCONV_SRCS="keyconv.c util.c groestl.c sha3.c"

PCRE_SRCS="pcre_byte_order.c pcre_chartables.c pcre_compile.c pcre_config.c
	pcre_dfa_exec.c pcre_exec.c pcre_fullinfo.c pcre_get.c pcre_globals.c
	pcre_jit_compile.c pcre_maketables.c pcre_newline.c pcre_ord2utf8.c
	pcre_refcount.c pcre_string_utils.c pcre_study.c pcre_tables.c pcre_ucd.c
	pcre_valid_utf8.c pcre_version.c pcre_xclass.c"

# Files shipped next to the binaries: OpenCL kernels are loaded from the
# current directory at runtime, base58prefix.txt is read by "-C <coin>".
RUNTIME_FILES="calc_addrs.cl calc_addrs_ed25519.cl precomp_data_ocl.h
	base58prefix.txt README.md LICENSE"

log() { printf '\n==> %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

fetch() { # <url> <file> <sha256>
	local out=$DEPS/src/$2
	if [ ! -f "$out" ]; then
		log "Downloading $2"
		curl -fSL --retry 3 -o "$out.part" "$1"
		mv "$out.part" "$out"
	fi
	echo "$3  $out" | sha256sum -c --quiet - || die "checksum mismatch: $out"
}

setup_common() {
	mkdir -p "$DEPS/src" "$DEPS/build" "$DIST"
	[ "$(uname -s)-$(uname -m)" = "Linux-x86_64" ] ||
		die "this script must run on x86_64 Linux"

	fetch "https://ziglang.org/download/$ZIG_VERSION/zig-x86_64-linux-$ZIG_VERSION.tar.xz" \
		"zig-x86_64-linux-$ZIG_VERSION.tar.xz" "$ZIG_SHA256"
	fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
		"openssl-$OPENSSL_VERSION.tar.gz" "$OPENSSL_SHA256"
	fetch "https://sourceforge.net/projects/pcre/files/pcre/$PCRE_VERSION/pcre-$PCRE_VERSION.tar.bz2/download" \
		"pcre-$PCRE_VERSION.tar.bz2" "$PCRE_SHA256"
	fetch "https://github.com/KhronosGroup/OpenCL-Headers/archive/refs/tags/v$OPENCL_HEADERS_VERSION.tar.gz" \
		"OpenCL-Headers-$OPENCL_HEADERS_VERSION.tar.gz" "$OPENCL_HEADERS_SHA256"

	if [ ! -x "$ZIG" ]; then
		tar xJf "$DEPS/src/zig-x86_64-linux-$ZIG_VERSION.tar.xz" -C "$DEPS"
		mv "$DEPS/zig-x86_64-linux-$ZIG_VERSION" "$DEPS/zig-$ZIG_VERSION"
	fi

	# OpenCL headers, also reachable as <OpenCL/...> for macOS sources
	local ocl=$DEPS/opencl-$OPENCL_HEADERS_VERSION
	if [ ! -f "$ocl/functions.txt" ]; then
		rm -rf "$ocl" && mkdir -p "$ocl/include"
		tar xzf "$DEPS/src/OpenCL-Headers-$OPENCL_HEADERS_VERSION.tar.gz" \
			-C "$ocl" --strip-components=1 "OpenCL-Headers-$OPENCL_HEADERS_VERSION/CL"
		mv "$ocl/CL" "$ocl/include/CL"
		cp -r "$ocl/include/CL" "$ocl/include/OpenCL"
		# Every API function, used to generate the link stubs
		grep -oE '^cl[A-Za-z0-9_]+\(' "$ocl/include/CL/cl.h" | tr -d '(' |
			sort -u > "$ocl/functions.txt"
	fi
	OPENCL_DIR=$ocl
}

configure_target() {
	T=$1
	EXE=
	case $T in
	linux-x86_64)   ZT=x86_64-linux-gnu.2.17;  OSSL_TARGET=linux-x86_64 ;;
	linux-arm64)    ZT=aarch64-linux-gnu.2.17; OSSL_TARGET=linux-aarch64 ;;
	windows-x86_64) ZT=x86_64-windows-gnu;     OSSL_TARGET=mingw64; EXE=.exe ;;
	macos-x86_64)   ZT=x86_64-macos.11.0;      OSSL_TARGET=darwin64-x86_64-cc ;;
	macos-arm64)    ZT=aarch64-macos.11.0;     OSSL_TARGET=darwin64-arm64-cc ;;
	*) die "unknown target '$T' (valid: $ALL_TARGETS)" ;;
	esac
	OS=${T%%-*}
	PREFIX=$DEPS/$T
	BUILD=$DEPS/build/$T
	CC=$PREFIX/bin/cc
	AR=$PREFIX/bin/ar
	RANLIB=$PREFIX/bin/ranlib
	mkdir -p "$PREFIX/bin" "$PREFIX/include" "$PREFIX/lib" "$BUILD"

	# Tool wrappers, so that build systems see plain "cc"/"ar"/"ranlib".
	# OpenSSL passes "-arch <arch>" on macOS, the target already says it.
	cat > "$CC" <<-EOF
	#!/usr/bin/env bash
	args=()
	while [ \$# -gt 0 ]; do
		case \$1 in
		-arch) shift ;;
		*) args+=("\$1") ;;
		esac
		shift
	done
	exec "$ZIG" cc -target $ZT "\${args[@]}"
	EOF
	printf '#!/bin/sh\nexec "%s" ar "$@"\n' "$ZIG" > "$AR"
	printf '#!/bin/sh\nexec "%s" ranlib "$@"\n' "$ZIG" > "$RANLIB"
	chmod +x "$CC" "$AR" "$RANLIB"
}

build_openssl() {
	[ -f "$PREFIX/lib/libcrypto.a" ] && return 0
	log "[$T] Building OpenSSL $OPENSSL_VERSION"
	local src=$BUILD/openssl-$OPENSSL_VERSION
	rm -rf "$src"
	tar xzf "$DEPS/src/openssl-$OPENSSL_VERSION.tar.gz" -C "$BUILD"
	(
		cd "$src"
		CC=$CC AR=$AR RANLIB=$RANLIB ./Configure "$OSSL_TARGET" \
			no-shared no-module no-apps no-tests no-docs \
			--prefix="$PREFIX" --libdir=lib
		make -j"$JOBS" build_libs
		make install_dev
	) > "$BUILD/openssl.log" 2>&1 || die "OpenSSL build failed, see $BUILD/openssl.log"
	rm -rf "$src"
}

build_pcre() {
	[ -f "$PREFIX/lib/libpcre.a" ] && return 0
	log "[$T] Building PCRE $PCRE_VERSION"
	local src=$BUILD/pcre-$PCRE_VERSION f
	rm -rf "$src"
	tar xjf "$DEPS/src/pcre-$PCRE_VERSION.tar.bz2" -C "$BUILD"
	(
		cd "$src"
		cp pcre.h.generic pcre.h
		cp pcre_chartables.c.dist pcre_chartables.c
		{
			cat config.h.generic
			printf '#define %s 1\n' SUPPORT_PCRE8 SUPPORT_UTF SUPPORT_UCP \
				HAVE_STDINT_H HAVE_INTTYPES_H HAVE_MEMMOVE HAVE_STRERROR
		} > config.h
		for f in $PCRE_SRCS; do
			"$CC" -O2 -DHAVE_CONFIG_H -DPCRE_STATIC -I. -c "$f" -o "${f%.c}.o"
		done
		rm -f libpcre.a
		"$AR" rcs libpcre.a $(for f in $PCRE_SRCS; do echo "${f%.c}.o"; done)
	) > "$BUILD/pcre.log" 2>&1 || die "PCRE build failed, see $BUILD/pcre.log"
	cp "$src/pcre.h" "$PREFIX/include/"
	cp "$src/libpcre.a" "$PREFIX/lib/"
	rm -rf "$src"
}

# Link-time stand-in for the system OpenCL library
build_opencl_stub() {
	local fns=$OPENCL_DIR/functions.txt
	case $OS in
	linux)
		[ -f "$PREFIX/lib/libOpenCL.so" ] && return 0
		sed 's/.*/void &(void) {}/' "$fns" > "$BUILD/opencl_stub.c"
		"$CC" -shared -fPIC -Wl,-soname,libOpenCL.so.1 \
			-o "$PREFIX/lib/libOpenCL.so" "$BUILD/opencl_stub.c"
		;;
	windows)
		[ -f "$PREFIX/lib/libOpenCL.a" ] && return 0
		{ echo "LIBRARY OpenCL.dll"; echo "EXPORTS"; cat "$fns"; } > "$BUILD/OpenCL.def"
		"$ZIG" dlltool -m i386:x86-64 -d "$BUILD/OpenCL.def" -l "$PREFIX/lib/libOpenCL.a"
		;;
	macos)
		local fw=$PREFIX/frameworks/OpenCL.framework
		[ -f "$fw/OpenCL.tbd" ] && return 0
		mkdir -p "$fw"
		{
			echo '--- !tapi-tbd'
			echo 'tbd-version:     4'
			echo 'targets:         [ x86_64-macos, arm64-macos ]'
			echo "install-name:    '/System/Library/Frameworks/OpenCL.framework/Versions/A/OpenCL'"
			echo 'exports:'
			echo '  - targets:         [ x86_64-macos, arm64-macos ]'
			echo "    symbols:         [ $(sed 's/^/_/' "$fns" | paste -sd, - | sed 's/,/, /g') ]"
			echo '...'
		} > "$fw/OpenCL.tbd"
		;;
	esac
}

build_programs() {
	log "[$T] Building vanitygen++, oclvanitygen++, keyconv"
	local out=$BUILD/bin
	local cflags="-O3 -Wall -Wno-deprecated-declarations -DPCRE_STATIC
		-DCL_TARGET_OPENCL_VERSION=120 -I$PREFIX/include -I$OPENCL_DIR/include"
	local libs="-L$PREFIX/lib -lpcre -lcrypto"
	local ocl_libs extra=
	case $OS in
	linux)
		libs="$libs -lpthread -ldl -lm"
		ocl_libs="-lOpenCL"
		;;
	windows)
		extra=winglue.c
		libs="$libs -lpthread -lws2_32 -lcrypt32 -lgdi32 -ladvapi32 -luser32 -lbcrypt"
		ocl_libs="-lOpenCL"
		;;
	macos)
		libs="$libs -lpthread -lm"
		ocl_libs="-F$PREFIX/frameworks -framework OpenCL"
		;;
	esac
	rm -rf "$out" && mkdir -p "$out"
	(
		cd "$ROOT"
		"$CC" $cflags -s -o "$out/vanitygen++$EXE" $VANITYGEN_SRCS $extra $libs
		"$CC" $cflags -s -o "$out/oclvanitygen++$EXE" $OCLVANITYGEN_SRCS $extra $libs $ocl_libs
		"$CC" $cflags -s -o "$out/keyconv$EXE" $KEYCONV_SRCS $extra $libs
	) 2>&1 | tee "$BUILD/programs.log" | grep -E 'error|undefined' >&2 || true
	for f in vanitygen++ oclvanitygen++ keyconv; do
		[ -f "$out/$f$EXE" ] || die "$f$EXE was not built, see $BUILD/programs.log"
	done
}

package() {
	local name=vanitygen-plusplus-$T
	local stage=$BUILD/$name f
	rm -rf "$stage" && mkdir -p "$stage"
	for f in vanitygen++ oclvanitygen++ keyconv; do
		cp "$BUILD/bin/$f$EXE" "$stage/"
	done
	(cd "$ROOT" && cp $RUNTIME_FILES "$stage/")
	if [ "$OS" = windows ]; then
		rm -f "$DIST/$name.zip"
		(cd "$BUILD" && python3 -m zipfile -c "$DIST/$name.zip" "$name")
		log "[$T] $DIST/$name.zip"
	else
		tar czf "$DIST/$name.tar.gz" -C "$BUILD" "$name"
		log "[$T] $DIST/$name.tar.gz"
	fi
}

main() {
	local targets=${*:-$ALL_TARGETS} t
	setup_common
	for t in $targets; do
		configure_target "$t"
		build_openssl
		build_pcre
		build_opencl_stub
		build_programs
		package
	done
	(cd "$DIST" && sha256sum vanitygen-plusplus-*.tar.gz vanitygen-plusplus-*.zip \
		2>/dev/null > SHA256SUMS) || true
	log "Done, archives are in $DIST"
}

main "$@"
