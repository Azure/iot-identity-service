# cargo install --force bindgen
BINDGEN = bindgen

# On some distros like Raspbian 10, libclang has issues parsing the default /usr/include/limits.h
# On such distros, set this to a directory with a working limits.h,
# such as /usr/lib/gcc/arm-linux-gnueabihf/8/include-fixed/
BINDGEN_EXTRA_INCLUDE_DIR =

CARGO = cargo

# cargo install --force cbindgen
CBINDGEN = cbindgen

# 0 => false, _ => true
V = 0

# 0 => false, _ => true
RELEASE = 0

# '' => amd64, 'arm32v7' => arm32v7, 'aarch64' => aarch64
ARCH =


ifneq ($(BINDGEN_EXTRA_INCLUDE_DIR), )
	BINDGEN_EXTRA_FLAGS = -isystem $(BINDGEN_EXTRA_INCLUDE_DIR)
endif

ifeq ($(V), 0)
	BINDGEN_VERBOSE =
	CARGO_VERBOSE = --quiet
	CBINDGEN_VERBOSE = --quiet
else
	BINDGEN_VERBOSE = --verbose
	CARGO_VERBOSE = --verbose
	CBINDGEN_VERBOSE =
endif

ifeq ($(RELEASE), 0)
	CARGO_PROFILE =
	CARGO_PROFILE_DIRECTORY = debug
else
	CARGO_PROFILE = --release
	CARGO_PROFILE_DIRECTORY = release
endif

ifeq ($(ARCH), arm32v7)
	CARGO_TARGET = armv7-unknown-linux-gnueabihf
	DPKG_ARCH_FLAGS = --host-arch armhf
else ifeq ($(ARCH), aarch64)
	CARGO_TARGET = aarch64-unknown-linux-gnu
	DPKG_ARCH_FLAGS = --host-arch arm64 --host-type aarch64-linux-gnu --target-type aarch64-linux-gnu
else
	CARGO_TARGET = x86_64-unknown-linux-gnu
	DPKG_ARCH_FLAGS =
endif


# Some of the targets use bash-isms like `set -o pipefail`
SHELL := /bin/bash


.PHONY: clean default iotedged pkcs11-test test
.PHONY: deb dist install-common install-deb install-rpm rpm


default:
	cd key/aziot-keys/ && $(CBINDGEN) --config cbindgen.toml --output aziot-keys.h.tmp $(CBINDGEN_VERBOSE)
	cp key/aziot-keys/cbindgen.prelude.h key/aziot-keys/aziot-keys.h.new
	< key/aziot-keys/aziot-keys.h.tmp grep -v 'cbindgen_unused_' >> key/aziot-keys/aziot-keys.h.new
	$(RM) key/aziot-keys/aziot-keys.h.tmp
	if ! diff -q key/aziot-keys/aziot-keys.h key/aziot-keys/aziot-keys.h.new; then \
		mv key/aziot-keys/aziot-keys.h.new key/aziot-keys/aziot-keys.h; \
		$(RM) key/aziot-keyd/src/keys.generated.rs; \
	else \
		$(RM) key/aziot-keys/aziot-keys.h.new; \
	fi
	if ! [ -f key/aziot-keyd/src/keys.generated.rs ]; then \
		$(BINDGEN) \
			--blacklist-type '__.*' \
			--whitelist-function 'aziot_keys_.*' \
			--whitelist-type 'AZIOT_KEYS_.*' \
			--whitelist-var 'AZIOT_KEYS_.*' \
			-o key/aziot-keyd/src/keys.generated.rs.tmp \
			$(BINDGEN_VERBOSE) \
			key/aziot-keys/aziot-keys.h \
			-- \
			$(BINDGEN_EXTRA_FLAGS); \
		mv key/aziot-keyd/src/keys.generated.rs.tmp key/aziot-keyd/src/keys.generated.rs; \
	fi
	$(CARGO) build \
		-p aziot \
		-p aziot-certd \
		-p aziot-identityd \
		-p aziot-keyd \
		-p aziot-key-openssl-engine-shared \
		-p aziot-keys \
		$(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)


clean:
	$(CARGO) clean $(CARGO_VERBOSE)
	$(RM) key/aziot-keyd/src/keys.generated.rs
	$(RM) key/aziot-keys/aziot-keys.h

iotedged:
	$(CARGO) build -p iotedged $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)


pkcs11-test:
	$(CARGO) build -p pkcs11-test $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)


test: default iotedged pkcs11-test
test:
	set -o pipefail; \
	$(CARGO) test --all --exclude aziot-key-openssl-engine-shared \
		$(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE) 2>&1 | \
		grep -v 'running 0 tests' | grep -v '0 passed; 0 failed' | grep '.'

	find . -name '*.rs' | \
		grep -v '^\./target/' | \
		grep -v '\.generated\.rs$$' | \
		grep -E '/(build|lib|main|(examples|tests)/[^/]+)\.rs$$' | \
		while read -r f; do \
			if ! grep -Eq '^#!\[deny\(rust_2018_idioms, warnings\)\]$$' "$$f"; then \
				echo "missing #![deny(rust_2018_idioms, warnings)] in $$f" >&2; \
				exit 1; \
			fi; \
			if ! grep -Eq '^#!\[deny\(clippy::all, clippy::pedantic\)\]$$' "$$f"; then \
				echo "missing #![deny(clippy::all, clippy::pedantic)] in $$f" >&2; \
				exit 1; \
			fi; \
		done

	$(CARGO) clippy --all $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)
	$(CARGO) clippy --all --exclude aziot-key-openssl-engine-shared --tests $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)
	$(CARGO) clippy --all --examples $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)

	$(CARGO) fmt --all $(CARGO_VERBOSE) -- --check

	find . -name 'Makefile' -or -name '*.c' -or -name '*.md' -or -name '*.rs' -or -name '*.toml' -or -name '*.txt' | \
		grep -v '^\./target/' | \
		grep -v '\.generated\.rs$$' | \
		while read -r f; do \
			if [ "$$(tail -c 1 "$$f" | wc -l)" -eq '0' ]; then \
				echo "missing newline at end of $$f" >&2; \
				exit 1; \
			fi; \
		done

	find . -name '*.c' -or -name '*.rs' | \
		grep -v '^\./target/' | \
		grep -v '\.generated\.rs$$' | \
		while read -r f; do \
			if ! (head -n1 "$$f" | grep -q 'Copyright (c) Microsoft. All rights reserved.'); then \
				echo "missing copyright header in $$f" >&2; \
				exit 1; \
			fi; \
		done


# Packaging
#
# - `make PACKAGE_VERSION='...' PACKAGE_RELEASE='...' deb` builds deb packages for Debian and Ubuntu.
# - `make PACKAGE_VERSION='...' PACKAGE_RELEASE='...' rpm` builds RPM packages for CentOS.

# Creates a source tarball at /tmp/aziot-identity-service-$(PACKAGE_VERSION).tar.gz
dist:
	$(RM) -r /tmp/aziot-identity-service-$(PACKAGE_VERSION)* /tmp/aziot-identity-service_$(PACKAGE_VERSION)* /tmp/aziot-identity-service-dbgsym_$(PACKAGE_VERSION)*
	mkdir -p /tmp/aziot-identity-service-$(PACKAGE_VERSION)

	# Copy source files
	cp -R \
		./aziot ./cert ./http-common ./identity ./iotedged ./key ./openssl-build ./openssl-sys2 ./openssl2 ./pkcs11 \
		/tmp/aziot-identity-service-$(PACKAGE_VERSION)
	cp ./Cargo.toml ./Cargo.lock ./CODE_OF_CONDUCT.md ./CONTRIBUTING.md ./LICENSE ./Makefile ./README.md ./rust-toolchain ./SECURITY.md /tmp/aziot-identity-service-$(PACKAGE_VERSION)

	# `cargo vendor` for offline builds
	cd /tmp/aziot-identity-service-$(PACKAGE_VERSION) && $(CARGO) vendor
	mkdir -p /tmp/aziot-identity-service-$(PACKAGE_VERSION)/.cargo
	printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n' >/tmp/aziot-identity-service-$(PACKAGE_VERSION)/.cargo/config

	# Generate THIRD-PARTY-NOTICES
	set -o pipefail; \
	ARCH=$(ARCH) contrib/third-party-notices.sh >/tmp/aziot-identity-service-$(PACKAGE_VERSION)/THIRD-PARTY-NOTICES

	# Create dist tarball
	mkdir -p $(RPMBUILDDIR)/SOURCES
	cd /tmp && tar -cvzf /tmp/aziot-identity-service-$(PACKAGE_VERSION).tar.gz aziot-identity-service-$(PACKAGE_VERSION)

# deb
#
# Ref: https://www.debian.org/doc/manuals/maint-guide/build.en.html
# Ref: https://www.man7.org/linux/man-pages/man7/debhelper.7.html
deb: contrib/debian/*
deb: dist
	# Rename dist tarball to .orig.tar.gz as the source format version "3.0 (quilt)" requires
	mv /tmp/aziot-identity-service-$(PACKAGE_VERSION).tar.gz /tmp/aziot-identity-service_$(PACKAGE_VERSION).orig.tar.gz

	# Copy package files
	cp -R contrib/debian /tmp/aziot-identity-service-$(PACKAGE_VERSION)/
	sed -i -e 's/@version@/$(PACKAGE_VERSION)/g; s/@release@/$(PACKAGE_RELEASE)/g' /tmp/aziot-identity-service-$(PACKAGE_VERSION)/debian/changelog

	# Build package
	cd /tmp/aziot-identity-service-$(PACKAGE_VERSION) && dpkg-buildpackage -us -uc $(DPKG_ARCH_FLAGS)

# rpm
#
# Ref: https://rpm-packaging-guide.github.io
RPMBUILDDIR = $(HOME)/rpmbuild
rpm: contrib/centos/aziot-identity-service.spec
rpm: dist
rpm:
	# Move dist tarball to rpmbuild sources directory
	mkdir -p $(RPMBUILDDIR)/SOURCES
	mv /tmp/aziot-identity-service-$(PACKAGE_VERSION).tar.gz $(RPMBUILDDIR)/SOURCES/aziot-identity-service-$(PACKAGE_VERSION)-$(PACKAGE_RELEASE).tar.gz

	# Copy spec file to rpmbuild specs directory
	mkdir -p $(RPMBUILDDIR)/SPECS
	sed -e 's/@version@/$(PACKAGE_VERSION)/g; s/@release@/$(PACKAGE_RELEASE)/g' contrib/centos/aziot-identity-service.spec >$(RPMBUILDDIR)/SPECS/aziot-identity-service.spec

	# Build package
	rpmbuild -ba $(RPMBUILDDIR)/SPECS/aziot-identity-service.spec

# Ref: https://www.gnu.org/software/make/manual/html_node/Directory-Variables.html
#
# These are expected to be overridden by the spec file so that they correspond to the distro's personality.
prefix = /usr
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
datarootdir = $(prefix)/share
docdir = $(datarootdir)/doc/aziot-identity-service
includedir = $(prefix)/include
libdir = $(exec_prefix)/lib
libexecdir = $(exec_prefix)/libexec

# Note:
#
# This looks surprising, because it would imply the defaults are /usr/var and /usr/etc rather than /var and /etc.
# This is unfortunately by GNU's design, and the caller is expected to override localstatedir and sysconfdir when invoking the makefile.
# Both the debian and rpm build processes do this.
localstatedir = $(prefix)/var
sysconfdir = $(prefix)/etc

unitdir = $(libdir)/systemd/system

# Note: This default is almost certainly wrong for most distros and architectures, so it ought to be overridden by the caller of `make`.
#
# The correct value is the one output by `openssl version -e`, but we can't invoke that ourselves since we could be cross-compiling.
OPENSSL_ENGINES_DIR = $(libdir)/engines-1.1

# Ref: https://www.gnu.org/software/make/manual/html_node/Command-Variables.html
INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644

# Do not invoke directly; this is invoked by `rpmbuild` or `dpkg-buildpackage`. Use `make centos` or `make deb` instead.
install-common: default
install-common:
	# Ref: https://www.gnu.org/software/make/manual/html_node/DESTDIR.html

	# Binaries
	$(INSTALL_PROGRAM) -D target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/aziot-certd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-certd
	$(INSTALL_PROGRAM) -D target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/aziot-keyd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-keyd
	$(INSTALL_PROGRAM) -D target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/aziot-identityd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-identityd
	$(INSTALL_PROGRAM) -D target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/aziot $(DESTDIR)$(bindir)/aziot

	# libaziot-keys
	$(INSTALL_PROGRAM) -D target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/libaziot_keys.so $(DESTDIR)$(libdir)/libaziot_keys.so

	# Default configs
	$(INSTALL_DATA) -D cert/aziot-certd/config/unix/default.toml $(DESTDIR)$(sysconfdir)/aziot/certd/config.toml.default
	$(INSTALL_DATA) -D identity/aziot-identityd/config/unix/default.toml $(DESTDIR)$(sysconfdir)/aziot/identityd/config.toml.default
	$(INSTALL_DATA) -D key/aziot-keyd/config/unix/default.toml $(DESTDIR)$(sysconfdir)/aziot/keyd/config.toml.default

	# Home directories
	$(INSTALL) -d -m 0700 $(DESTDIR)$(localstatedir)/lib/aziot/certd
	$(INSTALL) -d -m 0700 $(DESTDIR)$(localstatedir)/lib/aziot/identityd
	$(INSTALL) -d -m 0700 $(DESTDIR)$(localstatedir)/lib/aziot/keyd

	# Systemd services and sockets
	$(INSTALL_DATA) -D cert/aziot-certd/aziot-certd.service $(DESTDIR)$(unitdir)/aziot-certd.service
	$(INSTALL_DATA) -D cert/aziot-certd/aziot-certd.socket $(DESTDIR)$(unitdir)/aziot-certd.socket

	$(INSTALL_DATA) -D identity/aziot-identityd/aziot-identityd.service $(DESTDIR)$(unitdir)/aziot-identityd.service
	$(INSTALL_DATA) -D identity/aziot-identityd/aziot-identityd.socket $(DESTDIR)$(unitdir)/aziot-identityd.socket

	$(INSTALL_DATA) -D key/aziot-keyd/aziot-keyd.service $(DESTDIR)$(unitdir)/aziot-keyd.service
	$(INSTALL_DATA) -D key/aziot-keyd/aziot-keyd.socket $(DESTDIR)$(unitdir)/aziot-keyd.socket

install-deb: install-common
	# libaziot-key-openssl-engine-shared
	$(INSTALL_PROGRAM) -D \
		target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/libaziot_key_openssl_engine_shared.so \
		$(DESTDIR)$(OPENSSL_ENGINES_DIR)/aziot_keys.so

	# Sockets

	# README.md and LICENSE
	$(INSTALL_DATA) -D README.md $(DESTDIR)$(docdir)/README.md
	$(INSTALL_DATA) -D THIRD-PARTY-NOTICES $(DESTDIR)$(docdir)/THIRD-PARTY-NOTICES
	$(INSTALL_DATA) -D LICENSE $(DESTDIR)$(docdir)/LICENSE

	# devel
	$(INSTALL_DATA) -D key/aziot-keys/aziot-keys.h $(DESTDIR)$(includedir)/aziot-identity-service/aziot-keys.h

install-rpm: install-common
	# libaziot-key-openssl-engine-shared
	$(INSTALL_PROGRAM) -D \
		target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/libaziot_key_openssl_engine_shared.so \
		$(DESTDIR)$(OPENSSL_ENGINES_DIR)/libaziot_keys.so

	# README.md and LICENSE are automatically installed by %doc and %license directives in the spec file

	# devel
	$(INSTALL_DATA) -D key/aziot-keys/aziot-keys.h $(DESTDIR)$(includedir)/aziot-identity-service/aziot-keys.h
