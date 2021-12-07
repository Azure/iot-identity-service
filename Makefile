CARGO = cargo

# Installed via `cargo install`. See /ci/install-build-deps.sh for exact command and versions.
BINDGEN = bindgen
CBINDGEN = cbindgen

# 0 => false, _ => true
V = 0

# 0 => false, _ => true
RELEASE = 0

# '' => amd64, 'arm32v7' => arm32v7, 'aarch64' => aarch64
ARCH =

INSTALL_PRESET = true


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


.PHONY: aziot-key-openssl-engine-shared-test clean default iotedged mock-dps-server test test-release
.PHONY: deb dist install-common install-deb install-rpm rpm


default:
	# Re-generate aziot-keys.h if necessary
	set -euo pipefail; \
	aziot_keys_h_new="$$(mktemp --tmpdir 'aziot-keys.h.new.XXXXXXXXXX')"; \
	trap "$(RM) '$$aziot_keys_h_new'" EXIT; \
	cp key/aziot-keys/cbindgen.prelude.h "$$aziot_keys_h_new"; \
	$(CBINDGEN) --config key/aziot-keys/cbindgen.toml --crate aziot-keys --lockfile "$$PWD/Cargo.lock" --output /dev/stdout $(CBINDGEN_VERBOSE) | \
		grep -v 'cbindgen_unused_' >> "$$aziot_keys_h_new"; \
	if ! diff -q key/aziot-keys/aziot-keys.h "$$aziot_keys_h_new"; then \
		mv "$$aziot_keys_h_new" key/aziot-keys/aziot-keys.h; \
		$(RM) key/aziot-keyd/src/keys.generated.rs; \
	fi

	# Re-generate keys.generated.rs if necessary
	set -euo pipefail; \
	if ! [ -f key/aziot-keyd/src/keys.generated.rs ]; then \
		$(BINDGEN) \
			--blacklist-type '__.*' \
			--whitelist-function 'aziot_keys_.*' \
			--whitelist-type 'AZIOT_KEYS_.*' \
			--whitelist-var 'AZIOT_KEYS_.*' \
			-o key/aziot-keyd/src/keys.generated.rs.tmp \
			$(BINDGEN_VERBOSE) \
			key/aziot-keys/aziot-keys.h; \
		mv key/aziot-keyd/src/keys.generated.rs.tmp key/aziot-keyd/src/keys.generated.rs; \
	fi

	# aziot-keys must be built before aziot-keyd is, because aziot-keyd needs to link to it.
	# But we can't do this with Cargo dependencies because of a cargo issue that causes spurious rebuilds.
	# So instead we do it manually.
	#
	# See the doc header of the aziot-keys-common crate for more info.
	$(CARGO) build \
		-p aziot-keys \
		$(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)

	$(CARGO) build \
		-p aziotctl \
		-p aziotd \
		-p aziot-key-openssl-engine-shared \
		$(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)


clean:
	$(CARGO) clean $(CARGO_VERBOSE)
	$(RM) key/aziot-keyd/src/keys.generated.rs
	$(RM) key/aziot-keys/aziot-keys.h

iotedged:
	$(CARGO) build -p iotedged $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)


aziot-key-openssl-engine-shared-test:
	$(CARGO) build -p aziot-key-openssl-engine-shared-test $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)

mock-dps-server:
	$(CARGO) build -p mock-dps-server $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)

target/openapi-schema-validated: cert/aziot-certd/openapi/*.yaml
target/openapi-schema-validated: key/aziot-keyd/openapi/*.yaml
target/openapi-schema-validated: identity/aziot-identityd/openapi/*.yaml
target/openapi-schema-validated:
	mkdir -p target
	$(RM) target/openapi-schema-validated

	# Pretend the task succeeds if docker isn't installed. This is because the CI runs `make test` inside a container
	# so it can't run docker there without mounting the host socket. Also some of the distros have very old versions of docker.
	#
	# We still want this task to be a dependency of the test target so that it runs by default on developers' machines.
	#
	# The resolution is to have CI run this target separately after running `make test`.
	if [ -f /usr/bin/docker ]; then \
		set -euo pipefail; \
		for f in cert/aziot-certd/openapi/*.yaml key/aziot-keyd/openapi/*.yaml identity/aziot-identityd/openapi/*.yaml; do \
			validator_output="$$( \
				docker run --rm -v "$$PWD:/src" --user 1000 \
					openapitools/openapi-generator-cli:v4.3.1 \
					validate -i "/src/$$f" --recommend || \
				: \
			)"; \
			if ! (<<< "$$validator_output" grep -q 'No validation issues detected'); then \
				printf '%s\n' "$$validator_output"; \
				exit 1; \
			fi; \
		done; \
	fi

	touch target/openapi-schema-validated


test-release: CLIPPY_FLAGS = -D warnings -D clippy::all -D clippy::pedantic
test-release: test
	$(CARGO) fmt --all -- --check

	[ -z "$$(git status --porcelain 'key/aziot-keys/aziot-keys.h')" ] || \
		(echo 'There are uncommitted modifications to aziot-keys.h' >&2; exit 1)


test: aziot-key-openssl-engine-shared-test default iotedged mock-dps-server
test: target/openapi-schema-validated
test:
	set -o pipefail; \
	$(CARGO) test --all \
		--exclude aziot-key-openssl-engine-shared \
		$(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE) 2>&1 | \
		grep -v 'running 0 tests' | grep -v '0 passed; 0 failed' | grep '.'

	find . -name '*.rs' | \
		grep -v '^\./target/' | \
		grep -v '^\./tpm/aziot-tpm-sys/azure-iot-hsm-c/' | \
		grep -v '\.generated\.rs$$' | \
		grep -E '/(build|lib|main|(examples|tests)/[^/]+)\.rs$$' | \
		while read -r f; do \
			if ! grep -Eq '^#!\[deny\(rust_2018_idioms\)\]$$' "$$f"; then \
				echo "missing #![deny(rust_2018_idioms)] in $$f" >&2; \
				exit 1; \
			fi; \
			if ! grep -Eq '^#!\[warn\(clippy::all, clippy::pedantic\)\]$$' "$$f"; then \
				echo "missing #![warn(clippy::all, clippy::pedantic)] in $$f" >&2; \
				exit 1; \
			fi; \
		done

	$(CARGO) clippy --all \
		$(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE) -- $(CLIPPY_FLAGS)
	$(CARGO) clippy --all --tests \
		--exclude aziot-key-openssl-engine-shared \
		$(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE) -- $(CLIPPY_FLAGS)
	$(CARGO) clippy --all --examples \
		$(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE) -- $(CLIPPY_FLAGS)

	find . -name 'Makefile' -or -name '*.c' -or -name '*.md' -or -name '*.rs' -or -name '*.toml' -or -name '*.txt' | \
		grep -v '^\./target/' | \
		grep -v '^\./tpm/aziot-tpm-sys/azure-iot-hsm-c/' | \
		grep -v '\.generated\.rs$$' | \
		while read -r f; do \
			if [[ -s "$$f" && "$$(tail -c 1 "$$f" | wc -l)" -eq '0' ]]; then \
				echo "missing newline at end of $$f" >&2; \
				exit 1; \
			fi; \
		done

	find . -name '*.c' -or -name '*.rs' | \
		grep -v '^\./target/' | \
		grep -v '^\./tpm/aziot-tpm-sys/azure-iot-hsm-c/' | \
		grep -v '\.generated\.rs$$' | \
		while read -r f; do \
			if ! (head -n1 "$$f" | grep -q 'Copyright (c) Microsoft. All rights reserved.'); then \
				echo "missing copyright header in $$f" >&2; \
				exit 1; \
			fi; \
		done


codecov:
	# Re-generate aziot-keys.h if necessary
	set -euo pipefail; \
	aziot_keys_h_new="$$(mktemp --tmpdir 'aziot-keys.h.new.XXXXXXXXXX')"; \
	trap "$(RM) '$$aziot_keys_h_new'" EXIT; \
	cp key/aziot-keys/cbindgen.prelude.h "$$aziot_keys_h_new"; \
	$(CBINDGEN) --config key/aziot-keys/cbindgen.toml --crate aziot-keys --lockfile "$$PWD/Cargo.lock" --output /dev/stdout $(CBINDGEN_VERBOSE) | \
		grep -v 'cbindgen_unused_' >> "$$aziot_keys_h_new"; \
	if ! diff -q key/aziot-keys/aziot-keys.h "$$aziot_keys_h_new"; then \
		mv "$$aziot_keys_h_new" key/aziot-keys/aziot-keys.h; \
		$(RM) key/aziot-keyd/src/keys.generated.rs; \
	fi

	# Re-generate keys.generated.rs if necessary
	set -euo pipefail; \
	if ! [ -f key/aziot-keyd/src/keys.generated.rs ]; then \
		$(BINDGEN) \
			--blacklist-type '__.*' \
			--whitelist-function 'aziot_keys_.*' \
			--whitelist-type 'AZIOT_KEYS_.*' \
			--whitelist-var 'AZIOT_KEYS_.*' \
			-o key/aziot-keyd/src/keys.generated.rs.tmp \
			$(BINDGEN_VERBOSE) \
			key/aziot-keys/aziot-keys.h; \
		mv key/aziot-keyd/src/keys.generated.rs.tmp key/aziot-keyd/src/keys.generated.rs; \
	fi

	# aziot-keys must be built before aziot-keyd is, because aziot-keyd needs to link to it.
	# But we can't do this with Cargo dependencies because of a cargo issue that causes spurious rebuilds.
	# So instead we do it manually.
	#
	# See the doc header of the aziot-keys-common crate for more info.
	$(CARGO) build \
		-p aziot-keys \
		--target $(CARGO_TARGET) $(CARGO_VERBOSE)

	$(CARGO) build \
		-p aziotctl \
		-p aziotd \
		-p aziot-key-openssl-engine-shared \
		--target $(CARGO_TARGET) $(CARGO_VERBOSE)
	mkdir -p coverage
	$(INSTALL_PROGRAM) -D target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/libaziot_keys.so $(DESTDIR)$(libdir)/libaziot_keys.so
	$(CARGO) tarpaulin --all --verbose \
		--exclude aziot-key-openssl-engine-shared \
		--no-fail-fast \
		--target $(CARGO_TARGET) --out Lcov \
		--output-dir ./coverage


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
		./config-common ./http-common ./logger ./openssl-build ./openssl-sys2 ./openssl2 ./pkcs11 \
		./aziotctl ./aziotd ./mini-sntp \
		./cert \
		./identity \
		./key \
		./test-common \
		./tpm \
		./iotedged \
		/tmp/aziot-identity-service-$(PACKAGE_VERSION)
	cp ./Cargo.toml ./Cargo.lock ./CODE_OF_CONDUCT.md ./CONTRIBUTING.md ./LICENSE ./Makefile ./README.md ./rust-toolchain ./SECURITY.md /tmp/aziot-identity-service-$(PACKAGE_VERSION)

	# `cargo vendor` for offline builds
	cd /tmp/aziot-identity-service-$(PACKAGE_VERSION) && $(CARGO) vendor
	mkdir -p /tmp/aziot-identity-service-$(PACKAGE_VERSION)/.cargo
	printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n' >/tmp/aziot-identity-service-$(PACKAGE_VERSION)/.cargo/config

	# Generate THIRD-PARTY-NOTICES
	set -euo pipefail; \
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
rpm: contrib/enterprise-linux/aziot-identity-service.spec
rpm: dist
rpm:
	# Move dist tarball to rpmbuild sources directory
	mkdir -p $(RPMBUILDDIR)/SOURCES
	mv /tmp/aziot-identity-service-$(PACKAGE_VERSION).tar.gz $(RPMBUILDDIR)/SOURCES/aziot-identity-service-$(PACKAGE_VERSION)-$(PACKAGE_RELEASE).tar.gz

	# Copy spec file to rpmbuild specs directory
	mkdir -p $(RPMBUILDDIR)/SPECS

	# Engine needs to be installed to what openssl considers the enginesdir,
	# which we can get from openssl 1.1 with `openssl version -e` but not from openssl 1.0.
	# Also, the filename for 1.0 should have a `lib` prefix.
	#
	# CentOS 7 has 1.0 and RedHat 8 has 1.1, so we need to support both here.
	#
	# Since there is no RPM macro for those two things, we have to infer them from
	# the output of `openssl version` and `openssl version -e` ourselves. This wouldn't be right
	# if we were cross-compiling, but we don't support cross-compiling for either of those two OSes,
	# so it's fine.
	which openssl # Assert that openssl exists
	case "$$(openssl version)" in \
		'OpenSSL 1.0.'*) OPENSSL_ENGINE_FILENAME='%\{_libdir\}/openssl/engines/libaziot_keys.so' ;; \
		'OpenSSL 1.1.'*) OPENSSL_ENGINE_FILENAME="$$(openssl version -e | sed 's/^ENGINESDIR: "\(.*\)"$$/\1/')/aziot_keys.so" ;; \
		*) echo "Unknown openssl version [$$(openssl version)]"; exit 1 ;; \
	esac; \
	<contrib/enterprise-linux/aziot-identity-service.spec sed \
		-e 's/@version@/$(PACKAGE_VERSION)/g' \
		-e 's/@release@/$(PACKAGE_RELEASE)/g' \
		-e "s|@openssl_engine_filename@|$$OPENSSL_ENGINE_FILENAME|g" \
		>$(RPMBUILDDIR)/SPECS/aziot-identity-service.spec

	# Copy preset file to be included in the package
	cp contrib/enterprise-linux/00-aziot.preset $(RPMBUILDDIR)/SOURCES

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
presetdir = $(libdir)/systemd/system-preset

# Note: This default is almost certainly wrong for most distros and architectures, so it ought to be overridden by the caller of `make`.
#
# The correct value is the one output by `openssl version -e`, but we can't invoke that ourselves since we could be cross-compiling.
OPENSSL_ENGINES_DIR = $(libdir)/engines-1.1

# Ref: https://www.gnu.org/software/make/manual/html_node/Command-Variables.html
INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644

# Do not invoke directly; this is invoked by `dpkg-buildpackage` or `rpmbuild`. Use `make deb` or `make rpm` instead.
install-common: default
install-common:
	# Ref: https://www.gnu.org/software/make/manual/html_node/DESTDIR.html

	# Binaries
	$(INSTALL_PROGRAM) -D target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziotd
	ln -s $(libexecdir)/aziot-identity-service/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-certd
	ln -s $(libexecdir)/aziot-identity-service/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-identityd
	ln -s $(libexecdir)/aziot-identity-service/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-keyd
	ln -s $(libexecdir)/aziot-identity-service/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-tpmd

	$(INSTALL_PROGRAM) -D target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/aziotctl $(DESTDIR)$(bindir)/aziotctl

	# libaziot-keys
	$(INSTALL_PROGRAM) -D target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/libaziot_keys.so $(DESTDIR)$(libdir)/libaziot_keys.so

	# Default configs and config directories
	$(INSTALL_DATA) -D cert/aziot-certd/config/unix/default.toml $(DESTDIR)$(sysconfdir)/aziot/certd/config.toml.default
	$(INSTALL) -d -m 0700 $(DESTDIR)$(sysconfdir)/aziot/certd/config.d

	$(INSTALL_DATA) -D identity/aziot-identityd/config/unix/default.toml $(DESTDIR)$(sysconfdir)/aziot/identityd/config.toml.default
	$(INSTALL) -d -m 0700 $(DESTDIR)$(sysconfdir)/aziot/identityd/config.d

	$(INSTALL_DATA) -D key/aziot-keyd/config/unix/default.toml $(DESTDIR)$(sysconfdir)/aziot/keyd/config.toml.default
	$(INSTALL) -d -m 0700 $(DESTDIR)$(sysconfdir)/aziot/keyd/config.d

	$(INSTALL_DATA) -D tpm/aziot-tpmd/config/unix/default.toml $(DESTDIR)$(sysconfdir)/aziot/tpmd/config.toml.default
	$(INSTALL) -d -m 0700 $(DESTDIR)$(sysconfdir)/aziot/tpmd/config.d

	$(INSTALL_DATA) -D aziotctl/config/unix/template.toml $(DESTDIR)$(sysconfdir)/aziot/config.toml.template

	# Home directories
	$(INSTALL) -d -m 0700 $(DESTDIR)$(localstatedir)/lib/aziot/certd
	$(INSTALL) -d -m 0700 $(DESTDIR)$(localstatedir)/lib/aziot/identityd
	$(INSTALL) -d -m 0700 $(DESTDIR)$(localstatedir)/lib/aziot/keyd
	$(INSTALL) -d -m 0700 $(DESTDIR)$(localstatedir)/lib/aziot/tpmd

	# Systemd services and sockets
	$(INSTALL_DATA) -D cert/aziot-certd/aziot-certd.service $(DESTDIR)$(unitdir)/aziot-certd.service
	$(INSTALL_DATA) -D cert/aziot-certd/aziot-certd.socket $(DESTDIR)$(unitdir)/aziot-certd.socket

	$(INSTALL_DATA) -D identity/aziot-identityd/aziot-identityd.service $(DESTDIR)$(unitdir)/aziot-identityd.service
	$(INSTALL_DATA) -D identity/aziot-identityd/aziot-identityd.socket $(DESTDIR)$(unitdir)/aziot-identityd.socket

	$(INSTALL_DATA) -D key/aziot-keyd/aziot-keyd.service $(DESTDIR)$(unitdir)/aziot-keyd.service
	$(INSTALL_DATA) -D key/aziot-keyd/aziot-keyd.socket $(DESTDIR)$(unitdir)/aziot-keyd.socket

	$(INSTALL_DATA) -D tpm/aziot-tpmd/aziot-tpmd.service $(DESTDIR)$(unitdir)/aziot-tpmd.service
	$(INSTALL_DATA) -D tpm/aziot-tpmd/aziot-tpmd.socket $(DESTDIR)$(unitdir)/aziot-tpmd.socket

install-deb: install-common
	# libaziot-key-openssl-engine-shared
	$(INSTALL_PROGRAM) -D \
		target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY)/libaziot_key_openssl_engine_shared.so \
		$(DESTDIR)$(OPENSSL_ENGINES_DIR)/aziot_keys.so

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
		$(DESTDIR)$(OPENSSL_ENGINE_FILENAME)

	if [ $(INSTALL_PRESET) == "true" ]; then \
		$(INSTALL_DATA) -D ../../SOURCES/00-aziot.preset $(DESTDIR)$(presetdir)/00-aziot.preset; \
	fi

	# README.md and LICENSE are automatically installed by %doc and %license directives in the spec file

	# devel
	$(INSTALL_DATA) -D key/aziot-keys/aziot-keys.h $(DESTDIR)$(includedir)/aziot-identity-service/aziot-keys.h
