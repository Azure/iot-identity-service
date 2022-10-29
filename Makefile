# Installed via `cargo install`. See /ci/install-build-deps.sh for exact command and versions.
BINDGEN = bindgen
CBINDGEN = cbindgen

# Default users under which the services will run. Override by specifying on the CLI for make.
USER_AZIOTID ?= aziotid
USER_AZIOTCS ?= aziotcs
USER_AZIOTKS ?= aziotks
USER_AZIOTTPM ?= aziottpm

# Default socket directory. Override by specifying on the CLI for make.
SOCKET_DIR ?= /run/aziot

# 0 => false, _ => true
V = 0

# 0 => false, _ => true
RELEASE = 0

# 0 => false, _ => true
VENDOR_LIBTSS = 0

# Skip integration tests for tpm/tss-minimal
# 0 => false, _ => true
SKIP_TSS_MINIMAL = 0

# '' => amd64, 'arm32v7' => arm32v7, 'aarch64' => aarch64
ARCH =

INSTALL_PRESET = true

# Enable special features for specific runtime platforms
# '' => none, 'snapd' => snapd features
PLATFORM_FEATURES ?=
CARGO_FEATURES =

ifeq ($(PLATFORM_FEATURES), snapd)
	CARGO_FEATURES += --features snapctl
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
    CROSS_HOST_TRIPLE = arm-linux-gnueabihf
	DPKG_ARCH_FLAGS = --host-arch armhf
else ifeq ($(ARCH), aarch64)
	CARGO_TARGET = aarch64-unknown-linux-gnu
    CROSS_HOST_TRIPLE = aarch64-linux-gnu
	DPKG_ARCH_FLAGS = --host-arch arm64 --host-type aarch64-linux-gnu --target-type aarch64-linux-gnu
else
	CARGO_TARGET = x86_64-unknown-linux-gnu
    CROSS_HOST_TRIPLE = x86_64-linux-gnu
	DPKG_ARCH_FLAGS =
endif

CARGO_OUTPUT_ABSPATH = $(abspath ./target/$(CARGO_TARGET)/$(CARGO_PROFILE_DIRECTORY))
VENDOR_PREFIX = $(CARGO_OUTPUT_ABSPATH)/fakeroot
VENDOR_PKGCONFIG = $(VENDOR_PREFIX)$(AZIOT_PRIVATE_LIBRARIES)/pkgconfig

CARGO = VENDOR_PREFIX="$(VENDOR_PREFIX)" VENDOR_PKGCONFIG="$(VENDOR_PKGCONFIG)" \
		USER_AZIOTID="$(USER_AZIOTID)" \
		USER_AZIOTCS="$(USER_AZIOTCS)" \
		USER_AZIOTKS="$(USER_AZIOTKS)" \
		USER_AZIOTTPM="$(USER_AZIOTTPM)" \
		SOCKET_DIR="$(SOCKET_DIR)" cargo

# Some of the targets use bash-isms like `set -o pipefail`
SHELL = /bin/bash

.PHONY: aziot-key-openssl-engine-shared-test clean default mock-iot-server test test-release
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
			--blocklist-type '__.*' \
			--allowlist-function 'aziot_keys_.*' \
			--allowlist-type 'AZIOT_KEYS_.*' \
			--allowlist-var 'AZIOT_KEYS_.*' \
			-o key/aziot-keyd/src/keys.generated.rs.tmp \
			$(BINDGEN_VERBOSE) \
			key/aziot-keys/aziot-keys.h; \
		mv key/aziot-keyd/src/keys.generated.rs.tmp key/aziot-keyd/src/keys.generated.rs; \
	fi

	# Set libdir again due to environment bleedover from this
	# Makefile during RPM build.  Set prefix due to config.status's
	# incorrect assumption of /usr/local.  There is probably a better
	# way to do this...
	set -euo pipefail; \
	if [ -d third-party/tpm2-tss ]; then \
		cd third-party/tpm2-tss; \
		./bootstrap; \
		./configure \
			--disable-dependency-tracking \
			--disable-doxygen-doc \
			--disable-fapi \
			--disable-static \
			--disable-weakcrypto \
			--enable-debug=info \
			--host=$(CROSS_HOST_TRIPLE) \
			--libdir=$(AZIOT_PRIVATE_LIBRARIES) \
			--prefix=$(prefix); \
		$(MAKE) libdir=$(AZIOT_PRIVATE_LIBRARIES) prefix=$(prefix) -j; \
		$(MAKE) DESTDIR=$(VENDOR_PREFIX) libdir=$(AZIOT_PRIVATE_LIBRARIES) prefix=$(prefix) install; \
	fi

	# aziot-keys must be built before aziot-keyd is, because aziot-keyd needs to link to it.
	# But we can't do this with Cargo dependencies because of a cargo issue that causes spurious rebuilds.
	# So instead we do it manually.
	#
	# See the doc header of the aziot-keys-common crate for more info.
	$(CARGO) build \
		-p aziot-keys \
		$(CARGO_PROFILE) $(CARGO_FEATURES) --target $(CARGO_TARGET) $(CARGO_VERBOSE)

	$(CARGO) build \
		-p aziotctl \
		-p aziotd \
		-p aziot-key-openssl-engine-shared \
		$(CARGO_PROFILE) $(CARGO_FEATURES) --target $(CARGO_TARGET) $(CARGO_VERBOSE)

clean:
	$(CARGO) clean $(CARGO_VERBOSE)
	$(RM) key/aziot-keyd/src/keys.generated.rs
	$(RM) key/aziot-keys/aziot-keys.h


aziot-key-openssl-engine-shared-test:
	$(CARGO) build -p aziot-key-openssl-engine-shared-test $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)

mock-iot-server:
	$(CARGO) build -p mock-iot-server $(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE)

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

test: aziot-key-openssl-engine-shared-test default mock-iot-server
test: target/openapi-schema-validated
test:
	set -o pipefail; \
	if [ "$(SKIP_TSS_MINIMAL)" != 0 ]; then \
		MAYBE_EXCLUDE_TSS_MINIMAL="--exclude tss-minimal"; \
	fi; \
	$(CARGO) test --all \
		--exclude aziot-key-openssl-engine-shared \
		$$MAYBE_EXCLUDE_TSS_MINIMAL \
		$(CARGO_PROFILE) --target $(CARGO_TARGET) $(CARGO_VERBOSE) 2>&1 | \
		grep -v 'running 0 tests' | grep -v '0 passed; 0 failed' | grep '.'

	find . -name '*.rs' | \
		grep -v '^\./target/' | \
		grep -v '^\./third-party/' | \
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
		grep -v '^\./third-party/' | \
		grep -v '\.generated\.rs$$' | \
		while read -r f; do \
			if [[ -s "$$f" && "$$(tail -c 1 "$$f" | wc -l)" -eq '0' ]]; then \
				echo "missing newline at end of $$f" >&2; \
				exit 1; \
			fi; \
		done

	find . -name '*.c' -or -name '*.rs' | \
		grep -v '^\./target/' | \
		grep -v '^\./third-party/' | \
		grep -v '\.generated\.rs$$' | \
		while read -r f; do \
			if ! (head -n1 "$$f" | grep -q 'Copyright (c) Microsoft. All rights reserved.'); then \
				echo "missing copyright header in $$f" >&2; \
				exit 1; \
			fi; \
		done

codecov: default
	mkdir -p coverage

	+if [ "$(SKIP_TSS_MINIMAL)" != 0 ]; then \
		MAYBE_EXCLUDE_TSS_MINIMAL="--exclude tss-minimal"; \
	fi; \
	LD_LIBRARY_PATH="$$LD_LIBRARY_PATH:$(CARGO_OUTPUT_ABSPATH):$(VENDOR_PREFIX)$(AZIOT_PRIVATE_LIBRARIES)" $(CARGO) tarpaulin --all --verbose \
		--exclude aziot-key-openssl-engine-shared \
		--exclude openssl-build --exclude test-common \
		--exclude mock-iot-server \
		--exclude aziot-key-openssl-engine-shared-test \
		$$MAYBE_EXCLUDE_TSS_MINIMAL \
		--exclude-files third-party/* \
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
		/tmp/aziot-identity-service-$(PACKAGE_VERSION)
	cp ./Cargo.toml ./Cargo.lock ./CODE_OF_CONDUCT.md ./CONTRIBUTING.md ./LICENSE ./Makefile ./README.md ./rust-toolchain.toml ./SECURITY.md /tmp/aziot-identity-service-$(PACKAGE_VERSION)

	# Copy third-party libraries
	if [ $(VENDOR_LIBTSS) != 0 ]; then \
		mkdir -p /tmp/aziot-identity-service-$(PACKAGE_VERSION)/third-party; \
		cp -R third-party/tpm2-tss /tmp/aziot-identity-service-$(PACKAGE_VERSION)/third-party; \
	fi

	# Remove spurious .git directories
	find /tmp/aziot-identity-service-$(PACKAGE_VERSION) -name .git -exec $(RM) -r {} +

	# `cargo vendor` for offline builds
	cd /tmp/aziot-identity-service-$(PACKAGE_VERSION) && $(CARGO) vendor
	mkdir -p /tmp/aziot-identity-service-$(PACKAGE_VERSION)/.cargo
	printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n' >/tmp/aziot-identity-service-$(PACKAGE_VERSION)/.cargo/config

	# Generate THIRD-PARTY-NOTICES
	set -euo pipefail; \
	ARCH=$(ARCH) contrib/third-party-notices.sh >/tmp/aziot-identity-service-$(PACKAGE_VERSION)/THIRD-PARTY-NOTICES

	# Create dist tarball
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
	sed -i -e 's/@user_aziotid@/$(USER_AZIOTID)/g; s/@user_aziotks@/$(USER_AZIOTKS)/g; s/@user_aziotcs@/$(USER_AZIOTCS)/g; s/@user_aziottpm@/$(USER_AZIOTTPM)/g' /tmp/aziot-identity-service-$(PACKAGE_VERSION)/debian/postinst
	sed -i -e 's/@user_aziotid@/$(USER_AZIOTID)/g; s/@user_aziotks@/$(USER_AZIOTKS)/g; s/@user_aziotcs@/$(USER_AZIOTCS)/g; s/@user_aziottpm@/$(USER_AZIOTTPM)/g' 's|@socket_dir@|$(SOCKET_DIR)|g' /tmp/aziot-identity-service-$(PACKAGE_VERSION)/debian/postrm
	sed -i -e 's/@user_aziotid@/$(USER_AZIOTID)/g; s/@user_aziotks@/$(USER_AZIOTKS)/g; s/@user_aziotcs@/$(USER_AZIOTCS)/g; s/@user_aziottpm@/$(USER_AZIOTTPM)/g' /tmp/aziot-identity-service-$(PACKAGE_VERSION)/debian/preinst

	cd /tmp/aziot-identity-service-$(PACKAGE_VERSION) && dpkg-buildpackage -us -uc $(DPKG_ARCH_FLAGS)

# rpm
#
# Ref: https://rpm-packaging-guide.github.io
RPMBUILDDIR = $(HOME)/rpmbuild
rpm: contrib/enterprise-linux/aziot-identity-service.spec.in
rpm: dist
rpm:
	# Move dist tarball to rpmbuild sources directory
	mkdir -p $(RPMBUILDDIR)/SOURCES
	mv /tmp/aziot-identity-service-$(PACKAGE_VERSION).tar.gz $(RPMBUILDDIR)/SOURCES/aziot-identity-service-$(PACKAGE_VERSION)-$(PACKAGE_RELEASE).$(PACKAGE_DIST).tar.gz

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
	command -v openssl # Assert that openssl exists
	case "$$(openssl version)" in \
		'OpenSSL 1.0.'*) OPENSSL_ENGINE_FILENAME='%\{_libdir\}/openssl/engines/libaziot_keys.so' ;; \
		'OpenSSL 1.1.'*) OPENSSL_ENGINE_FILENAME="$$(openssl version -e | sed 's/^ENGINESDIR: "\(.*\)"$$/\1/')/aziot_keys.so" ;; \
		*) echo "Unknown openssl version [$$(openssl version)]"; exit 1 ;; \
	esac; \
	case "$$PACKAGE_DIST" in \
		'el7') \
			DEVTOOLSET=devtoolset-9-; \
			LLVM_TOOLSET=llvm-toolset-7-; \
			;; \
		'el8') \
			DEVTOOLSET=; \
			LLVM_TOOLSET=; \
			;; \
		*) echo "Unknown RHEL derivative"; exit 1 ;; \
	esac; \
	<contrib/enterprise-linux/aziot-identity-service.spec.in sed \
		-e 's/@version@/$(PACKAGE_VERSION)/g' \
		-e 's/@release@/$(PACKAGE_RELEASE)/g' \
		-e "s|@devtoolset@|$$DEVTOOLSET|g" \
		-e "s|@llvm_toolset@|$$LLVM_TOOLSET|g" \
		-e "s|@openssl_engine_filename@|$$OPENSSL_ENGINE_FILENAME|g" \
		-e "s/@user_aziotid@/$(USER_AZIOTID)/g" \
		-e "s/@user_aziotks@/$(USER_AZIOTKS)/g" \
		-e "s/@user_aziotcs@/$(USER_AZIOTCS)/g" \
		-e "s/@user_aziottpm@/$(USER_AZIOTTPM)/g" \
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

# NOTE:
#
# This looks surprising, because it would imply the defaults are /usr/var and /usr/etc rather than /var and /etc.
# This is unfortunately by GNU's design, and the caller is expected to override localstatedir and sysconfdir when invoking the makefile.
# Both the debian and rpm build processes do this.
localstatedir = $(prefix)/var
sysconfdir = $(prefix)/etc

unitdir = $(libdir)/systemd/system
presetdir = $(libdir)/systemd/system-preset

# NOTE: This default is almost certainly wrong for most distros and
# architectures, so it ought to be overridden by the caller of `make`.
#
# The correct value is the one output by `openssl version -e`, but we
# can't invoke that ourselves since we could be cross-compiling.
# On an openssl 3.0 box this will be replaced with $(libdir)/engines-3
OPENSSL_ENGINES_DIR = $(libdir)/engines-1.1

# NOTE: This is the default destination for vendored libraries.
# Services are invoked with LD_LIBRARY_PATH set to this directory.
AZIOT_PRIVATE_LIBRARIES = $(libdir)/aziot-identity-service

# Ref: https://www.gnu.org/software/make/manual/html_node/Command-Variables.html
INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644

# Do not invoke directly; this is invoked by `dpkg-buildpackage` or `rpmbuild`. Use `make deb` or `make rpm` instead.
install-common: default
install-common:
	# Ref: https://www.gnu.org/software/make/manual/html_node/DESTDIR.html

	# Binaries
	$(INSTALL_PROGRAM) -D $(CARGO_OUTPUT_ABSPATH)/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziotd
	ln -s $(libexecdir)/aziot-identity-service/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-certd
	ln -s $(libexecdir)/aziot-identity-service/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-identityd
	ln -s $(libexecdir)/aziot-identity-service/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-keyd
	ln -s $(libexecdir)/aziot-identity-service/aziotd $(DESTDIR)$(libexecdir)/aziot-identity-service/aziot-tpmd

	$(INSTALL_PROGRAM) -D $(CARGO_OUTPUT_ABSPATH)/aziotctl $(DESTDIR)$(bindir)/aziotctl

	# libaziot-keys
	$(INSTALL_PROGRAM) -D $(CARGO_OUTPUT_ABSPATH)/libaziot_keys.so $(DESTDIR)$(libdir)/libaziot_keys.so

	# tpm2-tss
	# See comment above regarding environment bleedover on RPM
	# builds.
	if [ -d third-party/tpm2-tss ]; then \
		cd third-party/tpm2-tss; \
		$(MAKE) libdir=$(AZIOT_PRIVATE_LIBRARIES) install-exec; \
	fi

	# Remove libtool files
	find $(DESTDIR) -name "*.la" -exec $(RM) {} +

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
	$(INSTALL) -d $(DESTDIR)$(unitdir)
	# NOTE: We do not use "install -D ... -t ..." since it is broken on
	# RHEL 7 derivatives and will not be fixed.
	# Ref: https://bugzilla.redhat.com/show_bug.cgi?format=multiple&id=1758488
	for i in cert identity key tpm; do \
		OUTPUT_SOCKET="$(DESTDIR)$(unitdir)/aziot-$${i}d.socket"; \
		<"$$i/aziot-$${i}d/aziot-$${i}d.socket.in" sed \
			-e 's|@user_aziotid@|$(USER_AZIOTID)|' \
			-e 's|@user_aziotks@|$(USER_AZIOTKS)|' \
			-e 's|@user_aziotcs@|$(USER_AZIOTCS)|' \
			-e 's|@user_aziottpm@|$(USER_AZIOTTPM)|' \
			-e 's|@socket_dir@|$(SOCKET_DIR)|' \
			>"$$OUTPUT_SOCKET"; \
		chmod 0644 "$$OUTPUT_SOCKET"; \
		OUTPUT_SERVICE="$(DESTDIR)$(unitdir)/aziot-$${i}d.service"; \
		<"$$i/aziot-$${i}d/aziot-$${i}d.service.in" sed \
			-e 's|@private-libs@|$(AZIOT_PRIVATE_LIBRARIES)|' \
			-e 's|@libexecdir@|$(libexecdir)|' \
			-e 's|@user_aziotid@|$(USER_AZIOTID)|' \
			-e 's|@user_aziotks@|$(USER_AZIOTKS)|' \
			-e 's|@user_aziotcs@|$(USER_AZIOTCS)|' \
			-e 's|@user_aziottpm@|$(USER_AZIOTTPM)|' \
			>"$$OUTPUT_SERVICE"; \
		chmod 0644 "$$OUTPUT_SERVICE"; \
	done

install-deb: install-common
	# libaziot-key-openssl-engine-shared
	$(INSTALL_PROGRAM) -D \
		$(CARGO_OUTPUT_ABSPATH)/libaziot_key_openssl_engine_shared.so \
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
		$(CARGO_OUTPUT_ABSPATH)/libaziot_key_openssl_engine_shared.so \
		$(DESTDIR)$(OPENSSL_ENGINE_FILENAME)

	if [ $(INSTALL_PRESET) == "true" ]; then \
		$(INSTALL_DATA) -D ../../SOURCES/00-aziot.preset $(DESTDIR)$(presetdir)/00-aziot.preset; \
	fi

	# README.md and LICENSE are automatically installed by %doc and %license directives in the spec file

	# devel
	$(INSTALL_DATA) -D key/aziot-keys/aziot-keys.h $(DESTDIR)$(includedir)/aziot-identity-service/aziot-keys.h
