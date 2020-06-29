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
	DIRECTORY = debug
else
	DIRECTORY = release
endif


# Dependencies of a crate, ie its source files as well as its crate dependencies.
#
# Keep in sync with the crates' respective Cargo.toml's

DEP_OPENSSL_BUILD = \
	openssl-build/Cargo.toml openssl-build/src/*.rs \

DEP_OPENSSL_SYS2 = \
	openssl-sys2/Cargo.toml openssl-sys2/build/* openssl-sys2/src/*.rs \
	$(DEP_OPENSSL_BUILD) \

DEP_OPENSSL2 = \
	openssl2/Cargo.toml openssl2/build/* openssl2/src/*.rs \
	$(DEP_OPENSSL_BUILD) \
	$(DEP_OPENSSL_SYS2) \

DEP_PKCS11 = \
	pkcs11/pkcs11/Cargo.toml pkcs11/pkcs11/build.rs pkcs11/pkcs11/src/*.rs \
	$(DEP_OPENSSL2) \
	$(DEP_OPENSSL_BUILD) \
	$(DEP_OPENSSL_SYS2) \
	$(DEP_PKCS11_SYS) \

DEP_PKCS11_SYS = \
	pkcs11/pkcs11-sys/Cargo.toml pkcs11/pkcs11-sys/src/*.rs \

DEP_PKCS11_OPENSSL_ENGINE = \
	pkcs11/pkcs11-openssl-engine/Cargo.toml pkcs11/pkcs11-openssl-engine/build/* pkcs11/pkcs11-openssl-engine/src/*.rs \
	$(DEP_OPENSSL2) \
	$(DEP_OPENSSL_BUILD) \
	$(DEP_OPENSSL_SYS2) \
	$(DEP_PKCS11) \
	$(DEP_PKCS11_SYS) \

DEP_PKCS11_TEST = \
	pkcs11/pkcs11-test/Cargo.toml pkcs11/pkcs11-test/build.rs pkcs11/pkcs11-test/src/*.rs \
	$(DEP_OPENSSL2) \
	$(DEP_OPENSSL_BUILD) \
	$(DEP_OPENSSL_SYS2) \
	$(DEP_PKCS11) \
	$(DEP_PKCS11_OPENSSL_ENGINE) \
	$(DEP_PKCS11_SYS) \

DEP_HTTP_COMMON = \
	http-common/Cargo.toml http-common/src/*.rs \

DEP_AZIOT_KEY_COMMON = \
	key/aziot-key-common/Cargo.toml key/aziot-key-common/src/*.rs \

DEP_AZIOT_KEY_COMMON_HTTP = \
	key/aziot-key-common-http/Cargo.toml key/aziot-key-common-http/src/*.rs \
	$(DEP_AZIOT_KEY_COMMON) \
	$(DEP_HTTP_COMMON) \

DEP_AZIOT_KEY_CLIENT = \
	key/aziot-key-client/Cargo.toml key/aziot-key-client/src/*.rs \
	$(DEP_AZIOT_KEY_COMMON) \
	$(DEP_AZIOT_KEY_COMMON_HTTP) \
	$(DEP_HTTP_COMMON) \

DEP_AZIOT_KEY_CLIENT_ASYNC = \
	key/aziot-key-client-async/Cargo.toml key/aziot-key-client-async/src/*.rs \
	$(DEP_AZIOT_KEY_COMMON) \
	$(DEP_AZIOT_KEY_COMMON_HTTP) \
	$(DEP_HTTP_COMMON) \

DEP_AZIOT_KEYD = \
	key/aziot-keyd/Cargo.toml key/aziot-keyd/build.rs key/aziot-keyd/src/keys.generated.rs key/aziot-keyd/src/*.rs key/aziot-keyd/src/http/*.rs \
	$(DEP_AZIOT_KEY_COMMON) \
	$(DEP_AZIOT_KEY_COMMON_HTTP) \
	$(DEP_HTTP_COMMON) \

DEP_AZIOT_KEY_OPENSSL_ENGINE = \
	key/aziot-key-openssl-engine/Cargo.toml key/aziot-key-openssl-engine/build/* key/aziot-key-openssl-engine/src/*.rs \
	$(DEP_AZIOT_KEY_CLIENT) \
	$(DEP_AZIOT_KEY_COMMON) \
	$(DEP_OPENSSL2) \
	$(DEP_OPENSSL_BUILD) \
	$(DEP_OPENSSL_SYS2) \

DEP_AZIOT_KEYS = \
	key/aziot-keys/aziot-keys.h \
	$(DEP_OPENSSL2) \
	$(DEP_OPENSSL_BUILD) \
	$(DEP_OPENSSL_SYS2) \
	$(DEP_PKCS11) \
	$(DEP_PKCS11_OPENSSL_ENGINE) \
	$(DEP_PKCS11_SYS) \

DEP_AZIOT_CERT_COMMON = \
	cert/aziot-cert-common/Cargo.toml cert/aziot-cert-common/src/*.rs \

DEP_AZIOT_CERT_COMMON_HTTP = \
	cert/aziot-cert-common-http/Cargo.toml cert/aziot-cert-common-http/src/*.rs \
	$(DEP_AZIOT_KEY_COMMON) \

DEP_AZIOT_CERT_CLIENT_ASYNC = \
	cert/aziot-cert-client-async/Cargo.toml cert/aziot-cert-client-async/src/*.rs \
	$(DEP_AZIOT_CERT_COMMON_HTTP) \
	$(DEP_AZIOT_KEY_COMMON) \
	$(DEP_HTTP_COMMON) \

DEP_AZIOT_CERTD = \
	cert/aziot-certd/Cargo.toml cert/aziot-certd/src/*.rs cert/aziot-certd/src/http/*.rs \
	$(DEP_AZIOT_CERT_COMMON_HTTP) \
	$(DEP_AZIOT_KEY_CLIENT) \
	$(DEP_AZIOT_KEY_COMMON) \
	$(DEP_AZIOT_KEY_OPENSSL_ENGINE) \
	$(DEP_OPENSSL2) \
	$(DEP_OPENSSL_BUILD) \
	$(DEP_OPENSSL_SYS2) \

DEP_IOTEDGED = \
	iotedged/Cargo.toml iotedged/src/*.rs \
	$(DEP_AZIOT_CERT_CLIENT_ASYNC) \
	$(DEP_AZIOT_KEY_CLIENT) \
	$(DEP_AZIOT_KEY_CLIENT_ASYNC) \
	$(DEP_AZIOT_KEY_COMMON) \
	$(DEP_AZIOT_KEY_OPENSSL_ENGINE) \
	$(DEP_HTTP_COMMON) \
	$(DEP_OPENSSL2) \
	$(DEP_OPENSSL_BUILD) \
	$(DEP_OPENSSL_SYS2) \


.PHONY: clean aziot-certd aziot-keyd aziot-keys iotedged pkcs11-test test


default: aziot-certd aziot-keyd aziot-keys iotedged pkcs11-test


clean:
	$(CARGO) clean $(CARGO_VERBOSE)
	$(RM) key/aziot-keyd/src/keys.generated.rs
	$(RM) key/aziot-keys/aziot-keys.h


aziot-keys: target/$(DIRECTORY)/libaziot_keys.so

target/$(DIRECTORY)/libaziot_keys.so: Cargo.lock
target/$(DIRECTORY)/libaziot_keys.so: key/aziot-keys/Cargo.toml key/aziot-keys/src/*.rs
	$(CARGO) build -p aziot-keys $(CARGO_VERBOSE)

key/aziot-keys/aziot-keys.h: target/$(DIRECTORY)/libaziot_keys.so key/aziot-keys/cbindgen.toml key/aziot-keys/cbindgen.prelude.h
	cd key/aziot-keys/ && $(CBINDGEN) --config cbindgen.toml --output aziot-keys.h.tmp $(CBINDGEN_VERBOSE)
	cp key/aziot-keys/cbindgen.prelude.h key/aziot-keys/aziot-keys.h
	< key/aziot-keys/aziot-keys.h.tmp grep -v 'cbindgen_unused' >> key/aziot-keys/aziot-keys.h
	$(RM) key/aziot-keys/aziot-keys.h.tmp


aziot-certd: target/$(DIRECTORY)/aziot-certd

target/$(DIRECTORY)/aziot-certd: Cargo.lock $(DEP_CSD)
	$(CARGO) build -p aziot-certd $(CARGO_VERBOSE)


key/aziot-keyd/src/keys.generated.rs: $(DEP_AZIOT_KEYS)
	$(BINDGEN) \
		--blacklist-type '__.*' \
		--whitelist-function 'KEYGEN_.*' \
		--whitelist-type 'KEYGEN_.*' \
		--whitelist-var 'KEYGEN_.*' \
		-o key/aziot-keyd/src/keys.generated.rs.tmp \
		$(BINDGEN_VERBOSE) \
		key/aziot-keys/aziot-keys.h \
		-- \
		$(BINDGEN_EXTRA_FLAGS)
	mv key/aziot-keyd/src/keys.generated.rs.tmp key/aziot-keyd/src/keys.generated.rs

key/aziot-keyd: target/$(DIRECTORY)/aziot-keyd

target/$(DIRECTORY)/aziot-keyd: Cargo.lock $(DEP_AZIOT_KEYD)
	$(CARGO) build -p aziot-keyd $(CARGO_VERBOSE)


iotedged: target/$(DIRECTORY)/iotedged

target/$(DIRECTORY)/iotedged: Cargo.lock $(DEP_IOTEDGED)
	$(CARGO) build -p iotedged $(CARGO_VERBOSE)


pkcs11-test: target/$(DIRECTORY)/pkcs11-test

target/$(DIRECTORY)/pkcs11-test: Cargo.lock $(DEP_PKCS11_TEST)
	$(CARGO) build -p pkcs11-test $(CARGO_VERBOSE)


test: target/$(DIRECTORY)/aziot-certd target/$(DIRECTORY)/libaziot_keys.so target/$(DIRECTORY)/aziot-keyd target/$(DIRECTORY)/iotedged target/$(DIRECTORY)/pkcs11-test
	$(CARGO) test --all $(CARGO_VERBOSE)
	$(CARGO) clippy --all $(CARGO_VERBOSE)
	$(CARGO) clippy --all --tests $(CARGO_VERBOSE)
	$(CARGO) clippy --all --examples $(CARGO_VERBOSE)


Cargo.lock:
	$(CARGO) update
