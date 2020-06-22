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

DEP_HTTP_COMMON = http-common/Cargo.toml http-common/src/*.rs

DEP_KS_COMMON = ks-common/Cargo.toml ks-common/src/*.rs
DEP_KS_COMMON_HTTP = ks-common-http/Cargo.toml ks-common-http/src/*.rs $(DEP_HTTP_COMMON) $(DEP_KS_COMMON)
DEP_KS_CLIENT = ks-client/Cargo.toml ks-client/src/*.rs $(DEP_HTTP_COMMON) $(DEP_KS_COMMON) $(DEP_KS_COMMON_HTTP)
DEP_KS_CLIENT_ASYNC = ks-client-async/Cargo.toml ks-client-async/src/*.rs $(DEP_HTTP_COMMON) $(DEP_KS_COMMON) $(DEP_KS_COMMON_HTTP)
DEP_KSD = ksd/Cargo.toml ksd/build.rs ksd/src/keygen.generated.rs ksd/src/*.rs ksd/src/http/*.rs $(DEP_HTTP_COMMON) $(DEP_KS_COMMON) $(DEP_KS_COMMON_HTTP)

DEP_OPENSSL_ENGINE_KS = openssl-engine-ks/Cargo.toml openssl-engine-ks/build/* openssl-engine-ks/src/*.rs $(DEP_KS_CLIENT) $(KS_COMMON)

DEP_CS_COMMON = cs-common/Cargo.toml cs-common/src/*.rs
DEP_CS_COMMON_HTTP = cs-common-http/Cargo.toml cs-common-http/src/*.rs $(DEP_KS_COMMON)
DEP_CS_CLIENT_ASYNC = cs-client-async/Cargo.toml cs-client-async/src/*.rs $(DEP_CS_COMMON_HTTP) $(DEP_HTTP_COMMON) $(DEP_KS_COMMON)
DEP_CSD = csd/Cargo.toml csd/src/*.rs csd/src/http/*.rs $(DEP_CS_COMMON_HTTP) $(DEP_KS_CLIENT) $(DEP_KS_COMMON) $(DEP_OPENSSL_ENGINE_KS)

DEP_IOTHSM_KEYGEN = iothsm-keygen/iothsm-keygen.h

DEP_IOTEDGED = iotedged/Cargo.toml iotedged/src/*.rs $(DEP_CS_CLIENT_ASYNC) $(DEP_HTTP_COMMON) $(DEP_KS_CLIENT) $(DEP_KS_CLIENT_ASYNC) $(DEP_KS_COMMON) $(DEP_OPENSSL_ENGINE_KS)


.PHONY: clean cs-client csd iotedged iothsm-keygen ks-client ksd test


default: csd iotedged ksd


clean:
	$(CARGO) clean $(CARGO_VERBOSE)
	rm -rf iothsm-keygen/iothsm-keygen.h
	rm -rf ksd/src/iothsm-keygen.generated.rs


iothsm-keygen: target/$(DIRECTORY)/libiothsm_keygen.so

target/$(DIRECTORY)/libiothsm_keygen.so: Cargo.lock
target/$(DIRECTORY)/libiothsm_keygen.so: iothsm-keygen/Cargo.toml iothsm-keygen/src/*.rs
	$(CARGO) build -p iothsm-keygen $(CARGO_VERBOSE)

iothsm-keygen/iothsm-keygen.h: target/$(DIRECTORY)/libiothsm_keygen.so iothsm-keygen/cbindgen.toml iothsm-keygen/cbindgen.prelude.h
	cd iothsm-keygen/ && $(CBINDGEN) --config cbindgen.toml --output iothsm-keygen.h.tmp $(CBINDGEN_VERBOSE)
	< iothsm-keygen/cbindgen.prelude.h cat > iothsm-keygen/iothsm-keygen.h
	< iothsm-keygen/iothsm-keygen.h.tmp grep -v 'cbindgen_unused' >> iothsm-keygen/iothsm-keygen.h
	rm -f iothsm-keygen/iothsm-keygen.h.tmp


csd: target/$(DIRECTORY)/csd

target/$(DIRECTORY)/csd: Cargo.lock $(DEP_CSD)
	$(CARGO) build -p csd $(CARGO_VERBOSE)


ksd/src/keygen.generated.rs: iothsm-keygen/iothsm-keygen.h
	$(BINDGEN) \
		--blacklist-type '__.*' \
		--whitelist-function 'KEYGEN_.*' \
		--whitelist-type 'KEYGEN_.*' \
		--whitelist-var 'KEYGEN_.*' \
		-o ksd/src/keygen.generated.rs.tmp \
		$(BINDGEN_VERBOSE) \
		iothsm-keygen/iothsm-keygen.h \
		-- \
		$(BINDGEN_EXTRA_FLAGS)
	mv ksd/src/keygen.generated.rs.tmp ksd/src/keygen.generated.rs

ksd: target/$(DIRECTORY)/ksd

target/$(DIRECTORY)/ksd: Cargo.lock $(DEP_KSD)
	$(CARGO) build -p ksd $(CARGO_VERBOSE)


iotedged: target/$(DIRECTORY)/iotedged

target/$(DIRECTORY)/iotedged: Cargo.lock $(DEP_IOTEDGED)
	$(CARGO) build -p iotedged $(CARGO_VERBOSE)


test: target/$(DIRECTORY)/libiothsm_keygen.so target/$(DIRECTORY)/csd target/$(DIRECTORY)/ksd target/$(DIRECTORY)/iotedged
	$(CARGO) test --all $(CARGO_VERBOSE)
	$(CARGO) clippy --all $(CARGO_VERBOSE)
	$(CARGO) clippy --all --tests $(CARGO_VERBOSE)
	$(CARGO) clippy --all --examples $(CARGO_VERBOSE)


Cargo.lock:
	$(CARGO) update
