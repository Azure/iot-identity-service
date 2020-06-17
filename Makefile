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


.PHONY: clean iotedged iothsm-certgen iothsm-keygen ks-client ksd test


default: iotedged ksd


clean:
	$(CARGO) clean $(CARGO_VERBOSE)
	rm -rf iotedged/src/iothsm-certgen.generated.rs
	rm -rf iothsm-certgen/iothsm-certgen.h
	rm -rf iothsm-keygen/iothsm-keygen.h
	rm -rf ksd/src/iothsm-keygen.generated.rs


iothsm-certgen: target/$(DIRECTORY)/libiothsm_certgen.so

target/$(DIRECTORY)/libiothsm_certgen.so: Cargo.lock
target/$(DIRECTORY)/libiothsm_certgen.so: iothsm-certgen/Cargo.toml iothsm-certgen/src/*.rs

iothsm-certgen/iothsm-certgen.h: target/$(DIRECTORY)/libiothsm_certgen.so iothsm-certgen/cbindgen.toml iothsm-certgen/cbindgen.prelude.h

	cd iothsm-certgen/ && $(CBINDGEN) --config cbindgen.toml --output iothsm-certgen.h.tmp $(CBINDGEN_VERBOSE)
	< iothsm-certgen/cbindgen.prelude.h cat > iothsm-certgen/iothsm-certgen.h
	< iothsm-certgen/iothsm-certgen.h.tmp cat >> iothsm-certgen/iothsm-certgen.h
	rm -f iothsm-certgen/iothsm-certgen.h.tmp


iothsm-keygen: target/$(DIRECTORY)/libiothsm_keygen.so

target/$(DIRECTORY)/libiothsm_keygen.so: Cargo.lock
target/$(DIRECTORY)/libiothsm_keygen.so: iothsm-keygen/Cargo.toml iothsm-keygen/src/*.rs

iothsm-keygen/iothsm-keygen.h: target/$(DIRECTORY)/libiothsm_keygen.so iothsm-keygen/cbindgen.toml iothsm-keygen/cbindgen.prelude.h
	cd iothsm-keygen/ && $(CBINDGEN) --config cbindgen.toml --output iothsm-keygen.h.tmp $(CBINDGEN_VERBOSE)
	< iothsm-keygen/cbindgen.prelude.h cat > iothsm-keygen/iothsm-keygen.h
	< iothsm-keygen/iothsm-keygen.h.tmp grep -v 'cbindgen_unused' >> iothsm-keygen/iothsm-keygen.h
	rm -f iothsm-keygen/iothsm-keygen.h.tmp


target/$(DIRECTORY)/libiothsm_certgen.so target/$(DIRECTORY)/libiothsm_keygen.so:
	$(CARGO) build -p iothsm-certgen -p iothsm-keygen $(CARGO_VERBOSE)


iotedged/src/certgen.generated.rs: iothsm-certgen/iothsm-certgen.h
	$(BINDGEN) \
		--blacklist-type '__.*' \
		--blacklist-type '(?:EVP|evp).*' \
		--blacklist-type '(?:X509|x509).*' \
		--whitelist-function 'CERTGEN_.*' \
		--whitelist-type 'CERTGEN_.*' \
		--whitelist-var 'CERTGEN_.*' \
		-o iotedged/src/certgen.generated.rs.tmp \
		$(BINDGEN_VERBOSE) \
		iothsm-certgen/iothsm-certgen.h \
		-- \
		$(BINDGEN_EXTRA_FLAGS)
	mv iotedged/src/certgen.generated.rs.tmp iotedged/src/certgen.generated.rs

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

target/$(DIRECTORY)/ksd: Cargo.lock
target/$(DIRECTORY)/ksd: ks-common/Cargo.toml ks-common/src/*.rs
target/$(DIRECTORY)/ksd: ks-common-http/Cargo.toml ks-common-http/src/*.rs
target/$(DIRECTORY)/ksd: ksd/Cargo.toml ksd/src/keygen.generated.rs ksd/src/*.rs ksd/src/http/*.rs

iotedged: target/$(DIRECTORY)/iotedged

target/$(DIRECTORY)/iotedged: Cargo.lock
target/$(DIRECTORY)/iotedged: iotedged/src/certgen.generated.rs
target/$(DIRECTORY)/iotedged: iotedged/Cargo.toml iotedged/src/*.rs
target/$(DIRECTORY)/iotedged: ks-client/Cargo.toml ks-client/src/*.rs
target/$(DIRECTORY)/iotedged: ks-common/Cargo.toml ks-common/src/*.rs
target/$(DIRECTORY)/iotedged: ks-common-http/Cargo.toml ks-common-http/src/*.rs
target/$(DIRECTORY)/iotedged: openssl-engine-ks/Cargo.toml openssl-engine-ks/src/*.rs
	$(CARGO) build -p iotedged $(CARGO_VERBOSE)


test: target/$(DIRECTORY)/libiothsm_certgen.so target/$(DIRECTORY)/libiothsm_keygen.so target/$(DIRECTORY)/ksd target/$(DIRECTORY)/iotedged
	$(CARGO) test --all $(CARGO_VERBOSE)
	$(CARGO) clippy --all $(CARGO_VERBOSE)
	$(CARGO) clippy --all --tests $(CARGO_VERBOSE)
	$(CARGO) clippy --all --examples $(CARGO_VERBOSE)


Cargo.lock:
	$(CARGO) update
