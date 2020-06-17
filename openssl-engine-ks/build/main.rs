#![deny(rust_2018_idioms, warnings)]

fn main() {
	openssl_build::define_version_number_cfg();

	let mut build = openssl_build::get_c_compiler();
	build.file("build/engine.c").compile("openssl_engine_ks_wrapper");
}
