#![deny(rust_2018_idioms, warnings)]

fn main() {
	println!("cargo:rustc-link-lib=iothsm_certgen");
}
