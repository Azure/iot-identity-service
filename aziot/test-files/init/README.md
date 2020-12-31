This directory contains test files for the `aziot init` tests.

For each test, passing `input.txt` to `aziot init` should produce the four services' configs in `keyd.toml`, `certd.toml`, `identityd.toml` and `tpmd.toml`. In the tests that involve a symmetric key, the `device-id` file stores the contents of the `/var/secrets/aziot/keyd/device-id` file that `aziot init` would generate.
