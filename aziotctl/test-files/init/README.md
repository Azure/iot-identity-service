This directory contains test files for the `aziotctl init` tests.

For each test, passing `input.txt` to `aziotctl init` should produce the four services' configs in `keyd.toml`, `certd.toml`, `identityd.toml` and `tpmd.toml`. In the tests that involve a symmetric key, the `device-id` file stores the contents of the `/var/secrets/aziot/keyd/device-id` file that `aziotctl init` would generate.
