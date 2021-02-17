This directory contains test files for the `aziotctl config apply` tests.

For each test, passing `input.txt` to `aziotctl config apply` should produce the four services' configs in `keyd.toml`, `certd.toml`, `identityd.toml` and `tpmd.toml`. In the tests that involve a symmetric key, the `device-id` file stores the contents of the `/var/secrets/aziot/keyd/device-id` file that `aziotctl config apply` would generate.
