# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.


## Code style

1. Every source file must start with a copyright header:

    - Rust: `// Copyright (c) Microsoft. All rights reserved.`
    - C: `/* Copyright (c) Microsoft. All rights reserved. */`

    This is enforced by `make test`.

1. Rust code must be formatted with `rustfmt`

    This is enforced by `make test-release`.

    Make sure to run `make test-release` before pushing to your remote so that you run all the checks that CI would run, as `make test` does not enforce rustfmt!

1. Every crate must import dependencies and lints from the workspace manifest.

    For dependencies, this means every dependency must be specified as `= { workspace = true }`.

    For lints, this means the crate manifest must have:

    ```toml
    [lints]
    workspace = true
    ```


## Tips

1. Consider opening a terminal and running `watch -c -- make -s test` in it. This lets you automatically see the result of compiling your code and runnings tests and lint checks on it as you're writing it.
