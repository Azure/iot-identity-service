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

    When developing locally, consider using `make test` instead, which does not enforcing rustfmt code formatting.

1. Every crate root must enable the major lint groups and warnings-as-errors:

    ```rust
    #![deny(rust_2018_idioms)]
    #![warn(clippy::all, clippy::pedantic)]
    ```

    This is enforced by `make test`.

    A crate root is any file that is the entrypoint of a crate. This includes `lib.rs`, `main.rs`, `build.rs` (build scripts), `tests/*.rs` (integration tests) and `examples/*.rs` (examples).

    To `#[deny]` a lint or lint group means that any diagnostics raised by that lint or lint group will be treated as errors and fail the build. Conversely, to `#[allow]` a lint or lint group means that the diagnostics raised by that lint or lint group will be suppressed.

    - `rust_2018_idioms`: This lint group fires for code that could be written in a better style in Edition 2018. For example, it enforces that `extern crate` statements are not used, and that trait objects are written like `dyn Trait` instead of just `Trait`.

    - `clippy::all`: This lint group contains the mostly-uncontroversial clippy lints.

    - `clippy::pedantic`: This lint group contains more subjective clippy lints. While some of these lints are overly pedantic and okay to `allow` (see below), there are some lints in this group that are useful, so we prefer to `warn` this group by default.

    When running in CI, the `make test-release` target is used, and all warnings are treated as errors.

    In general, if any of the above lint groups raises an error/warning, it should be fixed by modifying the code to satisfy the lint. However, there are some lints that it is acceptable to `allow`. The list below enumerates these lints. Note that it is okay to `allow` these lints at the crate level with `#![allow(...)]`, rather than at the smallest scope where the lint was raised with `#[allow(...)]`, unless indicated otherwise.

    1. `clippy::default_trait_access`: This lint fires for code that uses `Default::default()` and suggests using `ConcreteType::default()`. However, in most cases, there is no benefit to naming the `ConcreteType` explicitly because it doesn't matter which type's default is being used, and it can create more noise from having to `use path::to::ConcreteType` than to leave it unnamed.

    1. `clippy::doc_markdown`: This lint looks for doc comments that contain things that look like idents or URLs, and suggests wrapping them in code fences and angle brackets respectively. Unfortunately it sometimes fires for words that look like idents but aren't, like "IoT" due to its use of mixed case. In such a case, it is okay to `allow` the lint with a `#[allow]` attached to the item whose doc comment raised the lint.

        Note that when the doc comment that raised the lint is a crate-level inner doc comment, there is unfortunately no way to suppress the lint for that doc comment other than by adding a crate-level `#![allow]` attribute for it, which also disables the lint for every other doc comment in the crate.

    1. `clippy::let_and_return`: This lint fires for code that looks like `{ ...; let ident = expr; ident }` and suggests writing it as `{ ...; expr }`. However, the former style has its advantages: it makes backtraces and single-step debugging clearer by separating the evaluation of `expr` from the line where it's returned, and also allows for easily adding logging or other side effects between those two steps.

    1. `clippy::let_unit_value`: This lint fires for code that looks like `let () = expr;` and suggests writing it as `expr;`. However, when `expr` is a complicated expression like a function call, the former style is useful to document that the caller is not discarding some result of `expr` that it ought to have considered, because there is no result to discard. It serves a similar purpose to what the `#[must_use]` attribute does in standard Rust, except that it works for types and functions that don't have `#[must_use]`. For example, it is useful to assert that the code in `let () = std::io::Read::read_exact(...)?;` is not ignoring any result from `Read::read_exact` (other than the `std::io::Error` already handled by `?`).

    1. `clippy::missing_errors_doc`: This lint fires for `pub` functions that return `Result<_, _>` and whose doc comment doesn't have an `# Errors` section. Such a section would be used to document all the ways the function can fail and what kind of error it would return in each of those cases. Unfortunately, such comments have a tendency of getting out of sync with the actual implementation, and so are either detailed but wrong, or overly simplistic (eg `fn foo()`'s doc just says "Returns an error if the foo operation fails."). In either case, such a doc becomes useless.

    1. `clippy::must_use_candidate`: This lint is broken. It fires for most `pub` functions that have a non-`()` result and wants them to be marked with the `#[must_use]` attribute. This is not necessary in most cases since it's obvious that the function is being used to compute some value, so the caller has an interest in the function's result. Adding this attribute to satisfy the lint would be very noisy and not actually help that much.

    1. `clippy::shadow_unrelated`: This lint fires when a binding shadows another binding but has a different type, and recommends renaming the second binding. However, shadowing is an important feature of Rust and it's often cleaner to take advantage of it.

        Consider a binding named `url` that starts off as a `&str`, and is then parsed into a `url::Url`. It is useful to be able to assign the parsed value to a binding named `url` rather than some other name, both because that is what it is, and because the previous unparsed `&str` is no longer needed now that it has been parsed into a `url::Url`.

    1. `clippy::similar_names`: This lint fires for a pair of idents that the lint's heuristic determines are named too similarly, and thus the programmer could easily confuse one with the other. It tends to fire for short idents like `req` and `res`. However, using such short idents instead of full words like `request` and `response` is fairly common in Rust code. For example, iterators are usually called `iter`, callbacks with an obvious usage are usually called `f`, and so on.

    1. `clippy::too_many_lines`: This lint fires when a function has more lines of code than its heuristic thinks is acceptable. However this is subjective. Sometimes a function does one thing and needs many lines to do it, and it would not be suitable to split it into multiple smaller functions that are only called from the single parent caller.

    1. `clippy::type_complexity`: This lint fires when a type has more characters than its heuristic thinks is acceptable. This is subjective just like `clippy::too_many_lines`. It is not necessarily appropriate to make new type aliases for parts of the original type if they're only going to be used once.

    1. `clippy::use_self`: This lint fires for code that uses the name of the type instead of `Self` where `Self` would be valid, ie within impl blocks for the type. While it is true that using `Self` is preferred by the community when it comes to writing function signature (eg `fn new() -> Self`), the ability to use `Self` for struct and enum literals is a relatively newer feature and is less commonly used (eg `Self { foo: bar }` for structs and `Self::Foo { bar: baz }` for enums).

        Unfortunately, `allow`ing this lint also disables it when a function signature doesn't use `Self`.


## Tips

1. Consider opening a terminal and running `watch -c -- make -s test` in it. This lets you automatically see the result of compiling your code and runnings tests and lint checks on it as you're writing it.
