// Copyright (c) Microsoft. All rights reserved.

pub mod error;

use crate::error::{Error, ErrorKind};

pub fn read_config<TConfig>(
    config_path: std::path::PathBuf,
    config_directory_path: std::path::PathBuf,
) -> Result<TConfig, Error>
where
    TConfig: serde::de::DeserializeOwned,
{
    let config = std::fs::read(&config_path)
        .map_err(|err| ErrorKind::ReadConfig(Some(config_path.clone()), Box::new(err)))?;
    let mut config: toml::Value = toml::from_slice(&config)
        .map_err(|err| ErrorKind::ReadConfig(Some(config_path), Box::new(err)))?;

    match std::fs::read_dir(&config_directory_path) {
        Ok(entries) => {
            let mut patch_paths = vec![];
            for entry in entries {
                let entry = entry.map_err(|err| {
                    ErrorKind::ReadConfig(Some(config_directory_path.clone()), Box::new(err))
                })?;

                let entry_file_type = entry.file_type().map_err(|err| {
                    ErrorKind::ReadConfig(Some(config_directory_path.clone()), Box::new(err))
                })?;
                if !entry_file_type.is_file() {
                    continue;
                }

                let patch_path = entry.path();
                if patch_path.extension().and_then(std::ffi::OsStr::to_str) != Some("toml") {
                    continue;
                }

                patch_paths.push(patch_path);
            }
            patch_paths.sort();

            for patch_path in patch_paths {
                let patch = std::fs::read(&patch_path).map_err(|err| {
                    ErrorKind::ReadConfig(Some(patch_path.clone()), Box::new(err))
                })?;
                let patch: toml::Value = toml::from_slice(&patch)
                    .map_err(|err| ErrorKind::ReadConfig(Some(patch_path), Box::new(err)))?;
                merge_toml(&mut config, patch);
            }
        }

        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),

        Err(err) => {
            return Err(ErrorKind::ReadConfig(Some(config_directory_path), Box::new(err)).into())
        }
    }

    let config: TConfig = serde::Deserialize::deserialize(config)
        .map_err(|err| ErrorKind::ReadConfig(None, Box::new(err)))?;

    Ok(config)
}

fn merge_toml(base: &mut toml::Value, patch: toml::Value) {
    // Similar to JSON patch, except that:
    //
    // - Maps are called tables.
    // - There is no equivalent of null that can be used to remove keys from an object.
    // - Arrays are merged via concatenating the patch to the base, rather than replacing the base with the patch.

    if let toml::Value::Table(base) = base {
        if let toml::Value::Table(patch) = patch {
            for (key, value) in patch {
                // Insert a dummy `false` if the original key didn't exist at all. It'll be overwritten by `value` in that case.
                let original_value = base.entry(key).or_insert(toml::Value::Boolean(false));
                merge_toml(original_value, value);
            }

            return;
        }
    }

    if let toml::Value::Array(base) = base {
        if let toml::Value::Array(patch) = patch {
            base.extend(patch);
            return;
        }
    }

    *base = patch;
}

#[cfg(test)]
mod tests {
    #[test]
    fn merge_toml() {
        let base = r#"
foo_key = "A"
foo_parent_key = { foo_sub_key = "B" }

[bar_table]
bar_table_key = "C"
bar_table_parent_key = { bar_table_sub_key = "D" }

[[baz_table_array]]
baz_table_array_key = "E"
baz_table_array_parent_key = { baz_table_sub_key = "F" }
"#;
        let mut base: toml::Value = toml::from_str(base).unwrap();

        let patch = r#"
foo_key = "A2"
foo_key_new = "A3"
foo_parent_key = { foo_sub_key = "B2", foo_sub_key2 = "B3" }
foo_parent_key_new = { foo_sub_key = "B4", foo_sub_key2 = "B5" }

[bar_table]
bar_table_key = "C2"
bar_table_key_new = "C3"
bar_table_parent_key = { bar_table_sub_key = "D2", bar_table_sub_key2 = "D3" }
bar_table_parent_key_new = { bar_table_sub_key = "D4", bar_table_sub_key2 = "D5" }

[[baz_table_array]]
baz_table_array_key = "G"
baz_table_array_parent_key = { baz_table_sub_key = "H" }
"#;
        let patch: toml::Value = toml::from_str(patch).unwrap();

        super::merge_toml(&mut base, patch);

        let expected = r#"
foo_key = "A2"
foo_key_new = "A3"
foo_parent_key = { foo_sub_key = "B2", foo_sub_key2 = "B3" }
foo_parent_key_new = { foo_sub_key = "B4", foo_sub_key2 = "B5" }

[bar_table]
bar_table_key = "C2"
bar_table_key_new = "C3"
bar_table_parent_key = { bar_table_sub_key = "D2", bar_table_sub_key2 = "D3" }
bar_table_parent_key_new = { bar_table_sub_key = "D4", bar_table_sub_key2 = "D5" }

[[baz_table_array]]
baz_table_array_key = "E"
baz_table_array_parent_key = { baz_table_sub_key = "F" }

[[baz_table_array]]
baz_table_array_key = "G"
baz_table_array_parent_key = { baz_table_sub_key = "H" }
"#;
        let expected: toml::Value = toml::from_str(expected).unwrap();
        assert_eq!(expected, base);
    }
}
