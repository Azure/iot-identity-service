// Copyright (c) Microsoft. All rights reserved.

use std::path::PathBuf;

use async_trait::async_trait;
use notify::Watcher;

#[async_trait]
pub trait UpdateConfig {
    type Config: serde::de::DeserializeOwned + Send;
    type Error: std::error::Error + Send;

    async fn update_config(&mut self, new_config: Self::Config) -> Result<(), Self::Error>;
}

pub fn start_watcher<TApi>(
    config_path: PathBuf,
    config_directory_path: PathBuf,
    api: std::sync::Arc<futures_util::lock::Mutex<TApi>>,
) where
    TApi: UpdateConfig + Send + 'static,
{
    // DEVNOTE: The channel created for file watcher receiver needs to address up to two messages,
    // since the message is resent to file change receiver using a blocking send.
    // When the number of messages is set to 1, then main thread appears to block.
    let (file_changed_tx, mut file_changed_rx) = tokio::sync::mpsc::channel(2);

    // Start file watcher using blocking channel.
    std::thread::spawn({
        let config_path = config_path.clone();
        let config_directory_path = config_directory_path.clone();

        move || {
            let (file_watcher_tx, file_watcher_rx) = std::sync::mpsc::channel();

            // Create a watcher object, delivering debounced events.
            let mut file_watcher =
                notify::watcher(file_watcher_tx, std::time::Duration::from_secs(10)).unwrap();

            // Add configuration paths to be watched.
            if config_path.exists() {
                file_watcher
                    .watch(config_path, notify::RecursiveMode::NonRecursive)
                    .expect("Watching config file should not fail.");
            }
            if config_directory_path.exists() {
                file_watcher
                    .watch(config_directory_path, notify::RecursiveMode::NonRecursive)
                    .expect("Watching config directory path should not fail.");
            }

            loop {
                let _ = file_watcher_rx.recv();
                let _ = file_changed_tx.blocking_send(());
            }
        }
    });

    // Start file change listener that asynchronously updates service config.
    tokio::spawn(async move {
        while let Some(()) = file_changed_rx.recv().await {
            let new_config = match crate::read_config(&config_path, &config_directory_path) {
                Ok(config) => config,
                Err(err) => {
                    log::warn!(
                        "Detected config file update, but new config failed to parse. Error: {}",
                        err
                    );
                    continue;
                }
            };

            let mut api_ = api.lock().await;
            let _ = api_.update_config(new_config).await;
        }
    });
}
