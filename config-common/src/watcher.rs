// Copyright (c) Microsoft. All rights reserved.

use async_trait::async_trait;
use notify::Watcher;
use std::path::PathBuf;

type Api<TConfig, TError> = std::sync::Arc<
    futures_util::lock::Mutex<dyn UpdateConfig<Config = TConfig, Error = TError> + Send>,
>;

#[derive(Debug)]
pub enum ReprovisionTrigger {
    ConfigurationFileUpdate,
    Api,
    Startup,
}

#[async_trait]
pub trait UpdateConfig {
    type Config: serde::de::DeserializeOwned;
    type Error: std::error::Error;

    async fn update_config(
        &mut self,
        new_config: Self::Config,
        trigger: ReprovisionTrigger,
    ) -> Result<(), Self::Error>;
}

pub fn start_watcher<TConfig: 'static, TError: 'static>(
    config_path: PathBuf,
    config_directory_path: PathBuf,
    api: Api<TConfig, TError>,
) where
    TConfig: serde::de::DeserializeOwned + Send,
    TError: std::error::Error,
{
    // DEVNOTE: The channel created for file watcher receiver needs to address up to two messages,
    // since the message is resent to file change receiver using a blocking send.
    // When the number of messages is set to 1, then main thread appears to block.
    let (file_changed_tx, mut file_changed_rx) = tokio::sync::mpsc::channel(2);

    // Start file watcher using blocking channel.
    std::thread::spawn({
        let config_directory_path = config_directory_path.clone();

        move || {
            let (file_watcher_tx, file_watcher_rx) = std::sync::mpsc::channel();

            // Create a watcher object, delivering debounced events
            let mut file_watcher =
                notify::watcher(file_watcher_tx, std::time::Duration::from_secs(10)).unwrap();

            // Add configuration path to be watched
            file_watcher
                .watch(config_directory_path, notify::RecursiveMode::Recursive)
                .unwrap();

            loop {
                let _ = file_watcher_rx.recv();
                let _ = file_changed_tx.blocking_send(());
            }
        }
    });

    // Start file change listener that asynchronously updates service config.
    tokio::spawn(async move {
        while let Some(()) = file_changed_rx.recv().await {
            let new_config = crate::read_config(&config_path, &config_directory_path).unwrap();

            let mut api_ = api.lock().await;
            let _ = api_
                .update_config(new_config, ReprovisionTrigger::ConfigurationFileUpdate)
                .await;
        }
    });
}
