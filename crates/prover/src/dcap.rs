use std::thread::{spawn, JoinHandle};

use automata_sgx_sdk::dcap::{self, DcapError};
use tokio::{runtime::Builder, sync::mpsc};

pub struct AsyncDcapQuote {
    handle: Option<JoinHandle<()>>,
    sender: Option<mpsc::Sender<DcapTask>>,
}

pub struct DcapTask {
    pub data: [u8; 64],
    pub response_sender: mpsc::Sender<Result<Vec<u8>, DcapError>>,
}

impl AsyncDcapQuote {
    pub fn new() -> Self {
        let (sender, mut receiver) = mpsc::channel::<DcapTask>(1);
        let handle = spawn(move || {
            let rt = Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                loop {
                    let Some(task) = receiver.recv().await else {
                        return;
                    };
                    let quote = dcap::dcap_quote(task.data);
                    let _ = task.response_sender.send(quote).await;
                }
            })
        });
        Self {
            handle: Some(handle),
            sender: Some(sender),
        }
    }

    pub async fn generate(&self, data: [u8; 64]) -> Result<Vec<u8>, DcapError> {
        match &self.sender {
            Some(sender) => {
                let (tx, mut rx) = mpsc::channel(1);
                let task = DcapTask {
                    data,
                    response_sender: tx,
                };
                sender.send(task).await.map_err(|_| {
                    DcapError::Quote3("generate dcap quote fail: remote closed".into())
                })?;
                rx.recv().await.ok_or(DcapError::Quote3(
                    "generate dcap quote fail: remote closed".into(),
                ))?
            }
            None => Err(DcapError::Quote3(
                "generate dcap quote fail: remote closed".into(),
            )),
        }
    }
}

impl Drop for AsyncDcapQuote {
    fn drop(&mut self) {
        self.sender.take();
        self.handle.take().map(|h| h.join());
    }
}