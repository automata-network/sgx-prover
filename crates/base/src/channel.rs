use std::ops::DerefMut;

use tokio::sync::{
    mpsc::{self, error::TrySendError},
    Mutex,
};

pub struct Dispatcher<T> {
    senders: Mutex<Vec<mpsc::Sender<T>>>,
}

impl<T> Dispatcher<T> {
    pub fn new() -> Self {
        Self {
            senders: Mutex::new(Vec::new()),
        }
    }

    pub async fn dispatch(&self, mut t: T) -> Option<T> {
        let mut senders = self.senders.lock().await;
        let mut idx = 0;
        while idx < senders.len() {
            match senders[idx].try_send(t) {
                Ok(_) => {
                    return None;
                }
                Err(TrySendError::Full(obj)) => {
                    t = obj;
                    idx += 1;
                }
                Err(TrySendError::Closed(obj)) => {
                    t = obj;
                    senders.remove(idx);
                }
            }
        }
        Some(t)
    }

    pub async fn close_write(&self) {
        let mut senders = self.senders.lock().await;
        std::mem::take(senders.deref_mut());
    }

    pub async fn subscribe(&self) -> mpsc::Receiver<T> {
        let (sender, receiver) = mpsc::channel(1);
        self.senders.lock().await.push(sender);
        receiver
    }
}
