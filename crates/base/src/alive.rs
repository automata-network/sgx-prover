use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{
    sync::{broadcast, mpsc},
    time::sleep,
};

use async_trait::async_trait;

use crate::{SignedDuration, Time};

pub struct Signal {
    on: AtomicBool,
    notify: broadcast::Sender<bool>,
}

impl Signal {
    pub fn new(b: bool) -> Self {
        let (notify, _) = broadcast::channel(1);
        Self {
            on: AtomicBool::new(b),
            notify,
        }
    }

    pub fn get(&self) -> bool {
        self.on.load(Ordering::SeqCst)
    }

    pub fn set(&self, val: bool) {
        self.on.store(val, Ordering::SeqCst);
        let _ = self.notify.send(val);
    }

    pub async fn wait(&self, target: bool) {
        let mut rx = None;
        while self.get() != target {
            let rx = match rx.as_mut() {
                None => {
                    rx = Some(self.notify.subscribe());
                    rx.as_mut().unwrap()
                }
                Some(n) => n,
            };
            let _ = rx.recv().await.unwrap();
        }
    }
}

#[derive(Clone)]
pub struct Alive {
    alive: Arc<Signal>,
    parent: Box<Option<Alive>>,
    deadline: Option<Time>,
}

impl Default for Alive {
    fn default() -> Self {
        Self::new()
    }
}

impl Alive {
    pub fn new() -> Self {
        Self {
            alive: Arc::new(Signal::new(true)),
            parent: Box::new(None),
            deadline: None,
        }
    }

    pub fn deadline(&self) -> Option<Time> {
        self.deadline
    }

    pub fn remain_time(&self) -> Option<SignedDuration> {
        self.deadline.map(|item| item.duration_since(Time::now()))
    }

    pub fn is_alive(&self) -> bool {
        if !self.alive.get() {
            return false;
        }
        if let Some(deadline) = self.deadline {
            if Time::now() >= deadline {
                return false;
            }
        }
        if let Some(parent) = self.parent.as_ref() {
            return parent.is_alive();
        }
        return true;
    }

    pub fn shutdown(&self) {
        self.alive.set(false);
    }

    pub fn with_deadline(&mut self, deadline: Time) -> &mut Self {
        self.deadline = Some(deadline);
        self
    }

    pub fn fork_with_timeout(&self, dur: Duration) -> Self {
        self.fork_with_deadline(Time::now() + dur)
    }

    pub fn fork_with_deadline(&self, deadline: Time) -> Self {
        Self {
            alive: Arc::new(Signal::new(true)),
            parent: Box::new(Some(self.clone())),
            deadline: Some(match self.deadline {
                Some(d) => d.min(deadline),
                None => deadline,
            }),
        }
    }

    pub fn fork(&self) -> Alive {
        Self {
            alive: Arc::new(Signal::new(true)),
            parent: Box::new(Some(self.clone())),
            deadline: self.deadline,
        }
    }

    pub async fn sleep_ms(&self, ms: u64) -> bool {
        self.sleep(Duration::from_millis(ms)).await
    }

    pub async fn sleep(&self, dur: Duration) -> bool {
        self.sleep_to(Time::now() + dur).await;
        self.is_alive()
    }

    pub async fn sleep_to(&self, deadline: Time) {
        let max_sleep = Duration::from_secs(1);
        loop {
            if !self.is_alive() {
                break;
            }
            let now = Time::now();
            if now >= deadline {
                break;
            }
            let dur = (deadline - now).min(max_sleep);

            tokio::select! {
                _ = sleep(dur) => {},
                _ = self.alive.wait(false) => {},
            }
        }
    }

    // pub fn recv<T>(&self, r: &mpsc::Receiver<T>) -> Result<T, mpsc::RecvTimeoutError> {
    //     let max_sleep = Duration::from_secs(1);
    //     loop {
    //         if !self.is_alive() {
    //             break;
    //         }
    //         let mut timeout = max_sleep;
    //         if let Some(t) = self.remain_time() {
    //             if let Some(t) = t.duration() {
    //                 if t < timeout {
    //                     timeout = t;
    //                 }
    //             }
    //         }
    //         match r.recv_timeout(timeout) {
    //             Err(mpsc::RecvTimeoutError::Timeout) => break,
    //             other => return other,
    //         }
    //     }

    //     return Err(mpsc::RecvTimeoutError::Timeout);
    // }

    // pub fn recv_iter<'a, T>(&'a self, r: &'a mpsc::Receiver<T>) -> AliveIter<T, RecvIter<'a, T>> {
    //     self.iter(RecvIter {
    //         alive: self,
    //         dur: poll,
    //         receiver: r,
    //     })
    // }

    pub fn stream<N, T, II>(&self, n: N) -> AliveAsyncIter<T, II>
    where
        N: IntoAsyncIterator<Item = T, Iter = II>,
        II: AsyncIterator<Item = T>,
    {
        let iter = n.into_async_iter();
        AliveAsyncIter { alive: self, iter }
    }

    pub fn iter<N, I, II>(&self, n: N) -> AliveIter<I, II>
    where
        N: IntoIterator<Item = I, IntoIter = II>,
        II: Iterator<Item = I>,
    {
        let iter = n.into_iter();
        AliveIter { alive: self, iter }
    }
}

pub trait IntoAsyncIterator {
    type Item;
    type Iter: AsyncIterator<Item = Self::Item>;
    fn into_async_iter(self) -> Self::Iter;
}

impl<'a, T: Send> IntoAsyncIterator for &'a mut mpsc::Receiver<T> {
    type Item = T;
    type Iter = MpscReceiverIter<'a, T>;
    fn into_async_iter(self) -> Self::Iter {
        MpscReceiverIter { receiver: self }
    }
}

pub struct MpscReceiverIter<'a, T> {
    receiver: &'a mut mpsc::Receiver<T>,
}

#[async_trait]
impl<'a, T: Send> AsyncIterator for MpscReceiverIter<'a, T> {
    type Item = T;

    async fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().await
    }
}

// pub struct RecvIter<'a, T> {
//     alive: &'a Alive,
//     dur: Duration,
//     receiver: &'a mpsc::Receiver<T>,
// }

// impl<'a, T> Iterator for RecvIter<'a, T> {
//     type Item = T;
//     fn next(&mut self) -> Option<Self::Item> {
//         loop {
//             match self.receiver.recv_timeout(self.dur) {
//                 Ok(n) => return Some(n),
//                 Err(mpsc::RecvTimeoutError::Disconnected) => return None,
//                 Err(mpsc::RecvTimeoutError::Timeout) => {
//                     if !self.alive.is_alive() {
//                         return None;
//                     }
//                     continue;
//                 }
//             }
//         }
//     }
// }

#[async_trait]
pub trait AsyncIterator: Send {
    type Item: Send;

    async fn next(&mut self) -> Option<Self::Item>;

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        0
    }
}

pub struct AliveAsyncIter<'a, T, I: AsyncIterator<Item = T>> {
    alive: &'a Alive,
    iter: I,
}

#[async_trait]
impl<'a, T: Send, I: AsyncIterator<Item = T>> AsyncIterator for AliveAsyncIter<'a, T, I> {
    type Item = T;

    async fn next(&mut self) -> Option<Self::Item> {
        tokio::select! {
            _closed = self.alive.alive.wait(false) => return None,
            next = self.iter.next() => return next,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.iter.count()
    }
}

pub struct AliveIter<'a, T, I: Iterator<Item = T>> {
    alive: &'a Alive,
    iter: I,
}

impl<'a, T, I: Iterator<Item = T>> Iterator for AliveIter<'a, T, I> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.alive.is_alive() {
            return None;
        }
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.iter.count()
    }
}

impl std::fmt::Debug for Alive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", if self.is_alive() { "ALIVE" } else { "DEAD" })
    }
}
