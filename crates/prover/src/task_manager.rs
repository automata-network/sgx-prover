use std::{collections::{btree_map::Entry, BTreeMap}, time::Duration};

use base::Alive;
use tokio::sync::Mutex;


pub struct TaskManager<K, V, E>
where
    K: Ord + Clone,
    V: Clone,
    E: Clone,
{
    tasks: Mutex<(BTreeMap<K, TaskContext<V, E>>, Vec<K>)>,
    cap: usize,
}

impl<K, V, E> TaskManager<K, V, E>
where
    K: Ord + Clone + std::fmt::Debug,
    V: Clone,
    E: Clone,
{
    pub fn new(cap: usize) -> Self {
        Self {
            tasks: Mutex::new((BTreeMap::new(), Vec::new())),
            cap,
        }
    }

    async fn add_task(&self, task: K) -> Option<TaskContext<V, E>> {
        let mut tasks = self.tasks.lock().await;
        let result = match tasks.0.entry(task.clone()) {
            Entry::Occupied(entry) => Some(entry.get().clone()),
            Entry::Vacant(entry) => {
                entry.insert(TaskContext { result: None });
                tasks.1.push(task);
                None
            }
        };
        while tasks.1.len() > self.cap {
            let task = tasks.1.remove(0);
            tasks.0.remove(&task);
        }
        result
    }

    pub async fn process_task(&self, task: K) -> Option<Result<V, E>> {
        let alive = Alive::new();
        let alive = alive.fork_with_timeout(Duration::from_secs(120));

        while alive.is_alive() {
            match self.add_task(task.clone()).await {
                Some(tc) => match tc.result {
                    Some(poe) => return Some(poe),
                    None => {
                        log::info!("polling task result: {:?}", task);
                        alive.sleep_ms(5000).await;
                        continue;
                    }
                },
                None => return None,
            }
        }
        None
    }

    pub async fn update_task(&self, task: K, poe: Result<V, E>) -> bool {
        let mut tasks = self.tasks.lock().await;
        match tasks.0.entry(task) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().result = Some(poe);
                true
            }
            Entry::Vacant(_) => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TaskContext<T: Clone, E: Clone> {
    pub result: Option<Result<T, E>>,
}