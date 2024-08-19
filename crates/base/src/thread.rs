use std::{future::Future, sync::Arc};

use tokio::{runtime::Builder, sync::Semaphore};

use crate::Alive;

pub async fn parallel<O, T, C, A, F>(
    alive: &Alive,
    ctx: C,
    tasks: Vec<T>,
    worker: usize,
    f: F,
) -> Result<Vec<O>, String>
where
    O: Send + 'static,
    C: Clone + Send + 'static,
    T: Send + 'static,
    A: Future<Output = Result<O, String>> + Send + 'static,
    F: Fn(T, C) -> A + Clone + Send + 'static,
{
    let _alive = alive.fork();

    let rt = Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(worker)
        .build()
        .unwrap();
    let semaphore = Arc::new(Semaphore::new(worker));
    let mut results = Vec::new();
    let task_len = tasks.len();
    for task in tasks {
        let handler = f.clone();
        let ctx = ctx.clone();
        let semaphore = semaphore.clone();
        let handle = rt.spawn(async move {
            let _guard = semaphore.acquire().await.unwrap();
            handler(task, ctx).await
        });
        results.push(handle);
    }
    let mut out = Vec::with_capacity(task_len);
    for result in results {
        match result.await.unwrap() {
            Ok(n) => out.push(n),
            Err(err) => return Err(err),
        }
    }
    rt.shutdown_background();
    return Ok(out);

    // let dispatcher = <Dispatcher<A>>::new();
    // let mut handles = Vec::with_capacity(worker);
    // let processed = Arc::new(AtomicUsize::new(0));
    // let mut futures = Vec::with_capacity(tasks.len());
    // for task in &tasks {
    //     futures.push(f(task.clone()));
    // }
    // for i in 0..worker {
    //     let handler = f.clone();
    //     let mut receiver = dispatcher.subscribe().await;
    //     let alive = alive.clone();
    //     let processed = processed.clone();
    //     let handle = spawn(async move {
    //         let mut iter = alive.stream(&mut receiver);
    //         while let Some(item) = iter.next().await {
    //             if let Err(err) = handler(item.clone()).await {
    //                 log::error!("parallel execution fail: task:{:?}, info: {}", item, err);
    //                 alive.shutdown();
    //             } else {
    //                 processed.fetch_add(1, Ordering::SeqCst);
    //             }
    //         }
    //     });
    //     handles.push(handle);
    // }
    // for task in alive.iter(tasks) {
    //     let mut result = dispatcher.dispatch(task.clone()).await;
    //     loop {
    //         match result {
    //             Some(task) => {
    //                 if !alive.sleep_ms(100).await {
    //                     break;
    //                 }
    //                 result = dispatcher.dispatch(task).await;
    //             }
    //             None => break,
    //         }
    //     }
    // }
    // dispatcher.close_write().await;
    // for handle in handles {
    //     let _ = handle.await;
    // }
    // return processed.load(Ordering::SeqCst);
}
