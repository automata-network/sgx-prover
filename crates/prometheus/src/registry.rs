use std::sync::{Arc, Mutex};

use crate::{Counter, Gauge, Metric, U256Gauge};

#[derive(Clone, Debug, Default)]
pub struct CollectorRegistry {
    metrics: Vec<Arc<Mutex<dyn Metric>>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        CollectorRegistry {
            metrics: Vec::new(),
        }
    }

    pub fn create_counter<const N: usize>(
        &mut self,
        namespace: &str,
        subsystem: &str,
        name: &str,
        help: &str,
        labels: [&'static str; N],
    ) -> Arc<Mutex<Counter<N>>> {
        let counter = Arc::new(Mutex::new(Counter::new(
            namespace, subsystem, name, help, labels,
        )));
        self.metrics.push(counter.clone() as _);
        counter
    }

    pub fn create_gauge<const N: usize>(
        &mut self,
        namespace: &str,
        subsystem: &str,
        name: &str,
        help: &str,
        labels: [&'static str; N],
    ) -> Arc<Mutex<Gauge<N>>> {
        let gauge = Arc::new(Mutex::new(Gauge::new(
            namespace, subsystem, name, help, labels,
        )));
        self.metrics.push(gauge.clone() as _);
        gauge
    }

    pub fn create_u256_gauge<const N: usize>(
        &mut self,
        namespace: &str,
        subsystem: &str,
        name: &str,
        help: &str,
        labels: [&'static str; N],
    ) -> Arc<Mutex<U256Gauge<N>>> {
        let gauge = Arc::new(Mutex::new(U256Gauge::new(
            namespace, subsystem, name, help, labels,
        )));
        self.metrics.push(gauge.clone() as _);
        gauge
    }

    pub fn expose(&self) -> String {
        let mut all_metrics: Vec<String> = Vec::new();
        all_metrics.extend(
            self.metrics
                .iter()
                .map(|x| x.lock().unwrap().gen_openmetrics())
                .filter(|n| !n.is_empty()),
        );
        format!("{}\n", all_metrics.join("\n"))
    }
}
