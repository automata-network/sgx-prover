use std::prelude::v1::*;

use eth_types::U256;
use std::collections::BTreeMap;

pub trait Metric: std::fmt::Debug + Send {
    fn gen_openmetrics(&self) -> String;

    fn name(&self) -> String;
}

struct LabelTuple<'a, const N: usize>(&'a [&'static str; N], &'a [String; N]);

impl<'a, const N: usize> std::fmt::Display for LabelTuple<'a, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0.len() > 0 {
            write!(f, "{{")?;
            for idx in 0..self.0.len() {
                write!(f, "{}={:?}", self.0[idx], self.1[idx])?;
                if idx != self.0.len() - 1 {
                    write!(f, ",")?;
                }
            }
            write!(f, "}}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct LabeledValue<T, const N: usize> {
    labels: [&'static str; N],
    values: BTreeMap<[String; N], T>,
}

impl<T: Default + std::fmt::Display, const N: usize> LabeledValue<T, N> {
    pub fn new(labels: [&'static str; N]) -> Self {
        Self {
            labels: labels.into(),
            values: BTreeMap::new(),
        }
    }

    pub fn format(&self, list: &mut Vec<String>, name: &str) {
        for (label, val) in &self.values {
            assert_eq!(label.len(), self.labels.len());
            list.push(format!(
                "{}{} {}",
                name,
                LabelTuple(&self.labels, &label),
                val
            ));
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn get_mut(&mut self, labels: [String; N]) -> &mut T {
        self.values.entry(labels).or_insert_with(T::default)
    }
}

#[derive(Clone, Debug)]
pub struct Counter<const N: usize> {
    name: String,
    help: String,
    val: LabeledValue<f64, N>,
}

impl<const N: usize> Counter<N> {
    pub fn new(
        namespace: &str,
        subsystem: &str,
        name: &str,
        help: &str,
        labels: [&'static str; N],
    ) -> Self {
        let name = format!("{}_{}_{}_counter", namespace, subsystem, name);
        Counter {
            name,
            help: help.to_owned(),
            val: LabeledValue::new(labels),
        }
    }

    pub fn inc(&mut self, labels: [String; N]) {
        self.inc_val(labels, 1.0);
    }

    pub fn inc_val(&mut self, labels: [String; N], val: f64) {
        if val < 0.0 {
            panic!(
                "Counters can only be incremented by a positive value! {}",
                val
            );
        }
        *self.val.get_mut(labels) += val;
    }
}

impl<const N: usize> Metric for Counter<N> {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn gen_openmetrics(&self) -> String {
        if self.val.len() == 0 {
            return String::new();
        }
        let mut result: Vec<String> = Vec::new();
        result.push(format!("# HELP {} {}", self.name, self.help));
        result.push(format!("# TYPE {} counter", self.name));
        self.val.format(&mut result, &self.name);
        result.join("\n")
    }
}

#[derive(Clone, Debug)]
pub struct Gauge<const N: usize> {
    name: String,
    help: String,
    pub val: LabeledValue<f64, N>,
}

impl<const N: usize> Gauge<N> {
    pub fn new(
        namespace: &str,
        subsystem: &str,
        name: &str,
        help: &str,
        labels: [&'static str; N],
    ) -> Self {
        let name = format!("{}_{}_{}_gauge", namespace, subsystem, name);
        Gauge {
            name,
            help: help.to_owned(),
            val: LabeledValue::new(labels),
        }
    }

    pub fn inc(&mut self, labels: [String; N]) {
        self.inc_val(labels, 1.0)
    }

    pub fn inc_val(&mut self, labels: [String; N], val: f64) {
        if val < 0.0 {
            panic!("Can only be incremented by a positive value! {}", val);
        }
        *self.val.get_mut(labels) += val;
    }

    pub fn dec(&mut self, labels: [String; N]) {
        self.dec_val(labels, 1.0)
    }

    pub fn dec_val(&mut self, labels: [String; N], val: f64) {
        if val < 0.0 {
            panic!("Can only be decremented by a positive value! {}", val);
        }
        *self.val.get_mut(labels) -= val;
    }

    pub fn set(&mut self, labels: [String; N], val: f64) {
        *self.val.get_mut(labels) = val;
    }
}

impl<const N: usize> Metric for Gauge<N> {
    fn gen_openmetrics(&self) -> String {
        let mut result: Vec<String> = Vec::new();
        result.push(format!("# HELP {} {}", self.name, self.help));
        result.push(format!("# TYPE {} gauge", self.name));
        self.val.format(&mut result, &self.name);
        result.join("\n")
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}

#[derive(Clone, Debug)]
pub struct U256Gauge<const N: usize> {
    name: String,
    help: String,
    pub val: LabeledValue<U256, N>,
}

impl<const N: usize> U256Gauge<N> {
    pub fn new(
        namespace: &str,
        subsystem: &str,
        name: &str,
        help: &str,
        labels: [&'static str; N],
    ) -> Self {
        let name = format!("{}_{}_{}", namespace, subsystem, name);
        U256Gauge {
            name,
            help: help.to_owned(),
            val: LabeledValue::new(labels),
        }
    }

    pub fn inc(&mut self, labels: [String; N]) {
        self.inc_val(labels, 1.into())
    }

    pub fn inc_val(&mut self, labels: [String; N], val: U256) {
        *self.val.get_mut(labels) += val;
    }

    pub fn dec(&mut self, labels: [String; N]) {
        self.dec_val(labels, U256::one())
    }

    pub fn dec_val(&mut self, labels: [String; N], val: U256) {
        *self.val.get_mut(labels) -= val;
    }

    pub fn set(&mut self, labels: [String; N], val: U256) {
        *self.val.get_mut(labels) = val;
    }
}

impl<const N: usize> Metric for U256Gauge<N> {
    fn gen_openmetrics(&self) -> String {
        let mut result: Vec<String> = Vec::new();
        result.push(format!("# HELP {} {}", self.name, self.help));
        result.push(format!("# TYPE {} gauge", self.name));
        self.val.format(&mut result, &self.name);
        result.join("\n")
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
