//! Worker selection: least in-flight connections among workers serving the
//! protocol, with a per-worker capacity soft cap. A RAII Guard decrements the
//! in-flight count when the pumped connection ends.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::roster::WorkerEntry;

#[derive(Clone, Default)]
pub struct LoadCounters {
    inner: Arc<Mutex<HashMap<String, i32>>>,
}

impl LoadCounters {
    pub fn get(&self, worker_id: &str) -> i32 {
        *self.inner.lock().unwrap().get(worker_id).unwrap_or(&0)
    }

    /// Increment the in-flight count for worker_id and return a Guard that
    /// decrements on drop.
    pub fn acquire(&self, worker_id: &str) -> Guard {
        *self
            .inner
            .lock()
            .unwrap()
            .entry(worker_id.to_string())
            .or_insert(0) += 1;
        Guard {
            counters: self.clone(),
            worker_id: worker_id.to_string(),
        }
    }

    #[cfg(test)]
    pub fn set_for_test(&self, worker_id: &str, n: i32) {
        self.inner.lock().unwrap().insert(worker_id.to_string(), n);
    }

    fn decr(&self, worker_id: &str) {
        let mut m = self.inner.lock().unwrap();
        if let Some(v) = m.get_mut(worker_id) {
            *v -= 1;
            if *v <= 0 {
                m.remove(worker_id);
            }
        }
    }
}

/// Decrements the worker's in-flight count when dropped.
pub struct Guard {
    counters: LoadCounters,
    worker_id: String,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.counters.decr(&self.worker_id);
    }
}

/// Pick the least-loaded entry with spare capacity (capacity <= 0 => unlimited).
/// Ties broken randomly. None if all are full or the list is empty.
pub fn pick<'a>(entries: &'a [WorkerEntry], counters: &LoadCounters) -> Option<&'a WorkerEntry> {
    use rand::seq::SliceRandom;
    let mut best: Vec<(&WorkerEntry, i32)> = Vec::new();
    let mut best_load = i32::MAX;
    for e in entries {
        let load = counters.get(&e.worker_id);
        if e.capacity > 0 && load >= e.capacity {
            continue; // full
        }
        if load < best_load {
            best_load = load;
            best.clear();
            best.push((e, load));
        } else if load == best_load {
            best.push((e, load));
        }
    }
    best.choose(&mut rand::thread_rng()).map(|(e, _)| *e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::WorkerEntry;

    fn e(id: &str, cap: i32) -> WorkerEntry {
        WorkerEntry {
            worker_id: id.into(),
            protocol: "ssh".into(),
            address: format!("{id}:9000"),
            capacity: cap,
        }
    }

    #[test]
    fn picks_least_loaded() {
        let counters = LoadCounters::default();
        counters.set_for_test("w1", 3);
        counters.set_for_test("w2", 1);
        counters.set_for_test("w3", 2);
        let entries = vec![e("w1", 10), e("w2", 10), e("w3", 10)];
        let picked = pick(&entries, &counters).unwrap();
        assert_eq!(picked.worker_id, "w2");
    }

    #[test]
    fn skips_at_capacity() {
        let counters = LoadCounters::default();
        counters.set_for_test("w1", 5); // full
        counters.set_for_test("w2", 5); // full
        let entries = vec![e("w1", 5), e("w2", 5)];
        assert!(pick(&entries, &counters).is_none());
    }

    #[test]
    fn zero_capacity_means_unlimited() {
        let counters = LoadCounters::default();
        counters.set_for_test("w1", 100);
        let entries = vec![e("w1", 0)];
        assert!(pick(&entries, &counters).is_some());
    }

    #[test]
    fn empty_entries_none() {
        let counters = LoadCounters::default();
        assert!(pick(&[], &counters).is_none());
    }

    #[test]
    fn guard_decrements_on_drop() {
        let counters = LoadCounters::default();
        {
            let _g = counters.acquire("w1");
            assert_eq!(counters.get("w1"), 1);
        }
        assert_eq!(counters.get("w1"), 0);
    }
}
