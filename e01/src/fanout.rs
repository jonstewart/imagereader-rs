//! Help-first parallel execution of one read's chunk tasks.
//!
//! The calling thread works through the tasks itself, and spawns helpers onto
//! a pool to take tasks off the same queue. It never waits for a helper that
//! has not started: one that starts after the queue is drained finds the
//! batch closed and leaves without touching it.
//!
//! This replaces handing the whole batch to rayon (`pool.install`), which
//! parked the caller while a fixed-size pool did all the work. Under
//! concurrent clients that made the pool the bottleneck -- eight clients'
//! reads queued behind four decompression threads, while the eight client
//! threads sat idle -- and a lone read paid for waking the pool even when the
//! caller could have finished the work sooner on its own.

use std::{
    any::Any,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
    thread::{self, Thread},
};

/// The part of a batch that outlives it: a helper holds this even if it starts
/// after the caller has returned.
struct Gate {
    /// Index of the next unclaimed task. Pushed past the end to stop early.
    next: AtomicUsize,
    /// Helpers that may be touching the batch.
    active: AtomicUsize,
    /// Set once the caller has stopped claiming; a helper seeing it must not
    /// touch the batch, which may be gone.
    closed: AtomicBool,
    caller: Thread,
}

/// The batch itself, which lives on the caller's stack.
struct Batch<'a, T, F, E> {
    tasks: *mut T,
    len: usize,
    f: &'a F,
    error: Mutex<Option<E>>,
    panic: Mutex<Option<Box<dyn Any + Send>>>,
}

/// Claim and run tasks until there are none left.
fn work<T, F, E>(batch: &Batch<'_, T, F, E>, gate: &Gate)
where
    F: Fn(&mut T) -> Result<(), E>,
{
    loop {
        let i = gate.next.fetch_add(1, SeqCst);
        if i >= batch.len {
            return;
        }
        // SAFETY: the fetch_add hands out each index exactly once, so this is
        // the only reference to task i, and the batch outlives every claimer
        // (see `run`).
        let task = unsafe { &mut *batch.tasks.add(i) };

        let stop = match catch_unwind(AssertUnwindSafe(|| (batch.f)(task))) {
            Ok(Ok(())) => false,
            Ok(Err(e)) => {
                batch.error.lock().unwrap().get_or_insert(e);
                true
            }
            Err(p) => {
                batch.panic.lock().unwrap().get_or_insert(p);
                true
            }
        };
        if stop {
            // Nobody else need start a task whose result will be discarded.
            gate.next.store(usize::MAX / 2, SeqCst);
            return;
        }
    }
}

/// A helper's entry point, type-erased so the spawned closure is `'static`.
///
/// # Safety
/// `batch` must point to a `Batch<T, F, E>` that stays alive until `gate.active`
/// returns to zero after `gate.closed` is set.
unsafe fn help<T, F, E>(batch: usize, gate: &Gate)
where
    F: Fn(&mut T) -> Result<(), E>,
{
    // Announce before looking: with both sides SeqCst, either the caller sees
    // us active and waits for us, or we see the batch closed and stay out.
    gate.active.fetch_add(1, SeqCst);
    if !gate.closed.load(SeqCst) {
        work(unsafe { &*(batch as *const Batch<'_, T, F, E>) }, gate);
    }
    if gate.active.fetch_sub(1, SeqCst) == 1 {
        gate.caller.unpark();
    }
}

/// A helper, type-erased: nothing in it names the batch's types, so it is
/// `'static` however short-lived the tasks' borrows are.
struct Helper {
    entry: unsafe fn(usize, &Gate),
    batch: usize,
    gate: Arc<Gate>,
}

fn spawn(pool: Option<&rayon::ThreadPool>, helper: Helper) {
    // SAFETY: `run` keeps the batch alive until every helper that got in
    // before the batch closed has left.
    let job = move || unsafe { (helper.entry)(helper.batch, &helper.gate) };
    match pool {
        Some(pool) => pool.spawn(job),
        None => rayon::spawn(job),
    }
}

/// Run `f` over every task, on the calling thread plus up to `helpers` threads
/// from `pool` (rayon's global pool if `None`). Returns the first error; a
/// panic in any task is resumed on the caller.
pub(crate) fn run<T, F, E>(
    pool: Option<&rayon::ThreadPool>,
    helpers: usize,
    tasks: &mut [T],
    f: &F,
) -> Result<(), E>
where
    T: Send,
    F: Fn(&mut T) -> Result<(), E> + Sync,
    E: Send,
{
    let helpers = helpers.min(tasks.len().saturating_sub(1));
    if helpers == 0 {
        return tasks.iter_mut().try_for_each(f);
    }

    let gate = Arc::new(Gate {
        next: AtomicUsize::new(0),
        active: AtomicUsize::new(0),
        closed: AtomicBool::new(false),
        caller: thread::current(),
    });
    let batch = Batch {
        tasks: tasks.as_mut_ptr(),
        len: tasks.len(),
        f,
        error: Mutex::new(None),
        panic: Mutex::new(None),
    };

    for _ in 0..helpers {
        spawn(
            pool,
            Helper {
                entry: help::<T, F, E>,
                batch: &batch as *const Batch<'_, T, F, E> as usize,
                gate: gate.clone(),
            },
        );
    }

    work(&batch, &gate);

    gate.closed.store(true, SeqCst);
    while gate.active.load(SeqCst) != 0 {
        thread::park();
    }

    if let Some(p) = batch.panic.into_inner().unwrap() {
        resume_unwind(p);
    }
    match batch.error.into_inner().unwrap() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pool(threads: usize) -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
    }

    #[test]
    fn runs_every_task_exactly_once() {
        let pool = pool(4);
        for len in [0, 1, 2, 3, 17, 1000] {
            let mut tasks: Vec<u32> = vec![0; len];
            run(Some(&pool), 4, &mut tasks, &|t: &mut u32| {
                *t += 1;
                Ok::<_, ()>(())
            })
            .unwrap();
            assert!(tasks.iter().all(|&t| t == 1), "len {len}: {tasks:?}");
        }
    }

    #[test]
    fn work_is_shared_with_helpers() {
        let pool = pool(4);
        let mut tasks: Vec<Option<thread::ThreadId>> = vec![None; 64];
        run(Some(&pool), 4, &mut tasks, &|t: &mut Option<
            thread::ThreadId,
        >| {
            std::thread::sleep(Duration::from_millis(2));
            *t = Some(thread::current().id());
            Ok::<_, ()>(())
        })
        .unwrap();
        let mut ids: Vec<_> = tasks.into_iter().map(Option::unwrap).collect();
        ids.sort_by_key(|id| format!("{id:?}"));
        ids.dedup();
        assert!(ids.len() > 1, "only one thread did any work");
    }

    #[test]
    fn returns_an_error() {
        let pool = pool(2);
        let mut tasks: Vec<usize> = (0..50).collect();
        let r = run(Some(&pool), 2, &mut tasks, &|t: &mut usize| {
            if *t == 25 { Err(*t) } else { Ok(()) }
        });
        assert_eq!(r, Err(25));
    }

    #[test]
    #[should_panic(expected = "task 7")]
    fn resumes_a_panic_on_the_caller() {
        let pool = pool(2);
        let mut tasks: Vec<usize> = (0..20).collect();
        let _ = run(Some(&pool), 2, &mut tasks, &|t: &mut usize| {
            if *t == 7 {
                panic!("task 7");
            }
            Ok::<_, ()>(())
        });
    }

    /// The caller must not wait on a helper that never got to start: with the
    /// pool's only thread blocked, the batch still completes on the caller.
    #[test]
    fn does_not_wait_for_helpers_that_never_start() {
        let pool = pool(1);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        pool.spawn(move || {
            let _ = rx.recv();
        });

        let mut tasks = vec![0u8; 8];
        run(Some(&pool), 1, &mut tasks, &|t: &mut u8| {
            *t = 1;
            Ok::<_, ()>(())
        })
        .unwrap();
        assert!(tasks.iter().all(|&t| t == 1));

        // The helper now runs, finds the batch closed, and must not touch it.
        drop(tx);
        std::thread::sleep(Duration::from_millis(20));
    }
}
