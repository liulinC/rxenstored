// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Xenstore client connections over a unix socket. One pump thread reads
//! every connection: watch events are counted, replies are handed to the
//! thread waiting for them.

use crate::poller::Poller;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use xs_wire::{Decoder, Message, MsgType};

#[derive(Debug)]
pub enum CallError {
    Io(io::Error),
    /// The daemon closed the connection.
    Closed,
    Timeout,
    Wire(xs_wire::WireError),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CallError::Io(e) => write!(f, "i/o: {e}"),
            CallError::Closed => write!(f, "connection closed by the daemon"),
            CallError::Timeout => write!(f, "no reply in time"),
            CallError::Wire(e) => write!(f, "{e}"),
        }
    }
}

#[derive(Default)]
struct Slot {
    reply: Option<Message>,
    closed: bool,
}

pub struct Conn {
    stream: UnixStream,
    /// Held for a whole request/reply round trip; the value is the next request id.
    turn: Mutex<u32>,
    slot: Mutex<Slot>,
    ready: Condvar,
    decoder: Mutex<Decoder>,
    timeout: Duration,
}

impl Conn {
    /// Sends one request and waits for its reply. Requests of several
    /// threads on one connection are serialised.
    pub fn call(&self, ty: MsgType, tx_id: u32, payload: Vec<u8>) -> Result<Message, CallError> {
        let mut turn = self.turn.lock().unwrap();
        let req_id = *turn;
        *turn = turn.wrapping_add(1);
        let msg = Message::new(ty, req_id, tx_id, payload).map_err(CallError::Wire)?;
        let mut bytes = Vec::new();
        msg.encode_into(&mut bytes);
        (&self.stream).write_all(&bytes).map_err(CallError::Io)?;

        let deadline = Instant::now() + self.timeout;
        let mut slot = self.slot.lock().unwrap();
        loop {
            if let Some(reply) = slot.reply.take() {
                return Ok(reply);
            }
            if slot.closed {
                return Err(CallError::Closed);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(CallError::Timeout);
            }
            slot = self.ready.wait_timeout(slot, left).unwrap().0;
        }
    }

    fn fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    fn mark_closed(&self) {
        self.slot.lock().unwrap().closed = true;
        self.ready.notify_all();
    }
}

pub struct Pump {
    poller: Poller,
    conns: Mutex<HashMap<RawFd, Arc<Conn>>>,
    events: AtomicU64,
    stop: AtomicBool,
    timeout: Duration,
}

impl Pump {
    pub fn new(timeout: Duration) -> io::Result<Arc<Pump>> {
        Ok(Arc::new(Pump {
            poller: Poller::new()?,
            conns: Mutex::new(HashMap::new()),
            events: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            timeout,
        }))
    }

    pub fn connect(&self, socket: &Path) -> io::Result<Arc<Conn>> {
        let stream = UnixStream::connect(socket)?;
        let conn = Arc::new(Conn {
            stream,
            turn: Mutex::new(1),
            slot: Mutex::new(Slot::default()),
            ready: Condvar::new(),
            decoder: Mutex::new(Decoder::new()),
            timeout: self.timeout,
        });
        // Registered in the map first: the pump must find it on the first wake-up.
        self.conns.lock().unwrap().insert(conn.fd(), conn.clone());
        self.poller.add(conn.fd())?;
        Ok(conn)
    }

    /// Stops reading the connection and closes it once the last reference is dropped.
    pub fn close(&self, conn: &Arc<Conn>) {
        if self.conns.lock().unwrap().remove(&conn.fd()).is_some() {
            let _ = self.poller.del(conn.fd());
        }
        let _ = conn.stream.shutdown(std::net::Shutdown::Both);
        conn.mark_closed();
    }

    /// Watch events received so far, over all connections.
    pub fn events(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Waits until every watch event the daemon queued so far, on any
    /// open connection, is counted: a round trip on each, on `threads`
    /// threads. A reply comes after the events queued for its connection
    /// before the daemon read the request (xenstored queues the events of
    /// a write before it reads anything else), and this pump counts them as
    /// it reads them, in order.
    pub fn barrier(&self, threads: usize) {
        let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
        let per = conns.len().div_ceil(threads.max(1)).max(1);
        std::thread::scope(|s| {
            for chunk in conns.chunks(per) {
                s.spawn(move || {
                    for c in chunk {
                        // A failure (the connection went) leaves nothing to count on it.
                        let _ = c.call(MsgType::GetDomainPath, 0, b"0\0".to_vec());
                    }
                });
            }
        });
    }

    /// Waits until no watch event has arrived for two consecutive `quiet` periods.
    pub fn quiesce(&self, quiet: Duration, max: Duration) {
        let deadline = Instant::now() + max;
        let mut calm = 0;
        let mut last = self.events();
        while calm < 2 && Instant::now() < deadline {
            // sleep-ok: lets the daemon settle before its CPU time is read; the events are counted after `barrier`.
            std::thread::sleep(quiet);
            let now = self.events();
            calm = if now == last { calm + 1 } else { 0 };
            last = now;
        }
    }

    fn drop_conn(&self, conn: &Arc<Conn>) {
        if self.conns.lock().unwrap().remove(&conn.fd()).is_some() {
            let _ = self.poller.del(conn.fd());
        }
        conn.mark_closed();
    }

    fn read_one(&self, conn: &Arc<Conn>, buf: &mut [u8]) {
        let n = match (&conn.stream).read(buf) {
            Ok(0) => return self.drop_conn(conn),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return,
            Err(_) => return self.drop_conn(conn),
        };
        let mut decoder = conn.decoder.lock().unwrap();
        decoder.push(&buf[..n]);
        loop {
            match decoder.next_message() {
                Ok(Some(msg)) if msg.ty == MsgType::WatchEvent as u32 => {
                    self.events.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Some(msg)) => {
                    conn.slot.lock().unwrap().reply = Some(msg);
                    conn.ready.notify_all();
                }
                Ok(None) => break,
                Err(_) => {
                    drop(decoder);
                    return self.drop_conn(conn);
                }
            }
        }
    }

    /// Reads every connection until `stop` is called.
    pub fn run(&self) -> io::Result<()> {
        let mut ready = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        while !self.stop.load(Ordering::Relaxed) {
            self.poller.wait(&mut ready, 50)?;
            for fd in &ready {
                let conn = self.conns.lock().unwrap().get(fd).cloned();
                if let Some(conn) = conn {
                    self.read_one(&conn, &mut buf);
                }
            }
        }
        Ok(())
    }
}
