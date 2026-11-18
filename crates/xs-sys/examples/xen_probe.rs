// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Checks `xs_sys::xen::RealXen` against the devices of a live dom0, next
//! to the running xenstored and its guests. It only reads: it never
//! writes a ring page, never binds VIRQ_DOM_EXC (xenstored holds it) and
//! never binds a guest's port; the self-test uses two ports of its own.
//!
//!   xen_probe domains [DOMID...]          state of each domain (default 0 to 20)
//!   xen_probe dom0-ring [--files]         dom0's ring and port from /dev/xen/xenbus_backend,
//!                                         or with --files from xsd_kva and xsd_port
//!   xen_probe peek-ring DOMID GFN [--grant]
//!                                         a guest's ring by foreign mapping of GFN
//!                                         (`xenstore-read /local/domain/DOMID/store/ring-ref`),
//!                                         or by its grant 1 with --grant
//!   xen_probe evtchn-selftest             a loopback pair of event channels in dom0
//!
//! Exit status: 0 if every step worked, 1 if one failed, 2 on bad usage.

// A diagnostic tool run by hand, not the daemon: it may unwrap, index,
// print and panic (the no-panic rule of Cargo.toml is for the
// daemon's code).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::get_unwrap,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    clippy::exit,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unchecked_time_subtraction
)]

use std::io;
use std::process::ExitCode;
use xs_sys::backend::{Port, XenBackend};
use xs_sys::map::Mapping;
use xs_sys::xen::{self, RealXen, RingMapping, XenOptions};
use xs_sys::{Epoll, Interest};

const USAGE: &str = "usage: xen_probe domains [DOMID...]
       xen_probe dom0-ring [--files]
       xen_probe peek-ring DOMID GFN [--grant]
       xen_probe evtchn-selftest";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = match words.as_slice() {
        ["domains", ids @ ..] => match ids.iter().map(|s| number(s)).collect::<Option<Vec<u64>>>() {
            Some(ids) => domains(&ids),
            None => return usage(),
        },
        ["dom0-ring"] => dom0_ring(false),
        ["dom0-ring", "--files"] => dom0_ring(true),
        ["peek-ring", rest @ ..] => {
            let grant = rest.contains(&"--grant");
            let pos: Vec<&&str> = rest.iter().filter(|w| **w != "--grant").collect();
            match pos.as_slice() {
                [d, g] => match (number(d), number(g)) {
                    (Some(d), Some(g)) => peek_ring(d, g, grant),
                    _ => return usage(),
                },
                _ => return usage(),
            }
        }
        ["evtchn-selftest"] => evtchn_selftest(),
        _ => return usage(),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xen_probe: {e}");
            ExitCode::from(1)
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// Decimal, or hexadecimal with 0x.
fn number(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn open(mode: RingMapping) -> io::Result<RealXen> {
    let o = XenOptions {
        ring_mapping: mode,
        ..XenOptions::default()
    };
    let x = RealXen::open(&o)?;
    println!("opened {} (fd {}): {x:?}", o.evtchn.display(), x.event_fd());
    Ok(x)
}

fn domains(ids: &[u64]) -> io::Result<()> {
    let mut x = open(RingMapping::Foreign)?;
    println!(
        "XEN_DOMCTL_getdomaininfo, domctl interface version {:#x}",
        xen::XEN_DOMCTL_INTERFACE_VERSION
    );
    let ids: Vec<u64> = if ids.is_empty() {
        (0..=20).collect()
    } else {
        ids.to_vec()
    };
    let mut failed = None;
    for id in ids {
        let Ok(domid) = u32::try_from(id) else {
            println!("domain {id}: not a domain id");
            continue;
        };
        match x.domain_info(domid) {
            Ok(None) => println!("domain {domid}: {:?} (no such domain)", xen::domain_state_of(None)),
            Ok(Some(i)) => {
                let state = xen::domain_state_of(Some(i));
                let code = if i.shutdown() {
                    format!(", shutdown code {}", i.shutdown_code())
                } else {
                    String::new()
                };
                println!(
                    "domain {domid}: {state:?} (flags {:#010x}, dying {}, shutdown {}{code})",
                    i.flags,
                    i.dying(),
                    i.shutdown()
                );
            }
            Err(e) => {
                println!("domain {domid}: error: {e}");
                failed.get_or_insert(e);
            }
        }
    }
    failed.map_or(Ok(()), Err)
}

fn print_ring(what: &str, m: &Mapping) {
    match xen::ring_fields(m) {
        Some(f) => println!(
            "{what}: req_cons {} req_prod {} rsp_cons {} rsp_prod {} server_features {:#x} connection {} error {}",
            f.req_cons, f.req_prod, f.rsp_cons, f.rsp_prod, f.server_features, f.connection, f.error
        ),
        None => println!("{what}: mapping of {} bytes is too small for a ring", m.len()),
    }
}

fn dom0_ring(files: bool) -> io::Result<()> {
    let d = XenOptions::default();
    let o = XenOptions {
        xenbus_backend: d.xenbus_backend.filter(|_| !files),
        ..d
    };
    let mut x = RealXen::open(&o)?;
    let r = x.dom0_ring()?;
    println!("source: {:?}", r.source);
    println!("port: {}", r.port);
    print_ring("dom0 ring", &r.page);
    drop(r);
    println!("unmapped");
    Ok(())
}

fn peek_ring(domid: u64, gfn: u64, grant: bool) -> io::Result<()> {
    let domid =
        u32::try_from(domid).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "domain id out of range"))?;
    let mode = if grant {
        RingMapping::Grant
    } else {
        RingMapping::Foreign
    };
    let mut x = open(mode)?;
    let how = if grant {
        "grant 1 through gntdev".to_string()
    } else {
        format!("gfn {gfn:#x} through privcmd")
    };
    let m = x.map_ring(domid, gfn)?;
    println!("mapped the ring of domain {domid} ({how})");
    print_ring(&format!("domain {domid} ring"), &m);
    drop(m);
    println!("unmapped");
    Ok(())
}

/// The two ports of the self-test, unbound whatever happens (closing the
/// device would unbind them too).
struct Bound<'a> {
    x: &'a mut RealXen,
    ports: Vec<Port>,
}

impl Drop for Bound<'_> {
    fn drop(&mut self) {
        while let Some(p) = self.ports.pop() {
            match self.x.unbind(p) {
                Ok(()) => println!("unbound port {p}"),
                Err(e) => println!("error: {e}"),
            }
        }
    }
}

/// Waits up to `ms` for the device to be readable, then returns what is
/// pending, unmasking each port.
fn collect(x: &mut RealXen, ep: &Epoll, ms: i32) -> io::Result<Vec<Port>> {
    let mut ev = Vec::new();
    ep.wait(&mut ev, 4, ms)?;
    let mut ports = Vec::new();
    x.pending(&mut ports)?;
    for &p in &ports {
        x.unmask(p)?;
    }
    Ok(ports)
}

fn expect(x: &mut RealXen, ep: &Epoll, want: Port) -> io::Result<()> {
    let got = collect(x, ep, 1000)?;
    println!("pending: {got:?}, unmasked");
    if !got.contains(&want) {
        return Err(io::Error::other(format!("port {want} did not become pending")));
    }
    Ok(())
}

fn evtchn_selftest() -> io::Result<()> {
    let mut x = open(RingMapping::Foreign)?;
    let ep = Epoll::new()?;
    ep.add(x.event_fd(), 0, Interest::READ)?;
    let a = x.bind_unbound_port(0)?;
    println!("IOCTL_EVTCHN_BIND_UNBOUND_PORT for domain 0: port {a}");
    let mut b = Bound {
        x: &mut x,
        ports: vec![a],
    };
    let p = b.x.bind_interdomain(0, a)?;
    b.ports.push(p);
    println!("IOCTL_EVTCHN_BIND_INTERDOMAIN to port {a} of domain 0: port {p}");
    // Xen marks a freshly bound port pending in case its peer signalled
    // before (xen/common/event_channel.c, evtchn_bind_interdomain).
    let early = collect(b.x, &ep, 200)?;
    println!("pending after binding: {early:?}, unmasked");
    b.x.notify(p)?;
    println!("notified port {p}");
    expect(b.x, &ep, a)?;
    b.x.notify(a)?;
    println!("notified port {a}");
    expect(b.x, &ep, p)?;
    drop(b);
    println!("evtchn self-test passed");
    Ok(())
}
