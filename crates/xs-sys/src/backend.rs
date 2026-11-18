// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! What the daemon needs from Xen, behind one trait with two
//! implementations: `xen::RealXen` (the devices of a dom0) and the
//! simulated one of `xs-sim` (memfd pages, eventfd ports, a table of
//! domains). The daemon and the core never see a raw pointer.

use crate::map::Mapping;
use std::fmt;
use std::io;
use std::os::fd::RawFd;
use std::path::PathBuf;

/// A local event channel port.
pub type Port = u32;

/// What Xen says of a domain. `xs_core::DomainState` is its twin on
/// purpose: the core does no I/O and depends on no system crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    Running,
    /// Shut down (or suspended, crashed...) but not destroyed yet.
    Shutdown,
    /// Being destroyed, or no such domain.
    Dead,
}

/// What `pending` says of the ports it returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pending {
    /// Every port that fired since the last call.
    Complete,
    /// The device dropped notifications (its buffer overflowed) and has
    /// been reset: any bound port may have fired unseen, and is then
    /// masked until `unmask`.
    Lost,
}

/// Domain 0's own ring, as `XenBackend::dom0_ring` finds it.
pub struct Dom0Ring {
    pub page: Mapping,
    /// The remote port of its event channel.
    pub port: Port,
    pub source: Dom0Source,
}

/// Where domain 0's ring page and port came from.
#[derive(Debug)]
pub enum Dom0Source {
    /// Both from the xenbus backend device.
    Device(PathBuf),
    /// The page from `kva`, the port from `port`. `device`: the xenbus
    /// backend device was tried first and not used, and why.
    Files {
        kva: PathBuf,
        port: PathBuf,
        device: Option<DeviceNotUsed>,
    },
    /// The simulated hypervisor of the tests.
    Simulated,
}

/// Why the xenbus backend device was not used.
#[derive(Debug)]
pub struct DeviceNotUsed {
    pub path: PathBuf,
    /// The device does not exist (ENOENT, ENODEV, ENXIO at open): a
    /// kernel without it. Otherwise it exists and failed.
    pub missing: bool,
    pub error: io::Error,
}

impl fmt::Display for DeviceNotUsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.error)
    }
}

pub trait XenBackend {
    /// The descriptor to poll: readable (or in error) when local ports are
    /// pending. It is non-blocking.
    fn event_fd(&self) -> RawFd;

    /// Appends the pending local ports to `out`. A port stays masked
    /// until `unmask`. Nothing pending is not an error.
    fn pending(&mut self, out: &mut Vec<Port>) -> io::Result<Pending>;

    /// Lets a port that `pending` returned fire again.
    fn unmask(&mut self, local: Port) -> io::Result<()>;

    /// Binds `VIRQ_DOM_EXC`: fires when a domain shuts down or dies.
    fn bind_dom_exc(&mut self) -> io::Result<Port>;

    /// Binds a local port to `remote` of `domid`.
    fn bind_interdomain(&mut self, domid: u32, remote: Port) -> io::Result<Port>;

    fn unbind(&mut self, local: Port) -> io::Result<()>;

    /// Signals the other end of a bound port.
    fn notify(&mut self, local: Port) -> io::Result<()>;

    /// Domain 0's own ring page and the remote port of its event channel
    /// (`/dev/xen/xenbus_backend`, or `/proc/xen/xsd_kva` and
    /// `/proc/xen/xsd_port`).
    fn dom0_ring(&mut self) -> io::Result<Dom0Ring>;

    /// Maps the xenstore ring page of a domain, which INTRODUCE said is at
    /// guest frame `gfn`.
    fn map_ring(&mut self, domid: u32, gfn: u64) -> io::Result<Mapping>;

    fn domain_state(&mut self, domid: u32) -> io::Result<DomainState>;
}
