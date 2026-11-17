// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Load generator for any xenstored.
//!
//! It replays the xenstore traffic of a recorded VM start (and stop), taken
//! from an oxenstored access log, once per simulated VM, over the daemon's
//! unix socket. Simulated VMs are not Xen domains: the guest's own requests
//! go over a socket too, and nothing is introduced to the daemon.

pub mod client;
pub mod poller;
pub mod run;
pub mod scenario;
pub mod trace;
