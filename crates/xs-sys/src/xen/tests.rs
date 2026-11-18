// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! What can be checked without Xen: every failure that a missing device,
//! a wrong file or bad content produces, and the paths that work on any
//! character device. /dev/null and /dev/zero stand in for the Xen devices:
//! they open like them, refuse every Xen ioctl with ENOTTY, and /dev/zero
//! can be mapped.

use super::*;
use std::os::unix::fs::FileExt;

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("xs-sys-xen-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir(&p).unwrap();
        Dir(p)
    }

    fn file(&self, name: &str, content: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    fn missing(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Character devices everywhere Xen's would be, and a dom0 ring made of
/// regular files, used as configured (no xenbus backend device).
fn fake(d: &Dir, mode: RingMapping) -> XenOptions {
    let kva = d.file("xsd_kva", &[0; PAGE_SIZE]);
    XenOptions {
        evtchn: "/dev/null".into(),
        privcmd: "/dev/zero".into(),
        privcmd_fallback: d.missing("proc-privcmd"),
        hypercall: d.missing("hypercall"),
        #[cfg(feature = "gnttab")]
        gntdev: "/dev/zero".into(),
        xenbus_backend: None,
        xsd_kva: kva,
        xsd_port: d.file("xsd_port", b"7"),
        ring_mapping: mode,
    }
}

fn err_text<T>(r: io::Result<T>) -> String {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn defaults_are_those_of_a_dom0() {
    let o = XenOptions::default();
    assert_eq!(o.evtchn, Path::new("/dev/xen/evtchn"));
    assert_eq!(o.privcmd, Path::new("/dev/xen/privcmd"));
    assert_eq!(o.privcmd_fallback, Path::new("/proc/xen/privcmd"));
    assert_eq!(o.hypercall, Path::new("/dev/xen/hypercall"));
    #[cfg(feature = "gnttab")]
    assert_eq!(o.gntdev, Path::new("/dev/xen/gntdev"));
    assert_eq!(o.xenbus_backend.as_deref(), Some(Path::new("/dev/xen/xenbus_backend")));
    assert_eq!(o.xsd_kva, Path::new("/proc/xen/xsd_kva"));
    assert_eq!(o.xsd_port, Path::new("/proc/xen/xsd_port"));
    assert_eq!(o.ring_mapping, RingMapping::Foreign);
    assert_eq!(RingMapping::default(), RingMapping::Foreign);
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn devices_open_non_blocking_and_close_on_exec() {
    for nonblocking in [false, true] {
        let fd = open_device(Path::new("/dev/null"), nonblocking).unwrap();
        // SAFETY: plain calls on a descriptor owned by `fd`.
        let (fl, fdfl) = unsafe {
            (
                libc::fcntl(fd.as_raw_fd(), libc::F_GETFL),
                libc::fcntl(fd.as_raw_fd(), libc::F_GETFD),
            )
        };
        assert_eq!(fl & libc::O_NONBLOCK != 0, nonblocking);
        assert_eq!(fl & libc::O_ACCMODE, libc::O_RDWR);
        assert_ne!(fdfl & libc::FD_CLOEXEC, 0);
    }
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn a_missing_device_or_a_regular_file_is_refused_by_name() {
    let d = Dir::new("open");
    let gone = d.missing("evtchn");
    let e = open_device(&gone, true).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        e.to_string(),
        format!("{}: No such file or directory (os error 2)", gone.display())
    );
    let file = d.file("regular", b"");
    let e = open_device(&file, false).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(e.to_string(), format!("{}: not a character device", file.display()));

    // Through the constructor, each device in turn.
    let mut o = fake(&d, RingMapping::Foreign);
    o.evtchn = gone.clone();
    assert!(err_text(RealXen::open(&o)).starts_with(&gone.display().to_string()));
    #[cfg(feature = "gnttab")]
    {
        let mut o = fake(&d, RingMapping::Grant);
        o.gntdev = file.clone();
        assert!(err_text(RealXen::open(&o)).ends_with("not a character device"));
        let mut o = fake(&d, RingMapping::Foreign);
        o.gntdev = gone.clone();
        assert!(RealXen::open(&o).is_ok(), "gntdev is only needed for grant mapping");
    }
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn privcmd_falls_back_to_proc_only_when_missing() {
    let d = Dir::new("privcmd");
    let mut o = fake(&d, RingMapping::Foreign);
    o.privcmd = d.missing("dev-privcmd");
    o.privcmd_fallback = "/dev/zero".into();
    assert!(format!("{:?}", RealXen::open(&o).unwrap()).contains(r#"privcmd: "/dev/zero""#));
    o.privcmd_fallback = d.missing("proc-privcmd");
    let e = RealXen::open(&o).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
    let msg = e.to_string();
    assert!(
        msg.contains("dev-privcmd: No such file") && msg.contains("proc-privcmd: No such file"),
        "{msg}"
    );
    // Present but wrong: no fallback.
    o.privcmd = d.file("dev-privcmd", b"");
    o.privcmd_fallback = "/dev/zero".into();
    assert!(err_text(RealXen::open(&o)).ends_with("dev-privcmd: not a character device"));
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn the_hypercall_buffer_comes_from_the_device_or_locked_memory() {
    let d = Dir::new("hcall");
    // No buffer device: locked anonymous memory.
    let x = RealXen::open(&fake(&d, RingMapping::Foreign)).unwrap();
    assert_eq!(x.hcall.len(), PAGE_SIZE);
    // A device that maps (as /dev/xen/hypercall does).
    let mut o = fake(&d, RingMapping::Foreign);
    o.hypercall = "/dev/zero".into();
    let x = RealXen::open(&o).unwrap();
    assert_eq!(x.hcall.len(), PAGE_SIZE);
    assert!(format!("{x:?}").contains(r#"hypercall_buffer: "/dev/zero""#));
    // One that does not map, and a regular file.
    o.hypercall = "/dev/null".into();
    assert!(err_text(RealXen::open(&o)).starts_with("mmap of /dev/null: "));
    o.hypercall = d.file("hypercall", b"");
    assert!(err_text(RealXen::open(&o)).ends_with("hypercall: not a character device"));
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn event_channel_ioctls_report_the_device_error() {
    let d = Dir::new("evtchn");
    let mut x = RealXen::open(&fake(&d, RingMapping::Foreign)).unwrap();
    assert!(x.event_fd() >= 0);
    let enotty = "Inappropriate ioctl for device (os error 25)";
    assert_eq!(
        err_text(x.bind_dom_exc()),
        format!("IOCTL_EVTCHN_BIND_VIRQ VIRQ_DOM_EXC: {enotty}")
    );
    assert_eq!(
        err_text(x.bind_interdomain(3, 9)),
        format!("IOCTL_EVTCHN_BIND_INTERDOMAIN to port 9 of domain 3: {enotty}")
    );
    assert_eq!(
        err_text(x.bind_unbound_port(0)),
        format!("IOCTL_EVTCHN_BIND_UNBOUND_PORT for domain 0: {enotty}")
    );
    assert_eq!(
        err_text(x.unbind(4)),
        format!("IOCTL_EVTCHN_UNBIND of port 4: {enotty}")
    );
    assert_eq!(
        err_text(x.notify(4)),
        format!("IOCTL_EVTCHN_NOTIFY of port 4: {enotty}")
    );
    assert_eq!(
        err_text(x.reset()),
        format!("IOCTL_EVTCHN_RESET after an overflow: {enotty}")
    );
    // /dev/null reads as nothing and takes any write.
    let mut out = vec![1];
    assert_eq!(x.pending(&mut out).unwrap(), Pending::Complete);
    assert_eq!(out, [1]);
    x.unmask(4).unwrap();
}

/// FIONREAD (asm-generic/ioctls.h), whose success can be had anywhere.
#[repr(C)]
struct Fionread(libc::c_int);

impl abi::Request for Fionread {
    const NR: u32 = libc::FIONREAD as u32;
}

#[test]
#[cfg_attr(miri, ignore = "ioctl FIONREAD on a pipe: not emulated by Miri")]
fn ioctl_returns_the_result_or_errno() {
    let (r, w) = pipe();
    // SAFETY: `w` is a valid descriptor and the buffer is valid.
    assert_eq!(unsafe { libc::write(w.as_raw_fd(), b"abc".as_ptr().cast(), 3) }, 3);
    let mut n = Fionread(0);
    // SAFETY: no pointers in the argument.
    assert_eq!(unsafe { ioctl(&r, &mut n) }.unwrap(), 0);
    assert_eq!(n.0, 3);
    // SAFETY: as above.
    let e = unsafe { ioctl(&r, &mut abi::Notify { port: 1 }) }.unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOTTY));
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: `fds` is valid for two descriptors.
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
        0
    );
    use std::os::fd::FromRawFd;
    // SAFETY: both are fresh descriptors that nothing else owns.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn read_ports(fd: RawFd, out: &mut Vec<Port>) -> io::Result<Pending> {
    drain(
        |b| read_fd(fd, b),
        || Err(io::Error::other("no overflow on a pipe")),
        out,
    )
}

#[test]
#[cfg_attr(
    miri,
    ignore = "Miri's strerror_r appends the error number, so the error text differs; the code before the check runs under Miri"
)]
fn pending_ports_are_read_until_the_device_would_block() {
    let (r, w) = pipe();
    let mut out = Vec::new();
    assert_eq!(read_ports(r.as_raw_fd(), &mut out).unwrap(), Pending::Complete);
    assert!(out.is_empty());
    // More than one read's worth: the loop goes on until EAGAIN.
    let ports: Vec<Port> = (1..=1500).collect();
    let bytes: Vec<u8> = ports.iter().flat_map(|p| p.to_ne_bytes()).collect();
    for chunk in bytes.chunks(PAGE_SIZE) {
        // SAFETY: `w` is valid and `chunk` valid for its length.
        assert_eq!(
            unsafe { libc::write(w.as_raw_fd(), chunk.as_ptr().cast(), chunk.len()) },
            chunk.len() as isize
        );
    }
    read_ports(r.as_raw_fd(), &mut out).unwrap();
    assert_eq!(out, ports);
    // The writer gone: end of file.
    drop(w);
    assert_eq!(read_ports(r.as_raw_fd(), &mut out).unwrap(), Pending::Complete);
    let e = read_ports(-1, &mut out).unwrap_err();
    assert_eq!(
        e.to_string(),
        "read of pending event channels: Bad file descriptor (os error 9)"
    );
}

/// Reads that return `script` in turn, then would block.
fn scripted(script: Vec<io::Result<Vec<Port>>>) -> impl FnMut(&mut [u8]) -> io::Result<usize> {
    let mut script = script.into_iter();
    move |buf| match script.next() {
        None => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
        Some(Err(e)) => Err(e),
        Some(Ok(ports)) => {
            let bytes: Vec<u8> = ports.iter().flat_map(|p| p.to_ne_bytes()).collect();
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "Miri's strerror_r appends the error number, so the error text differs; the code before the check runs under Miri"
)]
fn an_overflow_resets_the_device_and_says_events_were_lost() {
    let os = io::Error::from_raw_os_error;
    // Ports read before the overflow are kept; the reset comes once.
    let mut out = Vec::new();
    let mut resets = 0;
    let reset = || {
        resets += 1;
        Ok(())
    };
    let r = drain(
        scripted(vec![
            Ok(vec![3, 4]),
            Err(os(libc::EINTR)),
            Ok(vec![5]),
            Err(os(libc::EFBIG)),
            Ok(vec![9]),
        ]),
        reset,
        &mut out,
    );
    assert_eq!((r.unwrap(), &out[..], resets), (Pending::Lost, &[3, 4, 5][..], 1));
    // A reset that fails is the error of `pending`.
    let r = drain(scripted(vec![Err(os(libc::EFBIG))]), || Err(os(libc::ENOTTY)), &mut out);
    assert_eq!(r.unwrap_err().raw_os_error(), Some(libc::ENOTTY));
    // Another error is not an overflow.
    let r = drain(scripted(vec![Err(os(libc::EIO))]), || panic!("reset"), &mut out);
    assert_eq!(
        r.unwrap_err().to_string(),
        "read of pending event channels: Input/output error (os error 5)"
    );
}

#[test]
fn a_read_that_claims_more_than_the_buffer_is_an_error() {
    let mut out = Vec::new();
    let r = drain(|b| Ok(b.len() + 1), || panic!("reset"), &mut out);
    assert_eq!(
        r.unwrap_err().to_string(),
        "read of pending event channels: 4097 bytes into a buffer of 4096"
    );
    assert!(out.is_empty());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "Miri's strerror_r appends the error number, so the error text differs; the code before the check runs under Miri"
)]
fn unmask_writes_the_port() {
    let (r, w) = pipe();
    write_port(w.as_raw_fd(), 0x0a0b_0c0d).unwrap();
    let mut b = [0u8; 8];
    // SAFETY: `r` is valid and `b` writable for its length.
    assert_eq!(unsafe { libc::read(r.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) }, 4);
    assert_eq!(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]), 0x0a0b_0c0d);
    assert_eq!(
        err_text(write_port(-1, 5)),
        "unmask of event channel 5: Bad file descriptor (os error 9)"
    );
}

/// Through the backend: the descriptor to wait on and the unmask are the
/// evtchn device's (here /dev/full, which refuses every write).
#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn the_backend_waits_on_and_unmasks_through_the_evtchn_device() {
    let d = Dir::new("evtchn");
    let mut o = fake(&d, RingMapping::Foreign);
    o.evtchn = "/dev/full".into();
    let mut x = RealXen::open(&o).unwrap();
    let fd = x.event_fd();
    assert_eq!(
        std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap(),
        Path::new("/dev/full")
    );
    assert_eq!(
        err_text(x.unmask(5)),
        "unmask of event channel 5: No space left on device (os error 28)"
    );
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn domain_state_is_an_error_when_the_hypercall_fails() {
    let d = Dir::new("domctl");
    let mut x = RealXen::open(&fake(&d, RingMapping::Foreign)).unwrap();
    let e = x.domain_state(1).unwrap_err();
    assert_eq!(
        e.to_string(),
        "XEN_DOMCTL_getdomaininfo hypercall: Inappropriate ioctl for device (os error 25)"
    );
    // The request was put in the hypercall page.
    // SAFETY: inside the page, which nothing else uses.
    let head = unsafe { std::slice::from_raw_parts(x.hcall.as_ptr(), 10) }.to_vec();
    assert_eq!(head, [5, 0, 0, 0, 0x15, 0, 0, 0, 1, 0]);
    // A reserved id is no ordinary domain: no hypercall.
    assert_eq!(x.domain_state(0x7FF0).unwrap(), DomainState::Dead);
    assert_eq!(x.domain_info(u32::MAX).unwrap(), None);
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn ring_mapping_failures_are_clean() {
    let d = Dir::new("rings");
    let mut x = RealXen::open(&fake(&d, RingMapping::Foreign)).unwrap();
    assert_eq!(x.ring_mapping(), RingMapping::Foreign);
    assert_eq!(
        format!("{x:?}"),
        r#"RealXen { ring_mapping: Foreign, privcmd: "/dev/zero", hypercall_buffer: "locked memory", xenbus_backend: None, .. }"#
    );
    // The privcmd mapping is made, then the batch fails and it is undone.
    assert_eq!(
        err_text(x.map_ring(3, 0xfeff0)),
        "foreign mapping of gfn 0xfeff0 of domain 3: Inappropriate ioctl for device (os error 25)"
    );
    assert_eq!(x.map_ring(0x7FF1, 1).err().unwrap().kind(), io::ErrorKind::InvalidInput);
    // A privcmd that cannot be mapped.
    let mut o = fake(&d, RingMapping::Foreign);
    o.privcmd = "/dev/null".into();
    let mut x = RealXen::open(&o).unwrap();
    assert!(err_text(x.map_ring(3, 1)).starts_with("foreign mapping of gfn 0x1 of domain 3: "));
}

#[test]
#[cfg(feature = "gnttab")]
fn grant_mapping_failures_are_clean() {
    let d = Dir::new("grant");
    let mut x = RealXen::open(&fake(&d, RingMapping::Grant)).unwrap();
    assert_eq!(x.ring_mapping(), RingMapping::Grant);
    assert_eq!(
        err_text(x.map_ring(3, 0)),
        "grant mapping of the xenstore grant of domain 3: Inappropriate ioctl for device (os error 25)"
    );
    assert_eq!(
        err_text(x.map_ring(0x7FF2, 0)),
        "domain 32754 is not an ordinary domain id"
    );
}

#[test]
#[cfg(feature = "gnttab")]
fn a_grant_release_failure_is_silent() {
    let fd = Arc::new(open_device(Path::new("/dev/zero"), false).unwrap());
    grant_release(fd.clone(), 0x1000)();
    assert_eq!(Arc::strong_count(&fd), 1, "the hook drops its descriptor");
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn dom0_ring_maps_xsd_kva_and_reads_xsd_port() {
    let d = Dir::new("dom0");
    let o = fake(&d, RingMapping::Foreign);
    let kva = std::fs::OpenOptions::new().write(true).open(&o.xsd_kva).unwrap();
    for (off, v) in [
        (2048u64, 1u32),
        (2052, 2),
        (2056, 3),
        (2060, 4),
        (2064, 1),
        (2068, 0),
        (2072, 2),
    ] {
        kva.write_at(&v.to_ne_bytes(), off).unwrap();
    }
    let mut x = RealXen::open(&o).unwrap();
    let r = x.dom0_ring().unwrap();
    let (m, port) = (r.page, r.port);
    assert_eq!((m.len(), port), (PAGE_SIZE, 7));
    match r.source {
        Dom0Source::Files { kva, port, device } => {
            assert_eq!((kva, port), (o.xsd_kva.clone(), o.xsd_port.clone()));
            assert!(device.is_none(), "not tried");
        }
        other => panic!("{other:?}"),
    }
    let f = ring_fields(&m).unwrap();
    assert_eq!(
        f,
        RingFields {
            req_cons: 1,
            req_prod: 2,
            rsp_cons: 3,
            rsp_prod: 4,
            server_features: 1,
            connection: 0,
            error: 2
        }
    );
    // The mapping is shared with the file.
    kva.write_at(&9u32.to_ne_bytes(), 2052).unwrap();
    assert_eq!(ring_fields(&m).unwrap().req_prod, 9);
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn dom0_ring_errors_name_the_file() {
    let d = Dir::new("dom0err");
    let mut o = fake(&d, RingMapping::Foreign);
    o.xsd_port = d.file("bad_port", b"seven");
    let e = RealXen::open(&o).unwrap().dom0_ring().err().unwrap();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        e.to_string(),
        format!(
            "{}: expected an event channel port number, found \"seven\"",
            o.xsd_port.display()
        )
    );
    o.xsd_port = d.missing("no_port");
    assert!(err_text(RealXen::open(&o).unwrap().dom0_ring()).contains("no_port: No such file"));
    o.xsd_port = d.file("xsd_port", b"7");
    o.xsd_kva = d.missing("no_kva");
    assert!(err_text(RealXen::open(&o).unwrap().dom0_ring()).contains("no_kva: No such file"));
    o.xsd_kva = "/dev/null".into();
    assert!(err_text(RealXen::open(&o).unwrap().dom0_ring()).starts_with("mmap of /dev/null: "));
}

#[test]
#[cfg_attr(miri, ignore = "file-backed mmap: not emulated by Miri")]
fn ring_fields_need_a_whole_ring() {
    let d = Dir::new("short");
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(d.file("short", &[0; 16]))
        .unwrap();
    // SAFETY: the test owns the file and does not truncate it.
    let m = unsafe { Mapping::of_fd(&f, 0, 16) }.unwrap();
    assert_eq!(ring_fields(&m), None);
    // Exactly up to the last word is enough; a byte less is not.
    let mut page = vec![0u8; abi::RING_FIELDS_END];
    for (i, off) in [abi::RING_REQ_CONS, abi::RING_ERROR].into_iter().enumerate() {
        page[off..off + 4].copy_from_slice(&(i as u32 + 7).to_ne_bytes());
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(d.file("ring", &page))
        .unwrap();
    for (len, some) in [(abi::RING_FIELDS_END, true), (abi::RING_FIELDS_END - 1, false)] {
        // SAFETY: the test owns the file and does not truncate it.
        let m = unsafe { Mapping::of_fd(&f, 0, len) }.unwrap();
        let fields = ring_fields(&m);
        assert_eq!(fields.is_some(), some);
        if let Some(r) = fields {
            assert_eq!((r.req_cons, r.req_prod, r.error), (7, 0, 8));
        }
    }
}

fn dom0_files(d: &Dir) -> (PathBuf, PathBuf) {
    (d.file("xsd_kva", &[0; PAGE_SIZE]), d.file("xsd_port", b"7"))
}

/// The page and port a working device would give: /dev/zero's page, port 9.
fn working_device(path: &Path) -> Result<(Mapping, Port), DeviceNotUsed> {
    assert_eq!(path, Path::new("/dev/xen/xenbus_backend"));
    let fd = open_device(Path::new("/dev/zero"), false).unwrap();
    // SAFETY: /dev/zero's page lives with the mapping.
    Ok((unsafe { Mapping::of_fd(&fd, 0, PAGE_SIZE) }.unwrap(), 9))
}

#[test]
#[cfg_attr(miri, ignore = "file-backed mmap: not emulated by Miri")]
fn dom0_ring_comes_from_the_xenbus_backend_device_when_it_works() {
    let d = Dir::new("dom0dev");
    // The files are not read: they do not exist.
    let r = dom0_ring_from(
        Some(Path::new("/dev/xen/xenbus_backend")),
        working_device,
        &d.missing("xsd_kva"),
        &d.missing("xsd_port"),
    )
    .unwrap();
    assert_eq!((r.page.len(), r.port), (PAGE_SIZE, 9));
    assert!(
        matches!(&r.source, Dom0Source::Device(p) if p == Path::new("/dev/xen/xenbus_backend")),
        "{:?}",
        r.source
    );
}

#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn dom0_ring_falls_back_to_the_files_when_the_device_is_missing() {
    let d = Dir::new("dom0nodev");
    let mut o = fake(&d, RingMapping::Foreign);
    o.xenbus_backend = Some(d.missing("xenbus_backend"));
    let r = RealXen::open(&o).unwrap().dom0_ring().unwrap();
    assert_eq!((r.page.len(), r.port), (PAGE_SIZE, 7));
    match r.source {
        Dom0Source::Files {
            kva,
            port,
            device: Some(dev),
        } => {
            assert_eq!((kva, port), (o.xsd_kva, o.xsd_port));
            assert!(dev.missing);
            assert_eq!(dev.error.raw_os_error(), Some(libc::ENOENT));
            assert_eq!(
                dev.to_string(),
                format!(
                    "{}: No such file or directory (os error 2)",
                    d.missing("xenbus_backend").display()
                )
            );
        }
        other => panic!("{other:?}"),
    }
}

/// A device that is there but does not work falls back too, and is not
/// missing: the daemon logs that as a warning.
#[test]
#[cfg_attr(miri, ignore = "open with O_NONBLOCK: not emulated by Miri")]
fn a_device_that_fails_falls_back_and_is_not_missing() {
    let d = Dir::new("dom0baddev");
    let regular = d.file("regular", b"");
    for (dev, error) in [
        // The ioctl is refused. (The Xen driver's ENODEV, when the kernel
        // has no store port, comes from the ioctl too: not missing.)
        (
            PathBuf::from("/dev/zero"),
            "IOCTL_XENBUS_BACKEND_EVTCHN: Inappropriate ioctl for device (os error 25)",
        ),
        (regular.clone(), "not a character device"),
        (d.0.clone(), "Is a directory (os error 21)"),
    ] {
        let mut o = fake(&d, RingMapping::Foreign);
        o.xenbus_backend = Some(dev.clone());
        let r = RealXen::open(&o).unwrap().dom0_ring().unwrap();
        assert_eq!(r.port, 7);
        match r.source {
            Dom0Source::Files { device: Some(e), .. } => {
                assert!(!e.missing, "{e}");
                assert_eq!(e.path, dev);
                assert_eq!(e.error.to_string(), error);
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn only_a_device_that_does_not_exist_counts_as_missing() {
    let os = io::Error::from_raw_os_error;
    for errno in [libc::ENOENT, libc::ENODEV, libc::ENXIO] {
        assert!(missing(&os(errno)), "{errno}");
    }
    for errno in [libc::EACCES, libc::EPERM, libc::ENOTTY, libc::EISDIR, libc::EIO] {
        assert!(!missing(&os(errno)), "{errno}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "Miri's strerror_r appends the error number, so the error text differs; the code before the check runs under Miri"
)]
fn when_the_files_fail_too_the_error_names_both() {
    let d = Dir::new("dom0none");
    let (kva, _) = dom0_files(&d);
    let failed = |_: &Path| -> Result<(Mapping, Port), DeviceNotUsed> {
        Err(DeviceNotUsed {
            path: "/dev/xen/xenbus_backend".into(),
            missing: false,
            error: io::Error::from_raw_os_error(libc::EPERM),
        })
    };
    let e = match dom0_ring_from(
        Some(Path::new("/dev/xen/xenbus_backend")),
        failed,
        &kva,
        &d.missing("no_port"),
    ) {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    };
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
    let msg = e.to_string();
    assert!(
        msg.starts_with("/dev/xen/xenbus_backend: Operation not permitted (os error 1), and ")
            && msg.ends_with("no_port: No such file or directory (os error 2)"),
        "{msg}"
    );
}

#[test]
#[cfg_attr(miri, ignore = "file-backed mmap: not emulated by Miri")]
fn without_a_device_the_files_are_used_and_the_device_is_not_tried() {
    let d = Dir::new("dom0files");
    let (kva, port) = dom0_files(&d);
    let r = dom0_ring_from(None, |_| panic!("tried"), &kva, &port).unwrap();
    assert_eq!(r.port, 7);
    assert!(matches!(r.source, Dom0Source::Files { device: None, .. }));
}

/// The rule of the configuration keys: files other than the defaults are
/// used as given; the defaults, set or not, are the device's fallback.
#[test]
fn configured_files_other_than_the_defaults_win_over_the_device() {
    let d = XenOptions::default();
    let with = |kva: &str, port: &str| XenOptions::default().with_dom0_files(kva.into(), port.into());
    let stock = with("/proc/xen/xsd_kva", "/proc/xen/xsd_port");
    assert_eq!(stock, d, "XCP-ng's oxenstored.conf sets the defaults: device first");
    // Paths compare by component: the same path spelt otherwise.
    assert_eq!(with("/proc/xen//xsd_kva", "/proc/xen/xsd_port/"), d);
    for (kva, port) in [
        ("/k", "/proc/xen/xsd_port"),
        ("/proc/xen/xsd_kva", "/p"),
        ("/k", "/p"),
        ("/dev/xen/xenbus_backend", "/proc/xen/xsd_port"),
    ] {
        let o = with(kva, port);
        assert_eq!(o.xenbus_backend, None, "{kva} {port}");
        assert_eq!((o.xsd_kva, o.xsd_port), (kva.into(), port.into()));
        assert_eq!(o.evtchn, d.evtchn);
    }
    // No device to begin with: none after.
    let o = XenOptions {
        xenbus_backend: None,
        ..XenOptions::default()
    }
    .with_dom0_files(d.xsd_kva.clone(), d.xsd_port.clone());
    assert_eq!(o.xenbus_backend, None);
}
