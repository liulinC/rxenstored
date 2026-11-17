// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! rxenstored: serves the xenstore protocol, started as oxenstored is.
//!
//! Start-up: read the command line and the configuration (warnings on
//! stderr), become a daemon unless `--no-fork`, then in the daemon bind
//! the socket (unless `--disable-socket`) and create the core, open Xen
//! and serve dom0's ring (unless `--no-domain-init`; the event loop is
//! `xs_daemon::reactor`), write the pid files, send `READY=1` to
//! `$NOTIFY_SOCKET`, and only then let the process that was started exit
//! 0. A failure before that point makes it exit 1 with the error. The pid
//! files are removed when the daemon stops, so that launch-xenstore will
//! start a new one (`ox/xenstored.ml:607-609`).

#![forbid(unsafe_code)]
// The no-panic lints of Cargo.toml are for code that is not a test; this
// crate's test build (unit tests) may unwrap, index and panic.
#![cfg_attr(
    test,
    allow(
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
    )
)]

mod config;
mod options;

use config::{FileConfig, Trouble};
use options::{Args, USAGE};
use std::ffi::OsString;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use xs_daemon::log::{self, Logger};
use xs_daemon::reactor;
use xs_sys::process::{self, Daemonized, Readiness};
use xs_sys::xen::{RealXen, XenOptions};

/// What the command line and the configuration ask for.
#[derive(Debug)]
enum Plan {
    Usage,
    ConfigValid(PathBuf),
    Start(Box<Start>),
}

#[derive(Debug)]
enum Failure {
    /// A bad command line: exit 2, as OCaml's Arg does.
    Usage(String),
    Fatal(String),
}

#[derive(Debug)]
struct Start {
    options: reactor::Options,
    daemonize: bool,
    /// The configuration's `pid-file`: a failure to write it is only
    /// reported (`ox/xenstored.ml:362`).
    config_pid_file: Option<PathBuf>,
    /// `--pid-file`: a failure to write it is fatal (`ox/xenstored.ml:364-367`).
    pid_file: Option<PathBuf>,
    notify_socket: Option<OsString>,
    log: xs_daemon::log::Settings,
}

/// Reads the command line and the configuration; what deserves a warning
/// on stderr goes to `warn`.
fn plan(argv: &[OsString], notify_socket: Option<OsString>, warn: &mut Vec<String>) -> Result<Plan, Failure> {
    let args = options::parse(argv).map_err(Failure::Usage)?;
    // Before --help: oxenstored checks a live update by running the new
    // binary with `--live --restart <its arguments> --help` and goes ahead
    // on exit 0 (`ox/process.ml:123-141`). It would then exec us with a
    // dump we cannot load and the host would lose its store: refuse here,
    // so that oxenstored keeps running.
    if args.live || args.restart {
        return Err(Failure::Fatal(
            "--live and --restart (live update) are not supported: refusing to take over".into(),
        ));
    }
    if args.help {
        return Ok(Plan::Usage);
    }
    if args.trace_file.is_some() {
        warn.push("-T: trace files are not implemented yet, ignored".into());
    }
    for a in &args.ignored {
        warn.push(format!("ignoring argument '{}'", a.to_string_lossy()));
    }
    let path = args
        .config_file
        .clone()
        .unwrap_or_else(|| options::DEFAULT_CONFIG.into());
    if args.config_test {
        read_config(&path, true, true, warn)
            .map_err(|e| Failure::Fatal(format!("{e}\nconfiguration not valid at {}", path.display())))?;
        return Ok(Plan::ConfigValid(path));
    }
    let cf = read_config(&path, args.config_file.is_some(), false, warn).map_err(Failure::Fatal)?;
    Ok(Plan::Start(Box::new(start_of(&args, cf, notify_socket))))
}

/// Reads the configuration file. `strict` (`--config-test`): every
/// problem is an error, and so is a missing file. Otherwise, as oxenstored
/// does, problems are warnings and the defaults stand in for what could
/// not be read, a missing file included. Either way `persistent = true`
/// is an error: the store is in memory only, and a key rxenstored accepts
/// but does not honour, set to other than its default, is a warning.
fn read_config(path: &Path, explicit: bool, strict: bool, warn: &mut Vec<String>) -> Result<FileConfig, String> {
    let text = match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) if strict => return Err(format!("config: {}: {e}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound && !explicit => return Ok(FileConfig::default()),
        Err(e) => {
            warn.push(format!("config: {}: {e}; using the defaults", path.display()));
            return Ok(FileConfig::default());
        }
    };
    let (mut cf, problems) = config::parse(&text);
    let mut errors = Vec::new();
    for p in problems {
        if strict && p.trouble != Trouble::NoEquals {
            errors.push(p.to_string());
        } else {
            warn.push(p.to_string());
        }
    }
    // Sizes: OCaml would take a negative one; here it cannot be a limit.
    let default = FileConfig::default();
    for (key, value, fallback) in [
        ("quota-maxsize", &mut cf.quota_maxsize, default.quota_maxsize),
        ("quota-path-max", &mut cf.quota_path_max, default.quota_path_max),
    ] {
        if *value < 0 {
            let p = format!("config: {key}: expect a non-negative int");
            if strict {
                errors.push(p);
            } else {
                warn.push(p);
            }
            *value = fallback;
        }
    }
    warn.extend(cf.not_honoured());
    if cf.persistent {
        errors.push("config: persistent = true is not supported: the store is kept in memory only".into());
    }
    if errors.is_empty() {
        Ok(cf)
    } else {
        Err(errors.join("\n"))
    }
}

fn start_of(args: &Args, cf: FileConfig, notify_socket: Option<OsString>) -> Start {
    let mut config = xs_core::Config {
        path_max: cf.quota_path_max as usize,
        // Without quotas oxenstored does not check sizes (`ox/quota.ml:56-58`).
        value_max: if cf.quota_activate {
            cf.quota_maxsize as usize
        } else {
            usize::MAX
        },
        perms_activate: cf.perms_activate,
        perms_watch_activate: cf.perms_watch_activate,
        ..xs_core::Config::default()
    };
    cf.apply_quotas(&mut config);
    cf.apply_conflicts(&mut config);
    let log = cf.log_settings(args.access_log, &ident());
    Start {
        options: reactor::Options {
            socket: args.socket.clone(),
            disable_socket: args.disable_socket,
            domain_init: args.domain_init,
            ring_scan: cf.ring_scan(),
            xsd_kva: cf.xenstored_kva,
            xsd_port: cf.xenstored_port,
            config,
        },
        daemonize: args.daemonize,
        config_pid_file: (!cf.pid_file.as_os_str().is_empty()).then_some(cf.pid_file),
        pid_file: args.pid_file.clone(),
        notify_socket,
        log,
    }
}

/// As oxenstored writes it (`ox/stdext.ml:141-153`), creating the missing
/// directories with mode 0755 as it does for the configuration's pid file
/// (`ox/xenstored.ml:342-347`).
fn write_pid_file(path: &Path, pid: u32) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::DirBuilder::new().recursive(true).mode(0o755).create(dir)?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .open(path)?;
    f.write_all(format!("{pid}\n").as_bytes())
}

/// Called by the reactor once initialised: pid files, systemd, then the
/// waiting parent. `written` collects the pid files to remove at the end.
fn announce(s: &Start, written: &mut Vec<PathBuf>, pending: &mut Option<Readiness>) -> io::Result<()> {
    let pid = std::process::id();
    if let Some(p) = &s.config_pid_file {
        match write_pid_file(p, pid) {
            Ok(()) => written.push(p.clone()),
            Err(e) => xs_daemon::echo!(Always, Warn, "xenstored", "pid file {}: {e}", p.display()),
        }
    }
    if let Some(p) = &s.pid_file {
        write_pid_file(p, pid).map_err(|e| io::Error::new(e.kind(), format!("pid file {}: {e}", p.display())))?;
        written.push(p.clone());
    }
    if let Some(socket) = &s.notify_socket {
        // oxenstored sends READY=1 only (`ox/systemd_stubs.c:34`); MAINPID
        // makes systemd follow the daemon rather than the launcher.
        if let Err(e) = process::notify(socket, &format!("READY=1\nMAINPID={pid}\n")) {
            xs_daemon::echo!(
                Always,
                Warn,
                "xenstored",
                "NOTIFY_SOCKET {}: {e}",
                socket.to_string_lossy()
            );
        }
    }
    if let Some(r) = pending.take() {
        // A parent that is gone has nobody to tell: serve anyway.
        let _ = r.ready();
    }
    Ok(())
}

/// The devices of a dom0, at their usual places; dom0's ring where the
/// configuration says.
fn xen_options(o: &reactor::Options) -> XenOptions {
    XenOptions {
        xsd_kva: o.xsd_kva.clone(),
        xsd_port: o.xsd_port.clone(),
        ..XenOptions::default()
    }
}

fn open_xen(o: &reactor::Options) -> io::Result<RealXen> {
    let xo = xen_options(o);
    let xen = RealXen::open(&xo)?;
    // cov:excl-start xen-opened
    xs_daemon::echo!(
        Always,
        Info,
        "xenstored",
        "Xen devices opened: {} and {xen:?}",
        xo.evtchn.display()
    );
    Ok(xen)
} // cov:excl-stop xen-opened

/// The program name, as `syslog(3)` takes it when `openlog` was not
/// called (glibc's `__progname`).
fn ident() -> String {
    let argv0 = std::env::args_os().next().unwrap_or_default();
    Path::new(&argv0)
        .file_name()
        .map_or_else(|| "rxenstored".into(), |n| n.to_string_lossy().into_owned())
}

/// Runs the daemon in this process, reporting to `readiness`. The logs
/// start here: after the fork, which a thread would not survive, and
/// before anything worth logging.
fn serve(s: &Start, readiness: Readiness) -> ExitCode {
    let logger = match Logger::start(&s.log) {
        Ok(l) => Some(l),
        Err(e) => {
            log::stderr(format_args!("cannot start the log thread: {e}: logging to stderr"));
            None
        }
    };
    if let Some(l) = &logger {
        l.install();
    }
    let mut pending = Some(readiness);
    let mut written = Vec::new();
    let result = reactor::run(
        &s.options,
        || open_xen(&s.options),
        None,
        || announce(s, &mut written, &mut pending),
    );
    for p in &written {
        let _ = fs::remove_file(p);
    }
    if let Err(e) = &result {
        xs_daemon::error!("xenstored", "{e}");
    }
    // What is queued is written before the process ends.
    log::uninstall();
    drop(logger);
    let Err(e) = result else { return ExitCode::SUCCESS };
    let message = e.to_string();
    // Not yet ready: the parent prints it, if there is one to tell.
    let told = match pending {
        Some(r) if r.is_piped() => r.failed(&message).is_ok(),
        _ => false,
    };
    if !told {
        log::stderr(format_args!("{message}"));
    }
    ExitCode::from(1)
}

fn main() -> ExitCode {
    xs_daemon::fatal::install_panic_hook();
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut warnings = Vec::new();
    let plan = plan(&argv, std::env::var_os("NOTIFY_SOCKET"), &mut warnings);
    for w in &warnings {
        log::stderr(format_args!("{w}"));
    }
    let s = match plan {
        Err(Failure::Usage(e)) => {
            log::stderr(format_args!("{e}\n\n{USAGE}"));
            return ExitCode::from(2);
        }
        Err(Failure::Fatal(e)) => {
            log::stderr(format_args!("{e}"));
            return ExitCode::from(1);
        }
        // What was asked was done; a stdout that cannot be written
        // changes nothing to it (`print!` would panic).
        Ok(Plan::Usage) => {
            let _ = io::stdout().write_all(USAGE.as_bytes());
            return ExitCode::SUCCESS;
        }
        Ok(Plan::ConfigValid(path)) => {
            let _ = writeln!(io::stdout(), "Configuration valid at {}", path.display());
            return ExitCode::SUCCESS;
        }
        Ok(Plan::Start(s)) => s,
    };
    if !s.daemonize {
        return serve(&s, Readiness::unpiped());
    }
    // No thread has been started: nothing here or in the standard
    // library's start-up starts one, and the reactor, which may, runs
    // after this. stderr stays if it is not a terminal (the journal under
    // systemd, a file, a pipe): it is the daemon's only log for now.
    match process::daemonize(!io::stderr().is_terminal()) {
        Ok(Daemonized::Daemon(readiness)) => serve(&s, readiness),
        Ok(Daemonized::Parent(Ok(()))) => ExitCode::SUCCESS,
        Ok(Daemonized::Parent(Err(e))) => {
            log::stderr(format_args!("{e}"));
            ExitCode::from(1)
        }
        Err(e) => {
            log::stderr(format_args!("cannot become a daemon: {e}"));
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixDatagram;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A fresh directory, removed on drop.
    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            let d = std::env::temp_dir().join(format!(
                "rxenstored-main-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(&d).unwrap();
            Dir(d)
        }

        fn file(&self, name: &str, text: &str) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, text).unwrap();
            p
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn run_plan(argv: &[&str]) -> (Result<Plan, Failure>, Vec<String>) {
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        let mut warn = Vec::new();
        let p = plan(&argv, Some("/notify".into()), &mut warn);
        (p, warn)
    }

    fn started(argv: &[&str]) -> (Start, Vec<String>) {
        match run_plan(argv) {
            (Ok(Plan::Start(s)), w) => (*s, w),
            (other, _) => panic!("{other:?}"),
        }
    }

    fn fatal(argv: &[&str]) -> String {
        match run_plan(argv).0 {
            Err(Failure::Fatal(e)) => e,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_host_start() {
        let d = Dir::new();
        let conf = d.file("oxenstored.conf", "pid-file = /var/run/xen/xenstored.pid\nquota-maxsize = 2048\nquota-path-max = 1024\nquota-maxentity = 8192\nquota-maxwatch = 512\nperms-watch-activate = false\nxenstored-kva = /k\nxenstored-port = /p\n");
        let (s, warn) = started(&[
            "--config-file",
            conf.to_str().unwrap(),
            "--pid-file",
            "/var/run/xen/xenstored.pid",
        ]);
        assert_eq!(warn, Vec::<String>::new());
        assert!(s.daemonize);
        assert_eq!(s.config_pid_file, Some("/var/run/xen/xenstored.pid".into()));
        assert_eq!(s.pid_file, Some("/var/run/xen/xenstored.pid".into()));
        assert_eq!(s.notify_socket, Some("/notify".into()));
        let o = &s.options;
        assert_eq!(o.socket, PathBuf::from(options::DEFAULT_SOCKET));
        assert!(o.domain_init && !o.disable_socket);
        assert_eq!(
            (o.xsd_kva.as_path(), o.xsd_port.as_path()),
            (Path::new("/k"), Path::new("/p"))
        );
        // And on to the devices, the others at their usual places.
        let xo = xen_options(o);
        assert_eq!((xo.xsd_kva, xo.xsd_port), ("/k".into(), "/p".into()));
        assert_eq!(xo.evtchn, XenOptions::default().evtchn);
        assert_eq!((o.config.value_max, o.config.path_max), (2048, 1024));
        assert!(o.config.perms_activate && !o.config.perms_watch_activate);
        // The quotas of the file, not the code's defaults.
        assert_eq!((o.config.entity_max, o.config.watch_max), (8192, Some(512)));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "under Miri the program name (argv[0]) is the source file's, which the test checks"
    )]
    fn options_reach_the_reactor() {
        let d = Dir::new();
        let conf = d.file("c", "quota-activate = false\nperms-activate = false\npid-file =\n");
        let (s, warn) = started(&[
            "--config-file",
            conf.to_str().unwrap(),
            "--no-fork",
            "--no-domain-init",
            "--disable-socket",
            "--socket",
            "/s",
            "-T",
            "/t",
            "stray",
            "--no-access-log",
            "--reraise-top-level",
        ]);
        assert!(!s.daemonize);
        assert_eq!(s.config_pid_file, None);
        assert_eq!(s.pid_file, None);
        assert!(!s.options.domain_init && s.options.disable_socket);
        assert_eq!(s.options.socket, PathBuf::from("/s"));
        assert_eq!(s.options.config.value_max, usize::MAX);
        assert!(!s.options.config.perms_activate);
        assert_eq!(s.options.xsd_kva, PathBuf::from("/proc/xen/xsd_kva"));
        assert_eq!(
            warn,
            [
                "-T: trace files are not implemented yet, ignored",
                "ignoring argument 'stray'"
            ]
        );
        assert_eq!(s.log.access, None, "--no-access-log");
        assert!(s.log.daemon.is_some());
        assert!(ident().starts_with("rxenstored"), "{}", ident());
    }

    #[test]
    fn help_usage_and_live_update() {
        assert!(matches!(run_plan(&["--help"]).0, Ok(Plan::Usage)));
        assert!(
            matches!(run_plan(&["--help", "--live"]).0, Ok(Plan::Usage)),
            "not read after --help"
        );
        assert!(matches!(run_plan(&["--bogus"]).0, Err(Failure::Usage(e)) if e.contains("--bogus")));
        for argv in [
            &["--live", "--restart", "--pid-file", "/p", "--help"][..],
            &["--restart"],
            &["--live"],
            &["--live", "--config-test"],
        ] {
            assert!(fatal(argv).contains("not supported"), "{argv:?}");
        }
    }

    #[test]
    fn config_files() {
        let d = Dir::new();
        let missing = d.0.join("missing");
        let m = missing.to_str().unwrap();
        // A missing file: the defaults, with a warning if it was named.
        let (s, warn) = started(&["--config-file", m]);
        assert_eq!(s.config_pid_file, Some(config::DEFAULT_PID_FILE.into()));
        assert_eq!(warn.len(), 1);
        assert!(warn[0].starts_with(&format!("config: {m}: ")), "{warn:?}");
        let mut warn = Vec::new();
        assert_eq!(
            read_config(&missing, false, false, &mut warn),
            Ok(FileConfig::default())
        );
        assert!(warn.is_empty());
        // Unreadable: a directory.
        let (_, warn) = started(&["--config-file", d.0.to_str().unwrap()]);
        assert!(warn[0].ends_with("; using the defaults"), "{warn:?}");
        // Problems are warnings; the defaults stand.
        let bad = d.file(
            "bad",
            "quota-maxsize = big\nfrob = 1\nnonsense\nquota-path-max = -1\nquota-maxsize = -3\n",
        );
        let (s, warn) = started(&["--config-file", bad.to_str().unwrap()]);
        assert_eq!(
            warn,
            [
                "config: line 1: quota-maxsize: expect int arg",
                "config: line 2: unknown key frob",
                "config: line 3: no '=', ignored",
                "config: quota-maxsize: expect a non-negative int",
                "config: quota-path-max: expect a non-negative int",
            ]
        );
        assert_eq!((s.options.config.value_max, s.options.config.path_max), (2048, 2048));
        // 0 is a size like any other.
        let zero = d.file("zero", "quota-maxsize = 0\nquota-path-max = 0\n");
        let (s, warn) = started(&["--config-file", zero.to_str().unwrap()]);
        assert_eq!(warn, Vec::<String>::new());
        assert_eq!((s.options.config.value_max, s.options.config.path_max), (0, 0));
        // Keys rxenstored does not honour: a warning, and the start goes on.
        let dbg = d.file("dbg", "allow-debug = true\nquota-maxentity = 8192\n");
        let (s, warn) = started(&["--config-file", dbg.to_str().unwrap()]);
        assert_eq!(warn.len(), 1);
        assert!(
            warn[0].starts_with("config: allow-debug = true is not honoured: rxenstored never lets a guest"),
            "{warn:?}"
        );
        assert_eq!(s.options.config.entity_max, 8192);
        // But persistence is refused.
        let p = d.file("p", "persistent = true\n");
        assert!(fatal(&["--config-file", p.to_str().unwrap()]).contains("persistent = true is not supported"));
    }

    #[test]
    fn config_test() {
        let d = Dir::new();
        let good = d.file("good", "# fine\nquota-maxsize = 10\nno equals here\n");
        let (p, warn) = run_plan(&["--config-test", "--config-file", good.to_str().unwrap()]);
        assert!(matches!(p, Ok(Plan::ConfigValid(ref path)) if *path == good), "{p:?}");
        assert_eq!(warn, ["config: line 3: no '=', ignored"]);
        // A key that is not honoured: said so, and the file is still valid.
        let dbg = d.file("dbg", "allow-debug = true\ntest-eagain = true\n");
        let (p, warn) = run_plan(&["--config-test", "--config-file", dbg.to_str().unwrap()]);
        assert!(matches!(p, Ok(Plan::ConfigValid(_))), "{p:?}");
        assert_eq!(warn.len(), 2);
        assert!(
            warn[0].starts_with("config: test-eagain = true is not honoured"),
            "{warn:?}"
        );
        assert!(
            warn[1].starts_with("config: allow-debug = true is not honoured"),
            "{warn:?}"
        );
        for text in [
            "frob = 1\n",
            "quota-maxsize = x\n",
            "quota-path-max = -1\n",
            "persistent = true\n",
        ] {
            let bad = d.file("bad", text);
            let e = fatal(&["--config-test", "--config-file", bad.to_str().unwrap()]);
            assert!(
                e.ends_with(&format!("\nconfiguration not valid at {}", bad.display())),
                "{text}: {e}"
            );
        }
        let e = fatal(&["--config-test", "--config-file", d.0.join("missing").to_str().unwrap()]);
        assert!(e.contains("No such file"), "{e}");
        // The default path, which this machine does not have.
        if !Path::new(options::DEFAULT_CONFIG).exists() {
            assert!(fatal(&["--config-test"]).contains(options::DEFAULT_CONFIG));
        }
    }

    #[test]
    fn pid_files() {
        let d = Dir::new();
        let p = d.0.join("a/b/pid");
        write_pid_file(&p, 42).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "42\n");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::metadata(d.0.join("a")).unwrap().permissions().mode() & 0o777, 0o755);
        write_pid_file(&p, 7).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "7\n", "truncated");
        // A relative name with no directory part.
        let cwd_pid = PathBuf::from(format!("rxenstored-pid-{}", std::process::id()));
        write_pid_file(&cwd_pid, 1).unwrap();
        fs::remove_file(&cwd_pid).unwrap();
        assert!(write_pid_file(Path::new("/proc/rxenstored/pid"), 1).is_err());
        assert!(write_pid_file(&d.0, 1).is_err(), "a directory");
    }

    fn start_in(d: &Dir, notify: Option<OsString>) -> Start {
        let (mut s, _) = started(&["--config-file", d.0.join("none").to_str().unwrap()]);
        s.config_pid_file = Some(d.0.join("conf/pid"));
        s.pid_file = Some(d.0.join("arg/pid"));
        s.notify_socket = notify;
        s
    }

    #[test]
    #[cfg_attr(miri, ignore = "AF_UNIX sockets: not emulated by Miri")]
    fn announce_writes_notifies_and_releases() {
        let d = Dir::new();
        let sock = d.0.join("notify");
        let listener = UnixDatagram::bind(&sock).unwrap();
        let s = start_in(&d, Some(sock.clone().into()));
        let (r, w) = std::io::pipe().unwrap();
        drop(r);
        // A parent that is gone does not stop the daemon.
        let mut pending = Some(Readiness::on_pipe(w));
        let mut written = Vec::new();
        announce(&s, &mut written, &mut pending).unwrap();
        assert!(pending.is_none());
        assert_eq!(written, [d.0.join("conf/pid"), d.0.join("arg/pid")]);
        let me = format!("{}\n", std::process::id());
        assert_eq!(fs::read_to_string(&written[1]).unwrap(), me);
        let mut buf = [0u8; 128];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(
            std::str::from_utf8(&buf[..n]).unwrap(),
            format!("READY=1\nMAINPID={me}")
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "AF_UNIX sockets: not emulated by Miri")]
    fn announce_failures() {
        let d = Dir::new();
        // The configuration's pid file and the notification may fail.
        let mut s = start_in(&d, Some("/proc/rxenstored/notify".into()));
        s.config_pid_file = Some("/proc/rxenstored/pid".into());
        let mut pending = Some(Readiness::unpiped());
        let mut written = Vec::new();
        announce(&s, &mut written, &mut pending).unwrap();
        assert_eq!(written, [d.0.join("arg/pid")]);
        // --pid-file may not; the parent is still owed a report.
        s.pid_file = Some("/proc/rxenstored/pid".into());
        let mut pending = Some(Readiness::unpiped());
        let e = announce(&s, &mut Vec::new(), &mut pending).unwrap_err();
        assert!(e.to_string().starts_with("pid file /proc/rxenstored/pid: "), "{e}");
        assert!(pending.is_some());
        s.pid_file = None;
        s.config_pid_file = None;
        s.notify_socket = None;
        announce(&s, &mut Vec::new(), &mut Some(Readiness::unpiped())).unwrap();
    }
}
