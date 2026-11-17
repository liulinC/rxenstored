// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use xs_bench::run::{ramp, Band, Config};
use xs_bench::scenario::Scenario;

const USAGE: &str = "\
xs-bench: load generator for any xenstored

  xs-bench ramp --scenario DIR --vms N [options]
      Replays the scenario's VM start once per simulated VM and reports,
      per band of VMs, what a start costs as the population grows.
      --socket PATH     daemon socket (default /var/run/xenstored/socket)
      --parallel N      concurrent VM starts (default 16)
      --band N          VMs per measurement band (default 50)
      --prefix PATH     prepended to every path, removed at the end
                        (default /rxsbench; give '' on a private daemon)
      --first-domid N   domid of the first simulated VM (default 10000)
      --daemon-pid PID  read the daemon's CPU time and memory from /proc
      --teardown        then replay the VM stop for every VM
      --keep            leave the nodes in the store at the end
      --csv FILE        also write every band to FILE
      --timeout-s N     give up on a request after N seconds (default 120)

  xs-bench census --scenario DIR
      Prints what the scenario holds.
";

fn parse_args(args: &[String]) -> Result<(Config, PathBuf, Option<PathBuf>), String> {
    let mut cfg = Config {
        socket: "/var/run/xenstored/socket".into(),
        prefix: "/rxsbench".into(),
        vms: 0,
        parallel: 16,
        band: 50,
        first_domid: 10000,
        daemon_pid: None,
        teardown: false,
        keep: false,
        timeout: Duration::from_secs(120),
    };
    let mut scenario = None;
    let mut csv = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().cloned().ok_or(format!("{arg} needs a value"));
        let num = |v: String| v.parse::<u32>().map_err(|_| format!("{arg}: not a number: {v}"));
        match arg.as_str() {
            "--socket" => cfg.socket = value()?.into(),
            "--scenario" => scenario = Some(PathBuf::from(value()?)),
            "--vms" => cfg.vms = num(value()?)?,
            "--parallel" => cfg.parallel = num(value()?)? as usize,
            "--band" => cfg.band = num(value()?)?,
            "--prefix" => cfg.prefix = value()?,
            "--first-domid" => cfg.first_domid = num(value()?)?,
            "--daemon-pid" => cfg.daemon_pid = Some(num(value()?)?),
            "--teardown" => cfg.teardown = true,
            "--keep" => cfg.keep = true,
            "--csv" => csv = Some(PathBuf::from(value()?)),
            "--timeout-s" => cfg.timeout = Duration::from_secs(num(value()?)? as u64),
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok((cfg, scenario.ok_or("--scenario is required")?, csv))
}

fn census(scenario: &Scenario) {
    let phases = [("start", Some(&scenario.start)), ("stop", scenario.stop.as_ref())];
    println!("shared connections: {:?}", scenario.shared);
    println!("baseline requests on them: {}", scenario.baseline.len());
    for (name, phase) in phases {
        let Some(phase) = phase else { continue };
        let c = &phase.census;
        println!(
            "\n{name}: {} requests replayed, {} watch events in the recording",
            c.total_requests(),
            c.total_events()
        );
        for ((conn, op), n) in &c.requests {
            let class = if scenario.shared.contains(conn) {
                "shared"
            } else {
                "per VM"
            };
            println!("  {n:>5}  {conn:?} ({class}) {op}");
        }
        for (what, n) in &c.skipped {
            println!("  {n:>5}  not replayed: {what}");
        }
    }
    println!("\nwatches left registered per running VM:");
    for (conn, n) in scenario.watches_per_vm() {
        println!("  {n:>5}  {conn:?}");
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = parse_args(rest).and_then(|(cfg, dir, csv)| {
        let scenario = Scenario::load(&dir)?;
        match command.as_str() {
            "census" => {
                census(&scenario);
                Ok(true)
            }
            "ramp" => {
                let fds = xs_bench::poller::raise_fd_limit().map_err(|e| format!("open file limit: {e}"))?;
                // Four long-lived connections per VM in the shipped scenario, plus short-lived ones.
                let needed = cfg.vms as u64 * 5 + 256;
                if fds < needed {
                    return Err(format!(
                        "{} VMs may need {needed} open files, the limit is {fds}",
                        cfg.vms
                    ));
                }
                println!("{}", Band::header());
                let report = ramp(&cfg, &scenario, |band| println!("{}", band.row()))?;
                if let Some(path) = csv {
                    let mut text = Band::csv_header() + "\n";
                    for band in &report.bands {
                        text += &(band.csv_row() + "\n");
                    }
                    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
                }
                let errors = report.errors();
                for (what, n) in &errors {
                    println!("error  {n:>7}  {what}");
                }
                Ok(errors.is_empty())
            }
            other => Err(format!("unknown command {other}\n\n{USAGE}")),
        }
    });
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("xs-bench: {e}");
            ExitCode::from(2)
        }
    }
}
