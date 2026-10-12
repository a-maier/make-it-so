//! Make It So is a task runner library that only runs a task if
//!
//! - it is new or has changed since the last run, e.g. because
//!   there are new arguments
//! - or any of the files the task touches has changed since the
//!   last run
//! - or the last run didn't finish successfully, meaning that a
//!   command returned with a non-zero exit status.
//!
//! Currently, only Linux x86_64 is supported.
//!
//! # How?
//!
//! ```
//! # use std::path::{Path, PathBuf};
//! # use make_it_so::{RunError, Runner, Task};
//! // Create a runner
//! // use `with_cache` for a persistent (on-disk) dependency cache
//! let mut runner = Runner::default();
//! let mut runner = Runner::with_cache(".dependencies.yaml".into())?;
//!
//! // The "recipe", i.e. a block of commands to be run
//! // Use `Command` for more complicated stuff
//! let cmd = [["/bin/sh", "-c", "echo Hello, world!"]];
//!
//! // Run the "greet everyone" task once
//! let run = runner.run("greet everyone", cmd)?;
//! assert!(run);
//!
//! // Don't run it again,
//! // unless e.g. `/bin/sh` has changed in the mean time
//! let run = runner.run("greet everyone", cmd)?;
//! assert!(!run);
//!
//! // Manually tweak dependencies
//! let task = Task {
//!     name: "greet everyone".into(),
//!     cmds: vec![cmd[0].into()]
//! };
//! let dependencies = runner.cache.get_mut(&task).unwrap();
//! dependencies.0.remove(Path::new("/etc/ld.so.cache"));
//! # Ok::<(), RunError>(())
//! ```
//!
//! Enable [log::Level::Info](https://docs.rs/log/latest/log/enum.Level.html#variant.Info)
//! to see which tasks get run and which ones don't.
//! Enable [log::Level::Debug](https://docs.rs/log/latest/log/enum.Level.html#variant.Debug)
//! to see _why_ a task is being run and which commands are part of it.
//! Enable [log::Level::Trace](https://docs.rs/log/latest/log/enum.Level.html#variant.Trace)
//! if you like walls of text.
//!
//! # Why?
//!
//! I often have a long-running series of commands (up to a few
//! weeks of wall clock time) and don't want to start all over
//! again whenever something goes wrong. However, I _do_ want to
//! be sure that the necessary bits get updated when I tinker with
//! the setup.
//!
//! There are quite a few existing alternatives:
//!
//! - With a shell script it's hard to figure out which parts have
//!   to be rerun. Error handling is also a challenge.
//!
//! - `make` gets very close to what I need, but you have to specify
//!   the task prerequisites manually. A nice feature is that `make`
//!   then knows in which order to run the tasks, but for me that's
//!   not really needed. In more complex setups like mine
//!   Makefiles quickly get hard to write, read, and debug.
//!
//! - To my understanding, [just](https://crates.io/crates/just)
//!   makes no attempt to skip up-to-date tasks.
//!
//! - [snakemake](https://snakemake.github.io/) and
//!   [doit](https://pydoit.org/index.html)
//!   use Python, which I don't know well and have always had a
//!   hard time getting to run. Otherwise similar to `make` in
//!   that I have to specify requirements manually and in turn get
//!   automatic resolution of inter-task dependencies.
//!
//! # How Does it Work?
//!
//! Commands are run under [ptrace](https://en.wikipedia.org/wiki/Ptrace).
//! Any system call that tries to access a file is intercepted and
//! the file is added to the set of task dependencies. After the
//! task finishes, we check for each of the files if it exists and
//! when it was last modified. The next time the task is started,
//! we check if anything has changed in the mean time.
//!
//! # Distant (?) Future Plans
//!
//! [ ] Support more architectures and operating systems.
//! [ ] Look into eBPF to lower overhead.
//! [ ] Use a DAG for inter-task dependencies.
mod syscalls;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::{Read, Write},
    num::NonZeroI32,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

use bon::Builder;
use log::{debug, info, trace, warn};
use pete::{Ptracer, Restart};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use syscalls::SyscallAction::*;
use tempfile::NamedTempFile;
use thiserror::Error;

/// The task runner
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct Runner {
    /// Dependency cache
    pub cache: HashMap<Task, Dependencies>,
    #[serde(skip)]
    cache_path: PathBuf,
}

impl Runner {
    /// Create a task runner associated with the given YAML cache file
    ///
    /// If the file does not exist, it will be created
    pub fn with_cache(p: PathBuf) -> Result<Self, IOError> {
        let mut res = if p.exists() {
            Self::import(&p)?
        } else {
            Self::default()
        };
        res.cache_path = p;
        Ok(res)
    }

    fn import(p: impl AsRef<Path>) -> Result<Self, IOError> {
        Self::from_reader(File::open(p)?)
    }

    fn from_reader(reader: impl Read) -> Result<Self, IOError> {
        let res = yaml_serde::from_reader(reader)?;
        Ok(res)
    }

    /// Save the dependencies to the associated YAML cache file
    pub fn save(&self) -> Result<(), IOError> {
        let target_dir =
            self.cache_path.parent().expect("Cache path has no parent");
        let mut outfile = NamedTempFile::new_in(target_dir)?;
        self.write_dependencies(&mut outfile)?;
        outfile.persist(&self.cache_path)?;
        Ok(())
    }

    /// Write out the dependencies in YAML format
    pub fn write_dependencies(&self, p: impl Write) -> Result<(), IOError> {
        yaml_serde::to_writer(p, &self)?;
        Ok(())
    }

    /// Run one task if it is not up to date
    ///
    /// Updates the dependencies and saves them to the cache file.
    /// Returns `true` if the task was actually run.
    pub fn run<I>(
        &mut self,
        name: impl Into<String>,
        cmds: impl IntoIterator<Item = I>,
    ) -> Result<bool, RunError>
    where
        I: Into<Command>,
    {
        let name = name.into();
        let cmds = cmds.into_iter().map(|c| c.into()).collect();
        self.run_task(Task { name, cmds })
    }

    /// Run one task if it is not up to date
    ///
    /// Updates the dependencies and saves them to the cache file.
    /// Returns `true` if the task was actually run.
    pub fn run_task(&mut self, task: Task) -> Result<bool, RunError> {
        let name = &task.name;
        debug!("Checking dependencies of task {name}");
        if self.is_up_to_date(&task) {
            info!("{name} is up to date");
            return Ok(false);
        }
        // remove from cache so that the command is considered
        // out of date if it fails now
        self.cache.remove(&task);
        let mut dependencies = BTreeSet::default();
        info!("Running {name}");
        for cmd in &task.cmds {
            dependencies.append(&mut self.force_run_cmd(cmd)?);
        }
        self.cache
            .insert(task, Dependencies::from_iter(dependencies));
        self.save()?;
        Ok(true)
    }

    #[cfg(feature = "rayon")]
    /// Run several tasks in parallel
    ///
    /// Skips all tasks that are up to date. Updates the dependencies
    /// and saves them to the cache file.
    /// See the [rayon documentation](https://docs.rs/rayon/latest/rayon/)
    /// for how to configure the number of threads.
    pub fn run_tasks(&mut self, mut tasks: Vec<Task>) -> Result<(), RunError> {
        tasks.retain(|t| {
            let name = &t.name;
            debug!("Checking dependencies of task {name}");
            let up_to_date = self.is_up_to_date(t);
            if up_to_date {
                info!("{name} is up to date")
            };
            !up_to_date
        });

        // remove from cache so that each failing task is considered
        // out of date next time
        for task in &tasks {
            self.cache.remove(task);
        }

        let res: Vec<Result<_, RunError>> = tasks
            .into_par_iter()
            .map(|t| {
                let mut dependencies = BTreeSet::default();
                info!("Running {}", t.name);
                for cmd in &t.cmds {
                    dependencies.append(&mut self.force_run_cmd(cmd)?);
                }
                Ok((t, dependencies))
            })
            .collect();

        // save dependencies for all successful tasks
        for (task, dep) in res.iter().filter_map(|t| t.as_ref().ok()).cloned() {
            self.cache.insert(task, Dependencies::from_iter(dep));
        }
        self.save()?;

        for dep in res {
            let _ = dep?;
        }
        Ok(())
    }

    fn force_run_cmd(
        &self,
        cmd: &Command,
    ) -> Result<BTreeSet<PathBuf>, RunError> {
        let mut ps = std::process::Command::new(&cmd.cmd);
        ps.args(cmd.args.iter()).envs(cmd.envs.iter());
        if let Some(current_dir) = cmd.current_dir.as_ref() {
            ps.current_dir(current_dir);
        }
        let mut tracer = Ptracer::new();
        let mut dependencies = BTreeSet::new();
        debug!("Running {cmd:#?}");
        let child = tracer.spawn(ps).map_err(RunError::Spawn)?;
        let child_exe = match syscalls::get_exe(child.id()) {
            Ok(exe) => exe,
            Err(SyscallHandleError::ReadLink { path, source }) => {
                return Err(RunError::ReadLink { path, source });
            }
            _ => unreachable!("Unhandled get_exe error"),
        };
        trace!("Command executed {child_exe:?}");
        dependencies.insert(child_exe);
        let mut exit_status = 0;
        while let Some(mut child) = tracer.wait().map_err(RunError::Wait)? {
            // TODO: only consider one of pre- and post-execution stops
            match syscalls::handle_syscall(&mut child) {
                Ok(Some(AddDependencyPair(path0, path1))) => {
                    dependencies.insert(path0);
                    dependencies.insert(path1);
                }
                Ok(Some(AddDependency(path))) => {
                    dependencies.insert(path);
                }
                Ok(Some(SetExitStatus(status))) => exit_status = status,
                Ok(None) => {}
                Err(e) => warn!("{:?}", anyhow::anyhow!(e)),
            }
            tracer
                .restart(child, Restart::Syscall)
                .map_err(RunError::Restart)?;
        }
        if let Ok(status) = NonZeroI32::try_from(exit_status) {
            return Err(RunError::Exit(status));
        }

        Ok(dependencies)
    }

    fn is_up_to_date(&self, task: &Task) -> bool {
        // TODO: account for env
        let Some(dependencies) = self.cache.get(task) else {
            debug!("Dependencies of {} are unknown", task.name);
            return false;
        };
        // TODO: parallelize
        for (file, mod_time) in &dependencies.0 {
            let new_mod_time = file.metadata().and_then(|m| m.modified()).ok();
            if &new_mod_time != mod_time {
                debug!(
                    "{file:?} time stamp changed: {mod_time:?} -> {new_mod_time:?}"
                );
                return false;
            }
            trace!("{file:?} time stamp unchanged: {mod_time:?}");
        }
        true
    }
}

#[derive(Debug, Error)]
pub enum IOError {
    #[error("I/O error")]
    File(#[from] std::io::Error),
    #[error("Failed to persist temporary file")]
    Persist(#[from] tempfile::PersistError),
    #[error("Failed to (de)serialize runner")]
    Parse(#[from] yaml_serde::Error),
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error("Failed to spawn command")]
    Spawn(#[source] pete::Error),
    #[error("Failed to restart command after syscall")]
    Restart(#[source] pete::Error),
    #[error("Failed to wait for child")]
    Wait(#[source] pete::Error),
    #[error("Failed to read child registers")]
    Registers(#[source] pete::Error),
    #[error("Failed to handle syscall {syscall}")]
    SyscallHandle {
        syscall: String,
        source: SyscallHandleError,
    },
    #[error("Command quit with non-zero status {0}")]
    Exit(NonZeroI32),
    #[error("Failed to export cache")]
    Export(#[from] IOError),
    #[error("Failed to read symbolic link {path}")]
    ReadLink {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug, Error)]
pub enum SyscallHandleError {
    #[error("Failed to read child memory at address {addr}")]
    ReadChildMemory { addr: u64, source: pete::Error },
    #[error("Failed to read symbolic link {path}")]
    ReadLink {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deserialize,
    Serialize,
)]
pub struct Task {
    pub name: String,
    pub cmds: Vec<Command>,
}

#[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deserialize,
    Serialize,
    Builder,
)]
#[builder(derive(Clone, Debug, Into))]
pub struct Command {
    cmd: String,
    #[builder(default)]
    args: Vec<String>,
    current_dir: Option<PathBuf>,
    #[builder(default)]
    envs: BTreeMap<String, String>,
}

impl<'a> FromIterator<&'a str> for Command {
    fn from_iter<I: IntoIterator<Item = &'a str>>(iter: I) -> Self {
        let mut iter = iter.into_iter().map(ToString::to_string);
        let Some(cmd) = iter.next() else {
            return Default::default();
        };
        let args = iter.collect();
        Command {
            cmd,
            args,
            ..Default::default()
        }
    }
}

impl<'a, I> From<I> for Command
where
    I: IntoIterator<Item = &'a str>,
{
    fn from(iter: I) -> Self {
        Self::from_iter(iter)
    }
}

/// Task dependencies
///
/// Currently, this is a collection of files with their
/// modification times after the last task execution.
#[derive(
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deserialize,
    Serialize,
)]
pub struct Dependencies(pub BTreeMap<PathBuf, Option<SystemTime>>);

impl FromIterator<PathBuf> for Dependencies {
    fn from_iter<I: IntoIterator<Item = PathBuf>>(files: I) -> Self {
        // TODO: parallelize
        let files = files
            .into_iter()
            .filter_map(|p| {
                let top_dir = p.components().nth(1);
                if let Some(Component::Normal(top_dir)) = top_dir
                    && matches!(top_dir.as_bytes(), b"proc" | b"sys" | b"run")
                {
                    return None;
                }
                let mod_time = p.metadata().and_then(|m| m.modified()).ok();
                trace!("Dependency {p:?} has modification time {mod_time:?}");
                Some((p, mod_time))
            })
            .collect();
        Self(files)
    }
}
