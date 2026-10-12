# make-it-so

Make It So is a task runner library that only runs a task if

- it is new or has changed since the last run, e.g. because
  there are new arguments
- or any of the files the task touches has changed since the
  last run
- or the last run didn't finish successfully, meaning that a
  command returned with a non-zero exit status.

Currently, only Linux x86_64 is supported.

## How?

```rust
// Create a runner
// use `with_cache` for a persistent (on-disk) dependency cache
let mut runner = Runner::default();
let mut runner = Runner::with_cache(".dependencies.yaml".into())?;

// The "recipe", i.e. a block of commands to be run
// Use `Command` for more complicated stuff
let cmd = [["/bin/sh", "-c", "echo Hello, world!"]];

// Run the "greet everyone" task once
let run = runner.run("greet everyone", cmd)?;
assert!(run);

// Don't run it again,
// unless e.g. `/bin/sh` has changed in the mean time
let run = runner.run("greet everyone", cmd)?;
assert!(!run);

// Manually tweak dependencies
let task = Task {
    name: "greet everyone".into(),
    cmds: vec![cmd[0].into()]
};
let dependencies = runner.cache.get_mut(&task).unwrap();
dependencies.0.remove(Path::new("/etc/ld.so.cache"));
```

Enable [log::Level::Info](https://docs.rs/log/latest/log/enum.Level.html#variant.Info)
to see which tasks get run and which ones don't.
Enable [log::Level::Debug](https://docs.rs/log/latest/log/enum.Level.html#variant.Debug)
to see _why_ a task is being run and which commands are part of it.
Enable [log::Level::Trace](https://docs.rs/log/latest/log/enum.Level.html#variant.Trace)
if you like walls of text.

## Why?

I often have a long-running series of commands (up to a few
weeks of wall clock time) and don't want to start all over
again whenever something goes wrong. However, I _do_ want to
be sure that the necessary bits get updated when I tinker with
the setup.

There are quite a few existing alternatives:

- With a shell script it's hard to figure out which parts have
  to be rerun. Error handling is also a challenge.

- `make` gets very close to what I need, but you have to specify
  the task prerequisites manually. A nice feature is that `make`
  then knows in which order to run the tasks, but for me that's
  not really needed. In more complex setups like mine
  Makefiles quickly get hard to write, read, and debug.

- To my understanding, [just](https://crates.io/crates/just)
  makes no attempt to skip up-to-date tasks.

- [snakemake](https://snakemake.github.io/) and
  [doit](https://pydoit.org/index.html)
  use Python, which I don't know well and have always had a
  hard time getting to run. Otherwise similar to `make` in
  that I have to specify requirements manually and in turn get
  automatic resolution of inter-task dependencies.

## How Does it Work?

Commands are run under [ptrace](https://en.wikipedia.org/wiki/Ptrace).
Any system call that tries to access a file is intercepted and
the file is added to the set of task dependencies. After the
task finishes, we check for each of the files if it exists and
when it was last modified. The next time the task is started,
we check if anything has changed in the mean time.

## Distant (?) Future Plans

[ ] Support more architectures and operating systems.
[ ] Look into eBPF to lower overhead.
[ ] Use a DAG for inter-task dependencies.

License: GPL-3.0-or-later
