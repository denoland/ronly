use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod sandbox;
mod shims;

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Auto,
    Rootless,
    Privileged,
}

pub struct Args {
    pub command: Vec<String>,
    pub tmpfs_size: String,
    pub extra_shims: Vec<PathBuf>,
    pub no_shims: bool,
    pub no_network: bool,
    pub writable: Vec<PathBuf>,
    pub mode: Mode,
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
const HELP: &str = include_str!("../README");

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        command: vec![],
        tmpfs_size: "64M".into(),
        extra_shims: vec![],
        no_shims: false,
        no_network: false,
        writable: vec![],
        mode: Mode::Auto,
    };

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next().unwrap() {
        match arg {
            Long("help") => {
                print!("{HELP}");
                std::process::exit(0);
            }
            Long("version") => {
                println!("ronly {VERSION}");
                std::process::exit(0);
            }
            Long("tmpfs-size") => {
                args.tmpfs_size = parser.value().unwrap().into_string().unwrap();
            }
            Long("extra-shims") => {
                args.extra_shims
                    .push(parser.value().unwrap().into_string().unwrap().into());
            }
            Long("no-shims") => {
                args.no_shims = true;
            }
            Long("no-network") => {
                args.no_network = true;
            }
            Long("rootless") => {
                args.mode = Mode::Rootless;
            }
            Long("privileged") => {
                args.mode = Mode::Privileged;
            }
            Long("writable") => {
                args.writable
                    .push(parser.value().unwrap().into_string().unwrap().into());
            }
            Value(val) => {
                args.command.push(val.into_string().unwrap());
            }
            _ => {
                eprintln!("unknown argument, try --help");
                std::process::exit(1);
            }
        }
    }
    args
}

fn main() -> crate::Result<()> {
    if let Some(code) = shims::maybe_run_as_shim() {
        std::process::exit(code);
    }
    let args = parse_args();
    sandbox::run(args)
}
