#![warn(clippy::pedantic)]
//#![warn(clippy::unwrap_used)]
#![warn(rust_2018_idioms, unused_lifetimes, missing_debug_implementations)]
#![forbid(unsafe_code)]

use structopt::StructOpt;

mod certificate;
mod metrics;
mod opt;

use opt::Opt;

fn main() {
    let opt = Opt::from_args();

    if let Err(err) = opt.run() {
        eprintln!("{err}");
    }
}
