use structopt::StructOpt;

mod certificate;
mod metrics;
mod opt;

use opt::Opt;

fn main() {
    let opt = Opt::from_args();

    if let Err(err) = opt.run() {
        eprintln!("{}", err);
    }
}
