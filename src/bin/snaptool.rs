use clap::Parser;
use anyhow::Result;
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Snaptool {
    #[clap(subcommand)]
    sub: Sub,
}

#[derive(Debug, Parser)]
enum Sub {
    List {
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Snaptool::parse();
    match args.sub {
        Sub::List { path } => {
            let file = std::fs::File::open(&path)?;
            let snapshot = lilosdbg::load_snapshot(file)?;

            let mut addr_width = 8 + 2;
            for (range, info) in snapshot.ranges() {
                if *range.start() > u64::from(u32::MAX) || *range.end() > u64::from(u32::MAX) {
                    addr_width = 16 + 2;
                }
            }
            println!("{:addr_width$}     {:addr_width$}   {}",
                "START", "END", "SOURCE");
            for (range, info) in snapshot.ranges() {
                let base = range.start();
                let end = range.end();
                let name = &info.name;
                println!("{base:#0addr_width$x} ..= {end:#0addr_width$x}   {name}");
            }

        }
    }
    Ok(())
}
