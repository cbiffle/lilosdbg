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
            let file = std::fs::File::open(path)?;
            let snapshot = lilosdbg::load_snapshot(file)?;

            println!("snapshot format version: {}",
                snapshot.format_version());
            println!();

            if snapshot.has_registers() {
                println!("Register state:");
                for (r, v) in snapshot.registers() {
                    println!("    reg {r} = {v:#x}");
                }
            }

            if snapshot.has_elf_files() {
                println!("ELF files:");
                for (_, f) in snapshot.elf_files() {
                    println!("    {f}");
                }
            }

            let mut addr_width = 8 + 2;
            let mut size_width = 8;
            for (range, _info) in snapshot.ranges() {
                if *range.start() > u64::from(u32::MAX) || *range.end() > u64::from(u32::MAX) {
                    addr_width = 16 + 2;
                }
                let n = range.end() - range.start() + 1;
                // Expensive hacks are convenient on std platforms:
                let decimal = format!("{}", n);
                size_width = size_width.max(decimal.len());
            }
            println!("Segments:");
            println!("{:addr_width$}     {:addr_width$}  {:>size_width$}   SOURCE",
                "START", "END", "SIZE");
            for (range, info) in snapshot.ranges() {
                let base = range.start();
                let end = range.end();
                let size = end - base + 1;
                let name = &info.name;
                println!("{base:#0addr_width$x} ..= {end:#0addr_width$x}  {size:>size_width$}   {name}");
            }

        }
    }
    Ok(())
}
