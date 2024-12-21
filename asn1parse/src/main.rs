use clap::Parser;
use std::io::Read;
use std::path::PathBuf;

#[derive(clap::Parser)]
struct Args {
    #[clap(long)]
    pem: bool,

    #[clap()]
    path: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut data = if let Some(path) = args.path {
        std::fs::read(path)?
    } else {
        let mut buf = vec![];
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    };

    if args.pem {
        data = pem::parse(data)?.into_contents();
    }

    let v = asn1::parse_single::<asn1parse::Value<'_>>(&data)?;
    v.render(&mut std::io::stdout().lock(), 0)?;

    Ok(())
}
