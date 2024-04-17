use clap::Parser;

/// Encrypt or decrypt a file or text from stdin
#[derive(Parser)]
#[command(author = "Szymon Błaszczyński <museyoucoulduse@gmail.com>", version, about = "Encrypt or decrypt a file or text from stdin", long_about = None)]
pub struct Cli {
    /// encrypt
    #[arg(short, long, default_value = "false")]
    pub encrypt: bool,

    /// decrypt
    #[arg(short, long, default_value = "false")]
    pub decrypt: bool,

    /// set input file
    #[arg(short, long)]
    pub input_file: Option<String>,

    /// set result file
    #[arg(short, long)]
    pub output_file: Option<String>,

    /// codes from file
    #[arg(long)]
    pub codes_file: Option<String>,

    /// display codes from file and exit
    #[arg(long, default_value = "false")]
    pub display_codes: bool,
    
    /// print result to stdout
    #[arg(long, default_value = "false")]
    pub stdout: bool,

    /// display license and exit
    #[arg(short, long)]
    pub license: bool,

}

