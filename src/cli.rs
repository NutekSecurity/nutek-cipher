use clap::Parser;

/// Encrypt or decrypt a file or text from stdin
#[derive(Parser)]
#[command(author = "Neosb <neosb@nuteksecurity.com>", version, about = "File or text (from standard input) encryption for modern days", long_about = None)]
pub struct Cli {
    /// encrypt
    #[arg(short, long, default_value = "false")]
    pub encrypt: bool,

    /// decrypt
    #[arg(short, long, default_value = "false")]
    pub decrypt: bool,

    /// input file
    #[arg(short, long)]
    pub input_file: Option<String>,

    /// output file
    #[arg(short, long)]
    pub output_file: Option<String>,

    /// separated by colon ":"
    /// paths to key_path:nonce_path files
    /// that will be merged into codes file
    #[arg(long)]
    pub sum_codes: Option<String>,

    /// codes from one file
    /// in format:
    /// key=xxx
    /// nonce=yyy
    #[arg(long)]
    pub codes_file: Option<String>,

    /// display codes loaded from file using --codes-file flag and then exit
    #[arg(long, default_value = "false")]
    pub display_codes: bool,

    /// random key and nonce
    #[arg(short, default_value = "false")]
    pub random_codes: bool,

    /// save key and nonce to separete codes file
    #[arg(long, default_value = "false")]
    pub save_codes: bool,

    /// print result to stdout
    #[arg(long, default_value = "false")]
    pub stdout: bool,
}
