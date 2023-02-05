extern crate openssl;

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

use clap::Parser;

use openssl::symm::{decrypt, encrypt, Cipher};

mod cli;

fn main() {
    let cli = cli::Cli::parse();
    
    let password_file = cli.password_file.unwrap_or("".to_string());
    let mut password = String::new();
    if password_file != "" {
        let mut file = File::open(password_file).expect("can't open password file");
        file.read_to_string(&mut password).expect("can't read password file");
        password = password.trim().to_string();
    } else {
        password = rpassword::prompt_password("Your password [32 characters]: ").unwrap();
    }
    if password.len() != 32 {
        println!("Password must be 32 characters long");
        std::process::exit(1);
    }

    let stdout = cli.stdout;

    let stdin = cli.stdin.unwrap_or("".to_string());

    let input_file = cli.input.unwrap_or("".to_string());

    let output_file = cli.output.unwrap_or("".to_string());
    

    if stdin != "" {
        if stdout || output_file != "" {
            if cli.encrypt == true {
                encrypt_stdin(stdin, output_file, stdout, password.as_str()).expect("can't encrypt");
            } else if cli.decrypt == true {
                decrypt_stdin(stdin, output_file, stdout, password.as_str()).expect("can't decrypt");
            } else {
                println!("Invalid mode. Must be -e or -d");
            }
        } else {
            println!("I must have either -o or --stdout");
        }
    } else if input_file != "" {
        if stdout || output_file != "" {
            if cli.encrypt == true {
                encrypt_file(input_file, output_file, password.as_str(), stdout).expect("can't encrypt");
            } else if cli.decrypt == true {
                decrypt_file(input_file, output_file, password.as_str(), stdout).expect("can't decrypt");
            } else {
                println!("Invalid mode. Must be -e or -d");
            }
        } else {
            println!("I must have -o");
        }
    } else {
        println!("I must have either -i or --stdin");
    }

        
}

fn encrypt_stdin(cleartext: String, output_file: String, stdout: bool, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read the input file
    let mut input_file = BufReader::new(std::io::stdin());
    let mut input_contents = String::new();

    if cleartext.is_empty() {
        input_file.read_to_string(&mut input_contents)?;
    } else {
        input_contents = cleartext;
    }

    // Set the password and create the cipher
    let password = password;
    let cipher = Cipher::aes_256_cbc();

    // Encrypt the input contents
    let encrypted_contents = encrypt(cipher, password.as_bytes(), None, input_contents.as_bytes())?;

    
    if output_file != "" {
        // Write the encrypted contents to the output file
        let mut output_file = BufWriter::new(File::create(output_file)?);
        output_file.write_all(&encrypted_contents)?;
    }

    if stdout {
        // String::from_utf8_lossy(&encrypted_contents.to_owned()).to_owned()
        println!("You don't want to print this.");
    }

    Ok(())
}

fn decrypt_stdin(ciphertext: String, output_file: String, stdout: bool, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read the encrypted file back in
    let mut encrypted_file = BufReader::new(std::io::stdin());
    let mut encrypted_contents = Vec::new();

    if ciphertext.is_empty() {
        encrypted_file.read_to_end(&mut encrypted_contents)?;
    } else {
        encrypted_contents = ciphertext.as_bytes().to_vec();
    }

    // Set the password and create the cipher
    let password = password;
    let cipher = Cipher::aes_256_cbc();

    // Decrypt the contents
    let decrypted_contents = decrypt(cipher, password.as_bytes(), None, &encrypted_contents)?;

    if output_file != "" {
        // Write the decrypted contents to the output file
        let mut output_file = BufWriter::new(File::create(output_file)?);
        output_file.write_all(&decrypted_contents)?;
    }

    if stdout {
        println!("{}", String::from_utf8(decrypted_contents).unwrap());
    }

    Ok(())
}

fn encrypt_file(input_file: String, output_file: String, password: &str, stdout: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Read the input file
    let mut input_file = BufReader::new(File::open(input_file)?);
    let mut input_contents = String::new();
    input_file.read_to_string(&mut input_contents)?;

    // Set the password and create the cipher
    let password = password;
    let cipher = Cipher::aes_256_cbc();

    // Encrypt the input contents
    let encrypted_contents = encrypt(cipher, password.as_bytes(), None, input_contents.as_bytes())?;

    if output_file != "" {
        // Write the encrypted contents to the output file
        let mut output_file = BufWriter::new(File::create(output_file)?);
        output_file.write_all(&encrypted_contents)?;
    }
    
    if stdout {
        // String::from_utf8_lossy(&encrypted_contents.to_owned()).to_owned()
        println!("You don't want to print this.");
    }

    Ok(())
}

fn decrypt_file(input_file: String, output_file: String, password: &str, stdout: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Read the encrypted file back in
    let mut encrypted_file = BufReader::new(File::open(input_file)?);
    let mut encrypted_contents = Vec::new();
    encrypted_file.read_to_end(&mut encrypted_contents)?;

    // Set the password and create the cipher
    let password = password;
    let cipher = Cipher::aes_256_cbc();

    // Decrypt the contents
    let decrypted_contents = decrypt(cipher, password.as_bytes(), None, &encrypted_contents)?;

    if output_file != "" {
        // Write the decrypted contents to the output file
        let mut output_file = BufWriter::new(File::create(output_file)?);
        output_file.write_all(&decrypted_contents)?;
    }

    if stdout {
        println!("{}", String::from_utf8(decrypted_contents).unwrap());
    }

    Ok(())

}
