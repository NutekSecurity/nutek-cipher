extern crate openssl;

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::env;

use openssl::symm::{decrypt, encrypt, Cipher};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        println!("Usage: filecrypt -e|-d <input_file> <output_file>");
        return;
    }

    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];

    if mode == "-e" {
        // hardcoded for testing purposes - change later and be clever e.g. load from file
        let password = "12345678123456781234567812345678";
        encrypt_file(input_file, output_file, password).expect("can't encrypt");
    } else if mode == "-d" {
        // hardcoded for testing purposes - change later and be clever e.g. load from file
        let password = "12345678123456781234567812345678";
        decrypt_file(input_file, output_file, password).expect("can't decrypt");
    } else {
        println!("Invalid mode. Must be -e or -d");
    }
}

fn encrypt_file(input_file: &String, output_file: &String, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read the input file
    let mut input_file = BufReader::new(File::open(input_file)?);
    let mut input_contents = String::new();
    input_file.read_to_string(&mut input_contents)?;

    // Set the password and create the cipher
    let password = password;
    let cipher = Cipher::aes_256_cbc();

    // Encrypt the input contents
    let encrypted_contents = encrypt(cipher, password.as_bytes(), None, input_contents.as_bytes())?;

    // Write the encrypted contents to the output file
    let mut output_file = BufWriter::new(File::create(output_file)?);
    output_file.write_all(&encrypted_contents)?;

    Ok(())
}

fn decrypt_file(input_file: &String, output_file: &String, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read the encrypted file back in
    let mut encrypted_file = BufReader::new(File::open(input_file)?);
    let mut encrypted_contents = Vec::new();
    encrypted_file.read_to_end(&mut encrypted_contents)?;

    // Set the password and create the cipher
    let password = password;
    let cipher = Cipher::aes_256_cbc();

    // Decrypt the contents
    let decrypted_contents = decrypt(cipher, password.as_bytes(), None, &encrypted_contents)?;

    // Write the decrypted contents to the output file
    let mut output_file = BufWriter::new(File::create(output_file)?);
    output_file.write_all(&decrypted_contents)?;

    Ok(())

    // // Convert the decrypted contents back to a string and print it
    // let decrypted_text = String::from_utf8(decrypted_contents)?;
    // println!("{}", decrypted_text);
}
