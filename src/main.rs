extern crate aes_gcm_siv;
use aes_gcm_siv::aead::consts::U12;

use aes_gcm_siv::aead::generic_array::GenericArray;
use clap::Parser;
use rand::Rng;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::process::exit;
mod cli;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv,
    Key, // Or `Aes128GcmSiv`
    Nonce,
};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use text_io::read;

fn decrypt(key_slice: &[u8], nonce_slice: &[u8], ciphertext: Vec<u8>) -> Option<Vec<u8>> {
    let key = Key::<Aes256GcmSiv>::from_slice(key_slice);
    let cipher = Aes256GcmSiv::new(&key);
    let nonce: &GenericArray<u8, U12> = Nonce::from_slice(nonce_slice);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
    println!("Successfuly decrypted ciphertext");
    Some(plaintext)
}

fn encrypt(plaintext: &[u8], nonce_slice: &[u8], key_slice: &[u8]) -> Vec<u8> {
    let key = Key::<Aes256GcmSiv>::from_slice(key_slice);
    let cipher = Aes256GcmSiv::new(&key);
    let nonce: &GenericArray<u8, U12> = Nonce::from_slice(nonce_slice);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
    if ciphertext.len() == 0 {
        panic!("❌ Ciphertext is empty");
    } else if ciphertext.len() > aes_gcm_siv::C_MAX.try_into().unwrap() {
        println!("❌ Ciphertext is too long");
    }
    println!("Successfuly encrypted plaintext");
    ciphertext
}

fn key_and_nonce_warning() {
    // print warning to protect key and nonce, and tell user they are
    // responsible for keeping them safe and not losing them
    // because they are not stored anywhere and not recoverable
    // also needed to decrypt the data
    println!("💥❗️  WARNING: You are responsible for keeping your 🔑 key and 🔑 nonce safe and not losing them. They are not stored anywhere and not recoverable. You will need them to decrypt your data.\nUse --save-codes to save codes to ONE file! distribute them as you wish...");
}

fn virtual_money() {
    println!("\nThank you for using nutek-cipher 🔐 - safe encryption for your daily use");
}

fn nuteksecurity_address() {
    println!("\nhttps://nuteksecurity.com");
    println!("neosb@nuteksecurity.com");
}

fn save_codes_file(password: String, nonce: String, test: bool) -> String {
    // save key and nonce to file in format
    // key=12345678123456781234567812345678
    // nonce=123456123456
    // with name  as UNIX timestamp
    let now = SystemTime::now();
    let home_dir = env::var("HOME").unwrap_or_else(|_| {
        println!("'HOME' environment variable not found.");
        String::new()
    });
    let mut codes_file = format!(
        "{}/Downloads/{}.codes",
        home_dir,
        now.duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    );
    if test {
        codes_file = format!(
            "{}.codes",
            now.duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
        );
    }
    let mut codes_file_buf = BufWriter::new(File::create(&codes_file).unwrap());
    codes_file_buf
        .write_all(
            format!(
                "key={}
nonce={}
",
                password, nonce
            )
            .as_bytes(),
        )
        .unwrap();
    println!("🔑 Written key and nonce to: {}", &codes_file);
    return codes_file;
}

fn sum_codes_to_file(sum_codes: String, test: bool) -> String {
    let mut sum_array = sum_codes.split(":").into_iter();

    let key_path = sum_array.next().unwrap().to_owned();
    let nonce_path = sum_array.next().unwrap().to_owned();

    let mut key = String::new();
    let file = File::open(key_path).expect("Failed to open key file");
    let mut reader = BufReader::new(file);
    reader.read_line(&mut key).unwrap();
    if key.starts_with("key=") {
        let shorter = key[4..].to_string();
        key = shorter;
    }

    let mut nonce = String::new();
    let file = File::open(nonce_path).expect("Failed to open nonce file");
    let mut reader = BufReader::new(file);
    reader.read_line(&mut nonce).unwrap();
    if key.starts_with("nonce=") {
        let shorter = key[6..].to_string();
        nonce = shorter;
    }

    assert_eq!(key.len(), 32, "❌ Key must be 32 characters long");
    assert_eq!(nonce.len(), 12, "❌ Nonce must be 12 characters long");
    // save key and nonce to file in format
    // key=12345678123456781234567812345678
    // nonce=123456123456
    // with name  as UNIX timestamp
    let now = SystemTime::now();
    let home_dir = env::var("HOME").unwrap_or_else(|_| {
        println!("'HOME' environment variable not found.");
        String::new()
    });
    let mut codes_file = format!(
        "{}/Downloads/{}.codes",
        home_dir,
        now.duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    );
    if test {
        codes_file = format!(
            "{}.codes",
            now.duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
        );
    }
    let mut codes_file_buf = BufWriter::new(File::create(&codes_file).unwrap());
    codes_file_buf
        .write_all(
            format!(
                "key={}
nonce={}
",
                key, nonce
            )
            .as_bytes(),
        )
        .unwrap();
    println!(
        "✅ Written new codes file from provided paths to key and nonce into {}. Exiting...",
        &codes_file
    );
    if !test {
        exit(0)
    } else {
        return codes_file;
    }
}

fn main() {
    // max 65,536 MB

    let cli = cli::Cli::parse();

    let stdin = io::stdin();
    let handle = stdin.lock();
    let lines = handle.lines();
    // unwrap lines
    let lines = lines.map(|line| line.unwrap());
    // let lines = lines.peekable()

    let mut key = String::new();
    let mut nonce = String::new();

    if let Some(sum_codes) = cli.sum_codes {
        sum_codes_to_file(sum_codes, false);
    }

    let codes_file = cli.codes_file.unwrap_or("".to_string());
    if codes_file != "" {
        let mut file = File::open(codes_file).expect("❌ can't open codes file");
        let mut codes = String::new();
        file.read_to_string(&mut codes)
            .expect("❌ can't read codes file");
        codes = codes.trim().to_string();
        let codes = codes.split("\n");
        for code in codes {
            let code_split = code.split("=");
            let code_split: Vec<&str> = code_split.collect();
            let code = code_split.get(1).unwrap_or(&"");
            let code = code.trim();
            let test = code_split.get(0).unwrap_or(&"");
            if test == &"key" {
                key = code.to_string();
            } else if test == &"nonce" {
                nonce = code.to_string();
            }
        }
    }

    if cli.display_codes {
        println!("🔑 Key: {}", key);
        println!("🔑 Nonce: {}", nonce);
        exit(0)
    }

    if cli.random_codes {
        key = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        nonce = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(12)
            .map(char::from)
            .collect();
    }

    if key != "" && nonce != "" {
        assert_eq!(key.len(), 32, "❌ Key must be 32 characters long");
        assert_eq!(nonce.len(), 12, "❌ Nonce must be 12 characters long");
    } else {
        key = rpassword::prompt_password("🔑 Your key [32 characters]: ").unwrap();
        nonce = rpassword::prompt_password("🔑 Your nonce [12 characters]: ").unwrap();
    }

    assert_eq!(key.len(), 32, "❌ Key must be 32 characters long");
    assert_eq!(nonce.len(), 12, "❌ Nonce must be 12 characters long");

    let stdout = cli.stdout;

    let input_file = cli.input_file.unwrap_or("".to_string());

    let output_file = cli.output_file.unwrap_or("".to_string());

    // if lines.peek().is_some() {
    println!("📝 Processing input from user...");
    if input_file != "" {
        println!("📝 Input file: {}", input_file);
        if stdout || output_file != "" {
            if cli.encrypt == true {
                println!("🔐 Encrypting file mode on... Proceeding...");
                encrypt_file(
                    input_file,
                    output_file,
                    &key,
                    &nonce,
                    stdout,
                    cli.save_codes,
                    false,
                )
                .expect("can't encrypt");
                // if cli.save_codes {
                //     save_codes_file(key, nonce)
                // }
                key_and_nonce_warning();
                virtual_money();
                nuteksecurity_address();
            } else if cli.decrypt == true {
                println!("🔓 Decrypting file mode on... Proceeding...");

                decrypt_file(input_file, output_file, &key, &nonce, stdout).expect("can't decrypt");

                virtual_money();
                nuteksecurity_address();
            } else {
                println!("❌ Invalid mode. Must be --encrypt or --decrypt");
            }
        } else {
            println!("❌ I must have either --output or --stdout");
        }
        exit(0);
    }
    if stdout || output_file != "" {
        if cli.encrypt == true {
            println!("🔐 Encrypting from pipe - use cat, echo, etc... [⏎ Enter] & CTRL+D (Unix) & [⏎ Enter] CTRL+Z (Windows) to continue with text you input below...");
            let mut stdin = String::new();

            for line in lines {
                if stdin != "" {
                    stdin = format!("{}\n{}", stdin, line);
                } else {
                    if line == "" {
                        println!("❌ No input");
                        exit(1);
                    }
                    stdin = format!("{}", line);
                }
            }

            // convert to UTF-8
            if stdin == "" {
                println!("❌ No input");
                let _line: String = read!("{}");
                exit(1);
            }
            if stdin.len() > aes_gcm_siv::P_MAX.try_into().unwrap() {
                println!(
                    "❌ Input is too long. Maximum is {} characters",
                    aes_gcm_siv::P_MAX
                );
                return;
            }
            println!(
                "📝 Successfully read {} characters from stdin... Continuing with encryption...",
                stdin.len()
            );

            encrypt_stdin(
                stdin,
                output_file,
                stdout,
                &key,
                &nonce,
                cli.save_codes,
                false,
            )
            .expect("can't encrypt");
            // if cli.save_codes {
            //     save_codes_file(key, nonce)
            // }
            key_and_nonce_warning();
            virtual_money();
            nuteksecurity_address();
        } else if cli.decrypt == true {
            println!("🔐 Decrypting stdin mode on... Proceeding...");
            let mut stdin = String::new();
            for line in lines {
                if stdin != "" {
                    stdin = format!("{}\n{}", stdin, line);
                } else {
                    if line == "" {
                        println!("❌ No input");
                        exit(1);
                    }
                    stdin = format!("{}", line);
                }
            }
            if stdin == "" {
                println!("❌ No input");
                exit(1);
            }
            if stdin.len() > aes_gcm_siv::C_MAX.try_into().unwrap() {
                println!(
                    "❌ Input is too long. Maximum is {} characters",
                    aes_gcm_siv::C_MAX
                );
                return;
            }
            println!(
                "📝 Successfully read {} characters from stdin... Continuing...",
                stdin.len()
            );

            decrypt_stdin(stdin, output_file, stdout, &key, &nonce).expect("can't decrypt");

            virtual_money();
            nuteksecurity_address();
        } else {
            println!("❌ Invalid mode. Must be --encrypt or --decrypt");
        }
    } else {
        println!("❌ I must have either --output-file or --stdout");
    }
    // } else {
    //     println!("❌ I must have either --input or data from pipe");
    // }
}

fn encrypt_stdin(
    cleartext: String,
    output_file: String,
    stdout: bool,
    password: &str,
    nonce: &str,
    should_save_codes: bool,
    test: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Encrypting...");
    let encrypted_content = encrypt(cleartext.as_bytes(), nonce.as_bytes(), password.as_bytes());
    println!("✅ Done!");
    if output_file != "" {
        // Write the encrypted contents to the output file
        let file = output_file.clone();
        let mut output_file_buf = BufWriter::new(File::create(output_file)?);
        output_file_buf.write_all(&encrypted_content)?;
        let nonce_file = format!("{}.nonce", file);
        let nonce_file_clone = nonce_file.clone();
        let mut nonce_file_buf = BufWriter::new(File::create(nonce_file)?);
        nonce_file_buf.write_all(nonce.as_bytes())?;
        let password_file = format!("{}.key", file);
        let password_file_clone = password_file.clone();
        let mut password_file_buf = BufWriter::new(File::create(password_file)?);
        password_file_buf.write_all(password.as_bytes())?;
        println!("Wrote encrypted content to: {}", file);
        println!("🔑 Wrote nonce to: {}", nonce_file_clone);
        println!("🔑 Wrote key to: {}", password_file_clone);
    }

    if stdout {
        let encoded = hex::encode(encrypted_content);
        println!("🔐 Ciphertext: \n{}", encoded);
        println!("🔑 Nonce: \n{}", nonce);
        println!("🔑 Key: \n{}", password);
    }

    if should_save_codes {
        let _ = save_codes_file(password.to_string(), nonce.to_string(), test);
    }

    Ok(())
}

fn decrypt_stdin(
    ciphertext: String,
    output_file: String,
    stdout: bool,
    password: &str,
    nonce: &str,
) -> Result<(), Box<std::io::Error>> {
    println!("🔓 Decrypting...");
    let decoded = hex::decode(ciphertext).unwrap();
    println!("✅ Done!");
    // Decrypt the contents
    let decrypted_contents = decrypt(password.as_bytes(), nonce.as_bytes(), decoded);

    if let Some(decrypted_contents) = decrypted_contents {
        if output_file != "" {
            // Write the decrypted contents to the output file
            let file = output_file.clone();
            let mut output_file_buf = BufWriter::new(File::create(output_file)?);
            output_file_buf.write_all(&decrypted_contents)?;
            println!("📝 Written decrypted content to {}", file);
        }

        if stdout {
            println!(
                "📝 Plaintext: \n{}",
                String::from_utf8_lossy(&decrypted_contents)
            );
        }
    } else {
        println!("❌ Decryption failed. Wrong 🔑 key, 🔑 nonce or 🥷 empty?");
        return Err::<(), Box<std::io::Error>>(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Decryption failed. Wrong key, nonce or empty?",
        )));
    }

    Ok(())
}

fn encrypt_file(
    input_file: String,
    output_file: String,
    password: &str,
    nonce: &str,
    stdout: bool,
    should_save_codes: bool,
    test: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the input file
    let mut input_file = BufReader::new(File::open(input_file)?);
    let mut input_contents = Vec::new();
    input_file.read_to_end(&mut input_contents)?;
    println!(
        "📝 Successfully read {} characters from file... Continuing...",
        input_contents.len()
    );

    // Encrypt the input contents
    println!("🔐 Encrypting...");
    let encrypted_content = encrypt(&input_contents, nonce.as_bytes(), password.as_bytes());
    println!("✅ Done!");

    // clone to check if output file is not empty string or is empty string
    let output_file_is_not_none = output_file.clone();
    let output_file_is_none = output_file.clone();

    if output_file_is_not_none != "" {
        // Write the encrypted contents to the output file
        let file = output_file.clone();
        let mut output_file_buf = BufWriter::new(File::create(output_file)?);
        output_file_buf.write_all(&encrypted_content)?;
        println!("Wrote encrypted content to: {}", file);
    }

    let encoded = hex::encode(encrypted_content);
    if stdout && encoded.len() <= 4800 {
        println!("🔐 Ciphertext: \n{}", encoded);
        println!("🔑 Nonce: \n{}", nonce);
        println!("🔑 Key: \n{}", password);
    } else if stdout && encoded.len() > 4800 && output_file_is_none == "" {
        println!("🔐 Ciphertext: \nToo long to display... {} characters; Maybe you want to write it to file? Use -o or --output", encoded.len());
        println!("🔑 Nonce: \n{}", nonce);
        println!("🔑 Key: \n{}", password);
    } else if stdout && encoded.len() > 4800 {
        println!(
            "🔐 Ciphertext: \nToo long to display... {} characters;",
            encoded.len()
        );
        println!("🔑 Nonce: \n{}", nonce);
        println!("🔑 Key: \n{}", password);
    }

    if should_save_codes {
        let _ = save_codes_file(password.to_string(), nonce.to_string(), test);
    }

    Ok(())
}

fn decrypt_file(
    input_file: String,
    output_file: String,
    password: &str,
    nonce: &str,
    stdout: bool,
) -> Result<(), Box<std::io::Error>> {
    // Read the encrypted file back in
    let mut encrypted_file = BufReader::new(File::open(input_file)?);
    let mut encrypted_contents = Vec::new();
    encrypted_file.read_to_end(&mut encrypted_contents)?;
    println!(
        "📝 Successfully read {} characters from file... Continuing...",
        encrypted_contents.len()
    );

    // Decrypt the contents
    println!("🔓 Decrypting...");
    let decrypted_content = decrypt(password.as_bytes(), nonce.as_bytes(), encrypted_contents);
    println!("✅ Done!");
    if let Some(decrypted_content) = decrypted_content {
        // clone to check if output file is not empty string or is empty string
        let output_file_is_not_none = output_file.clone();
        let output_file_is_none = output_file.clone();

        if output_file_is_not_none != "" {
            // Write the decrypted contents to the output file
            let file = output_file.clone();
            let mut output_file_buf = BufWriter::new(File::create(output_file)?);
            output_file_buf.write_all(&decrypted_content)?;
            println!("📝 Written decrypted content to {}", file);
        }

        let decrypted_content = String::from_utf8_lossy(&decrypted_content);
        if stdout && decrypted_content.len() <= 4800 {
            println!("📝 Plaintext: \n{}", decrypted_content);
        } else if stdout && decrypted_content.len() > 4800 && output_file_is_none == "" {
            println!("📝 Plaintext: \nToo long to display... {} characters; Maybe you want to write it to file? Use -o or --output", decrypted_content.len());
        } else if stdout && decrypted_content.len() > 4800 {
            println!(
                "📝 Plaintext: \nToo long to display... {} characters;",
                decrypted_content.len()
            );
        }
    } else {
        println!("❌ Decryption failed. Wrong 🔑 key, 🔑 nonce or 🥷 empty?");
        return Err::<(), Box<std::io::Error>>(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Decryption failed. Wrong key, nonce or empty?",
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_encrypt_decrypt() {
        let key = b"12345678123456781234567812345678"; // rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(32).map(char::from).collect();
        let nonce = b"123456123456"; // rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(12).map(char::from).collect();
        let plaintext = b"hello world";

        // let ciphertext = encrypt(key, nonce, plaintext);
        let ciphertext = encrypt(plaintext, nonce, key);
        let decrypted_content = decrypt(key, nonce, ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted_content[..]);
    }

    #[test]
    fn test_encrypt_stdin() {
        let cleartext = "hello world".to_string();
        let output_file = "test_output_encrypt_stdin.txt".to_string();
        let stdout = true;
        let password = "0123456789abcdef0123456789abcdef";
        let nonce = "0123456789ab";

        let output_file_clone = output_file.clone();
        let result = encrypt_stdin(
            cleartext,
            output_file_clone,
            stdout,
            password,
            nonce,
            true,
            true,
        );

        assert!(result.is_ok());

        let ciphertext = "d3de9dbdab9968e05220720f20379ae35ba6c90e3196967adb1f2d";

        // Check that the output file contains the encrypted content
        let output_file_clone = output_file.clone();
        let decrypted_content = fs::read(&output_file_clone).unwrap();
        let decrypted_content_encoded = hex::encode(decrypted_content.clone());
        assert_eq!(decrypted_content_encoded, ciphertext);

        // Clean up the test input and output files
        fs::remove_file(&output_file).unwrap();
        fs::remove_file(&format!("{}.nonce", output_file_clone)).unwrap();
        fs::remove_file(&format!("{}.key", output_file_clone)).unwrap();

        let now = SystemTime::now();
        let codes_file = fs::read_dir(".").unwrap();
        for file in codes_file {
            let file = file.unwrap();
            let file_name = file.file_name();
            let file_name = file_name.to_str().unwrap();
            if file_name.ends_with(".codes") {
                let unix_timestamp = now
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs()
                    - 30;
                // create unix timestamp from file_name without .codes extension
                let file_name_path = file_name.to_string();
                let codes_opened = fs::read_to_string(&file_name_path).unwrap();
                assert!(codes_opened.contains(password));
                assert!(codes_opened.contains(nonce));
                let file_name = file_name.replace(".codes", "");
                let file_name = file_name.parse::<u64>().unwrap();
                if file_name > unix_timestamp {
                    fs::remove_file(file_name_path).unwrap();
                } else {
                    panic!("❌ .codes file timestamp is older than 30 seconds. It should be removed after 30 seconds. Check if you have correct system")
                }
            }
        }
    }

    #[test]
    fn test_decrypt_stdin() {
        let ciphertext2 = "d3de9dbdab9968e05220720f20379ae35ba6c90e3196967adb1f2d".to_string();
        let output_file = "test_output_decrypt_stdin.txt".to_string();
        let stdout = true;
        let password = "0123456789abcdef0123456789abcdef";
        let nonce = "0123456789ab";

        let output_file_clone = output_file.clone();
        let decrypted_contents = decrypt_stdin(ciphertext2, output_file, stdout, password, nonce);

        // Check that function returned Ok
        assert!(decrypted_contents.is_ok());

        // Check that the output file was created and contains decrypted content
        let decrypted_content = fs::read(&output_file_clone).unwrap();
        assert_eq!(decrypted_content, "hello world".as_bytes());

        // Clean up the test input and output files
        fs::remove_file(&output_file_clone).unwrap();
    }

    #[test]
    fn test_encrypt_file() {
        let input_file = "test_input_encrypt_file.txt".to_string();
        let output_file = "test_output_encrypt_file.txt".to_string();
        let password = "0123456789abcdef0123456789abcdef";
        let nonce = "0123456789ab";
        let stdout = false;

        // Create a test input file
        fs::write(&input_file, "hello world").unwrap();

        // Call the encrypt_file function
        let result = encrypt_file(
            input_file.clone(),
            output_file.clone(),
            password,
            nonce,
            stdout,
            false,
            true,
        );

        // Check that the function completed successfully
        assert!(result.is_ok());

        // Check that the output file was created and contains encrypted content
        let encrypted_content = fs::read(&output_file).unwrap();
        assert!(encrypted_content.len() > 0);

        // Clean up the test input and output files
        fs::remove_file(&input_file).unwrap();
        fs::remove_file(&output_file).unwrap();
        // find file with codes, it has .codes extension
        let now = SystemTime::now();
        let codes_file = fs::read_dir(".").unwrap();
        for file in codes_file {
            let file = file.unwrap();
            let file_name = file.file_name();
            let file_name = file_name.to_str().unwrap();
            if file_name.ends_with(".codes") {
                let unix_timestamp = now
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs()
                    - 30;
                // create unix timestamp from file_name without .codes extension
                let file_name_path = file_name.to_string();
                let codes_opened = fs::read_to_string(&file_name_path).unwrap();
                let is_pass = codes_opened.contains(password);
                let is_nonce = codes_opened.contains(nonce);
                let file_name = file_name.replace(".codes", "");
                let file_name = file_name.parse::<u64>().unwrap();
                if file_name > unix_timestamp {
                    fs::remove_file(&file_name_path).unwrap();
                } else {
                    panic!("❌ .codes file timestamp is older than 30 seconds. It should be removed after 30 seconds. Check if you have correct system")
                }
                assert!(is_pass);
                assert!(is_nonce);
            }
        }
        // fs::remove_file(&format!("{}.nonce", output_file)).unwrap();
        // fs::remove_file(&format!("{}.key", output_file)).unwrap();
    }

    #[test]
    fn test_decrypt_file() {
        let input_file = "test_input_decrypt_file.txt".to_string();
        let output_file = "test_output_decrypt_file.txt".to_string();
        let password = "0123456789abcdef0123456789abcdef";
        let nonce = "0123456789ab";
        let stdout = false;

        // Create a test input file
        let encrypted_content = encrypt(
            "hello world".as_bytes(),
            nonce.as_bytes(),
            password.as_bytes(),
        );
        fs::write(&input_file, encrypted_content).unwrap();

        // Call the decrypt_file function
        let result = decrypt_file(
            input_file.clone(),
            output_file.clone(),
            password,
            nonce,
            stdout,
        );

        // Check that the function completed successfully
        assert!(result.is_ok());

        // Check that the output file was created and contains decrypted content
        let decrypted_content = fs::read(&output_file).unwrap();
        assert_eq!(decrypted_content, "hello world".as_bytes());

        // Clean up the test input and output files
        fs::remove_file(&input_file).unwrap();
        fs::remove_file(&output_file).unwrap();
    }

    #[test]
    fn sum_codes_to_file_with_test_mode_works() {
        let key_path = "key_test.txt";
        let nonce_path = "nonce_test.txt";

        // Create key and nonce files
        fs::write(key_path, "12345678123456781234567812345678").unwrap();
        fs::write(nonce_path, "123456789012").unwrap();

        sum_codes_to_file(format!("{}:{}", key_path, nonce_path), true);
        fs::remove_file(key_path).unwrap();
        fs::remove_file(nonce_path).unwrap();

        // find file with codes, it has .codes extension
        let now = SystemTime::now();
        let codes_file = fs::read_dir(".").unwrap();
        for file in codes_file {
            let file = file.unwrap();
            let file_name = file.file_name();
            let file_name = file_name.to_str().unwrap();
            if file_name.ends_with(".codes") {
                let unix_timestamp = now
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs()
                    - 30;
                // create unix timestamp from file_name without .codes extension
                let file_name_path = file_name.to_string();
                let codes_opened = fs::read_to_string(&file_name_path).unwrap();
                let is_pass = codes_opened.contains("12345678123456781234567812345678");
                let is_nonce = codes_opened.contains("123456789012");
                let file_name = file_name.replace(".codes", "");
                let file_name = file_name.parse::<u64>().unwrap();
                if file_name > unix_timestamp {
                    fs::remove_file(&file_name_path).unwrap();
                } else {
                    panic!("❌ .codes file timestamp is older than 30 seconds. It should be removed after 30 seconds. Check if you have correct system")
                }
                assert!(is_pass);
                assert!(is_nonce);
            }
        }
    }

    #[test]
    fn save_codes_to_file_with_test_mode_works() {
        let key = "12345678123456781234567812345678";
        let nonce = "123456789012";

        let saved_codes_file = save_codes_file(key.to_string(), nonce.to_string(), true);

        // find file with codes, it has .codes extension
        let now = SystemTime::now();
        let codes_file = fs::read_dir(".").unwrap();
        for file in codes_file {
            let file = file.unwrap();
            let file_name = file.file_name();
            let file_name = file_name.to_str().unwrap();
            if file_name.ends_with(".codes") {
                let unix_timestamp = now
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs()
                    - 30;
                // create unix timestamp from file_name without .codes extension
                let file_name_path = &saved_codes_file;
                let codes_opened = fs::read_to_string(&file_name_path).unwrap();
                let is_pass = codes_opened.contains("12345678123456781234567812345678");
                let is_nonce = codes_opened.contains("123456789012");
                let file_name = file_name.replace(".codes", "");
                let file_name = file_name.parse::<u64>().unwrap();
                if file_name > unix_timestamp {
                    fs::remove_file(&file_name_path).unwrap();
                } else {
                    panic!("❌ .codes file timestamp is older than 30 seconds. It should be removed after 30 seconds. Check if you have correct system")
                }
                assert!(is_pass);
                assert!(is_nonce);
            }
        }
    }
}
