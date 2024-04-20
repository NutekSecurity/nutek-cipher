extern crate aes_gcm_siv;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write, BufRead};
use std::process::exit;
use aes_gcm_siv::aead::consts::U12;
use aes_gcm_siv::aead::generic_array::GenericArray;
use clap::Parser;
mod cli;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce, Key  // Or `Aes128GcmSiv`
};
use rand::Rng;

use text_io::read;
use std::time::{SystemTime, UNIX_EPOCH};


fn decrypt(key_slice: &[u8], nonce_slice: &[u8], ciphertext: Vec<u8>) -> Option<Vec<u8>> {
    let key = Key::<Aes256GcmSiv>::from_slice(key_slice);
    let cipher = Aes256GcmSiv::new(&key);
    let nonce: &GenericArray<u8, U12> = Nonce::from_slice(nonce_slice);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
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
    ciphertext
}

fn key_and_nonce_warning() {
    // print warning to protect key and nonce, and tell user they are
    // responsible for keeping them safe and not losing them
    // because they are not stored anywhere and not recoverable
    // also needed to decrypt the data
    println!("💥❗️  WARNING: You are responsible for keeping your 🔑 key and 🔑 nonce safe and not losing them. They are not stored anywhere and not recoverable. You will need them to decrypt your data.");
}

fn virtual_money() {
    println!("\nFor future development and security awarness help me with Monero:");
    println!("Monero address: 87G8nLBPdwAEPycmWWAhUhZC8kUuuFgjX8zEUw1VjvNMPdkUWzxikocQyLtycwqzJfChR5bNVyXU87m5vT4Fy9gtS6Q5X8L");
    println!("or Bitcoin:");
    println!("Bitcoin address: 3AhSZUecGQDk97iCGtUtCq3kqCdndsZEF1");
}

fn nuteksecurity_address() {
    println!("\nhttps://nuteksecurity.com");
}

fn license_text() {
    // string with license text displayed as is
    let license_text = r#"LICENSE

The user is granted a non-exclusive, perpetual license to use,
and distribute the software, subject to the following terms:
The user must display the following copyright notice in all copies of the
software:

Copyright (c) 2024 Szymon Błaszczyński

The user is not permitted to sublicense the software.
The user is not permitted to sell the software.

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."#;
    println!("{}", license_text);
}

fn main() {
    // max 65,536 MB

    let cli = cli::Cli::parse();

    if cli.license {
        license_text();
        exit(0);
    }
    
    let stdin = io::stdin();
    let handle = stdin.lock();
    let lines = handle.lines();
    // unwrap lines
    let lines = lines.map(|line| line.unwrap());
    // let lines = lines.peekable()

    let mut key = String::new();
    let mut nonce = String::new();
    let codes_file = cli.codes_file.unwrap_or("".to_string());
    if codes_file != "" {
        let mut file = File::open(codes_file).expect("❌ can't open codes file");
        let mut codes = String::new();
        file.read_to_string(&mut codes).expect("❌ can't read codes file");
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
        exit(0);
    }

    if key != "" && nonce != "" {
        assert_eq!(key.len(), 32, "❌ Key must be 32 characters long");
        assert_eq!(nonce.len(), 12, "❌ Nonce must be 12 characters long");
    } else {
        key = rpassword::prompt_password("🔑 Your key [32 characters] - to skip press [Enter↩]: ").unwrap();
        let key_replay = rpassword::prompt_password("🔑 Confirm your key - to skip press [Enter↩]: ").unwrap();
        if key != key_replay {
            println!("❌ Keys don't match");
            exit(1);
        }
        nonce = rpassword::prompt_password("🔑 Your nonce [12 characters] - to skip press [Enter↩]: ").unwrap();
        let nonce_replay = rpassword::prompt_password("🔑 Confirm your nonce - to skip press [Enter↩]: ").unwrap();
        if nonce != nonce_replay {
            println!("❌ Nonces don't match");
            exit(1);
        }
    }
    if key == "" {
        key = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(32).map(char::from).collect();
    }
    assert_eq!(key.len(), 32, "❌ Key must be 32 characters long");
    
    if nonce == "" {
        nonce = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(12).map(char::from).collect();
    }
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
                        encrypt_file(input_file, output_file, &key, &nonce, stdout).expect("can't encrypt");
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
                println!("🔐 Encrypting from pipe - use cat, echo, etc... CTRL+D (Unix) & CTRL+Z (Windows) to proceed with text when no pipe is provided...");
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
                    let line: String = read!("{}");
                    exit(1);
                }
                if stdin.len() > aes_gcm_siv::P_MAX.try_into().unwrap() {
                    println!("❌ Input is too long. Maximum is {} characters", aes_gcm_siv::P_MAX);
                    return;
                }
                println!("📝 Successfully read {} characters from stdin... Continuing...", stdin.len());
                
                    encrypt_stdin(stdin, output_file, stdout, &key, &nonce).expect("can't encrypt");
                
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
                    println!("❌ Input is too long. Maximum is {} characters", aes_gcm_siv::C_MAX);
                    return;
                }
                println!("📝 Successfully read {} characters from stdin... Continuing...", stdin.len());
                
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

fn encrypt_stdin(cleartext: String, output_file: String, stdout: bool, password: &str, nonce: &str) -> Result<(), Box<dyn std::error::Error>> {
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

    Ok(())
}

fn decrypt_stdin(ciphertext: String, output_file: String, stdout: bool, password: &str, nonce: &str) -> Result<(), Box<std::io::Error>> {
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
            println!("📝 Wrote decrypted content to {}", file);
        }

        if stdout {
            println!("📝 Plaintext: \n{}", String::from_utf8_lossy(&decrypted_contents));
        }
    } else {
        println!("❌ Decryption failed. Wrong 🔑 key, 🔑 nonce or 🥷 empty?");
        return Err::<(), Box<std::io::Error>>(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Decryption failed. Wrong key, nonce or empty?")))
    }

    Ok(())
}

fn encrypt_file(input_file: String, output_file: String, password: &str, nonce: &str, stdout: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Read the input file
    let mut input_file = BufReader::new(File::open(input_file)?);
    let mut input_contents = Vec::new();
    input_file.read_to_end(&mut input_contents)?;
    println!("📝 Successfully read {} characters from file... Continuing...", input_contents.len());

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

        // save key and nonce to file in format
        // key=12345678123456781234567812345678
        // nonce=123456123456
        // with name  as UNIX timestamp 
        let now = SystemTime::now();
        let codes_file = format!("{}.codes", now.duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs());
        let codes_file_clone = codes_file.clone();
        let mut codes_file_buf = BufWriter::new(File::create(&codes_file)?);
        codes_file_buf.write_all(format
        !("
key={}
nonce={}
", password, nonce).as_bytes())?;
        println!("🔑 Wrote key and nonce to: {}", codes_file_clone);
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
    } else if stdout && encoded.len() > 4800  {
        println!("🔐 Ciphertext: \nToo long to display... {} characters;", encoded.len());
        println!("🔑 Nonce: \n{}", nonce);
        println!("🔑 Key: \n{}", password);
    }

    Ok(())
}

fn decrypt_file(input_file: String, output_file: String, password: &str, nonce: &str, stdout: bool) -> Result<(), Box<std::io::Error>> {
    // Read the encrypted file back in
    let mut encrypted_file = BufReader::new(File::open(input_file)?);
    let mut encrypted_contents = Vec::new();
    encrypted_file.read_to_end(&mut encrypted_contents)?;
    println!("📝 Successfully read {} characters from file... Continuing...", encrypted_contents.len());
    
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
            println!("📝 Wrote decrypted content to {}", file);
        }

        let decrypted_content = String::from_utf8_lossy(&decrypted_content);
        if stdout && decrypted_content.len() <= 4800 {
            println!("📝 Plaintext: \n{}", decrypted_content);
        } else if stdout && decrypted_content.len() > 4800 && output_file_is_none == "" {
            println!("📝 Plaintext: \nToo long to display... {} characters; Maybe you want to write it to file? Use -o or --output", decrypted_content.len());
        } else if stdout && decrypted_content.len() > 4800 {
            println!("📝 Plaintext: \nToo long to display... {} characters;", decrypted_content.len());
        }

    } else {
        println!("❌ Decryption failed. Wrong 🔑 key, 🔑 nonce or 🥷 empty?");
        return Err::<(), Box<std::io::Error>>(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Decryption failed. Wrong key, nonce or empty?")))
    }

    Ok(())

}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = b"12345678123456781234567812345678";// rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(32).map(char::from).collect();
        let nonce = b"123456123456";// rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(12).map(char::from).collect();
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
        let result = encrypt_stdin(cleartext, output_file_clone, stdout, password, nonce);

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
        let result = encrypt_file(input_file.clone(), output_file.clone(), password, nonce, stdout);

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
                let unix_timestamp = now.duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs() - 30;
                // create unix timestamp from file_name without .codes extension
                let file_name_path = file_name.to_string();
                let file_name = file_name.replace(".codes", "");
                let file_name = file_name.parse::<u64>().unwrap();
                if file_name > unix_timestamp {
                    fs::remove_file(file_name_path).unwrap();
                }
                else {
                    panic!("❌ .codes file timestamp is older than 30 seconds. It should be removed after 30 seconds. Check if you have correct system")
                }
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
        let encrypted_content = encrypt("hello world".as_bytes(), nonce.as_bytes(), password.as_bytes());
        fs::write(&input_file, encrypted_content).unwrap();

        // Call the decrypt_file function
        let result = decrypt_file(input_file.clone(), output_file.clone(), password, nonce, stdout);

        // Check that the function completed successfully
        assert!(result.is_ok());

        // Check that the output file was created and contains decrypted content
        let decrypted_content = fs::read(&output_file).unwrap();
        assert_eq!(decrypted_content, "hello world".as_bytes());

        // Clean up the test input and output files
        fs::remove_file(&input_file).unwrap();
        fs::remove_file(&output_file).unwrap();
    }
}