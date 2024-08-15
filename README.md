# nutek-cipher

Encrypt and decrypt files and text.

## setup

```shell
cargo install nutek-cipher
```

or download binary for your OS type from _GitHub_ release page

[GitHub Releases Page](https://github.com/NutekSecurity/nutek-cipher/releases "Release Page")

## Windows !IMPORTANT!

Before downloading `nutek-cipher_null_x86_64-pc-windows-gnu.zip` file, add Downloads, or any directory where you will download this file, to exception list in Windows Defender.

1. Open `Virus & threat protection`
2. Open `Manage settings` under `Virus & threat protection settings`
3. Under `Exclusions` click `Add or remove exclusions`
4. Add the target download folder
5. Download file
6. Check SHA256 checksum for file integrity
7. Unarchive it
8. Remove exclusion for download folder
9. Run `nutek-cipher.exe` - this should trigger _Windows Defender_ again
10. Get back to `Virus & threat protection` and go to `Protection history`
11. Find `nutek-cipher` under `Threat quarantined` and __restore__ it

## SHA256

Download archive for your operating system and corresponding `*.sha256` file.

On UNIX (Linux/macOS) change directory to place where both files resides and issue this command

```sh
shs256sum -c nutek-cipher...name_of_your_file.sha256
```

On Windows

```powershell
cat  nutek-cipher_null_x86_64-pc-windows-gnu.zip.sha256
Get-FileHash nutek-cipher_null_x86_64-pc-windows-gnu.zip -Algorithm SHA256 | Format-List
```

If the archive is actually the one downloaded from here, it should pass the test. On Windows, look for if the lowercase output of first command is the same as uppercase output of second command.


## usage

```shell
File or text (from standard input) encryption for modern days

Usage: nutek-cipher [OPTIONS]

Options:
  -e, --encrypt                    encrypt
  -d, --decrypt                    decrypt
  -i, --input-file <INPUT_FILE>    input file
  -o, --output-file <OUTPUT_FILE>  output file
      --sum-codes <SUM_CODES>      separated by colon ":" paths to key_path:nonce_path files that will be merged into codes file
      --codes-file <CODES_FILE>    codes from one file in format: key=xxx nonce=yyy
      --display-codes              display codes loaded from file using --codes-file flag and then exit
  -r                               random key and nonce
      --save-codes                 save key and nonce to separete codes file
      --stdout                     print result to stdout
  -h, --help                       Print help
  -V, --version                    Print version
```

for example:

```shell
echo hahaha | nutek-cipher --stdout -e
```

## cipher in use

This program uses *AES-GCM-SIV* cipher with *32 bytes* key and *12 bytes* nonce. It's enough for home use.

## license

Apache-2.0 or MIT
