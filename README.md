# nutek-cipher

Encrypt and decrypt files and text.

## setup

```shell
cargo install nutek-cipher
```

or download binary for your OS type from _GitHub_ release page

[GitHub Releases Page](https://github.com/nutek-terminal/nutek-cipher/releases "Release Page")

## usage

```shell
Usage: nutek-cipher [OPTIONS]

Options:
  -e, --encrypt                    encrypt
  -d, --decrypt                    decrypt
  -i, --input-file <INPUT_FILE>    set input file
  -o, --output-file <OUTPUT_FILE>  set result file
      --codes-file <CODES_FILE>    codes from file
      --display-codes              display codes from file and exit
      --stdout                     print result to stdout
  -l, --license                    display license and exit
  -h, --help                       Print help
  -V, --version                    Print version
```

for example:

```shell
echo hahaha | nutek-cipher --stdout -e
```

## cipher in use

This program uses *AES-GCM-SIV* cipher with *32 bytes* key and *12 bytes* nonce. It's enough for home use.

## roadmap

* ✅ changed encryption method to AES-GCM-SIV from AES-CBC using
AES-256 encryption algorithm
* ✅ pipe enabled - pass data from command line and export to file,
or output as ciphertext to terminal with no unreadable characters
* ✅ write to files
* ✅ read nonce and password from stdin on runtime and from files
* ✅ write tests
* 💥 fail better
* ✅ repair file encryption/decryption

## crypto gurus

Probably my vocabulary is wrong, but I want to supply a working copy
of encryption/decryption tool;

I'm opened to pull requests correcting my mistakes, although for now
there is nothing wrong with the program itself. And after no input from
community I will assume that everything is fine.

## license

Read [LICENSE](/LICENSE) file for more information.
