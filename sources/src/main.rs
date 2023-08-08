use std::env;
use std::process;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::fmt;
use std::error::Error;
use std::num::NonZeroU32;
use std::time::Instant;
//use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
//use std::thread;
use generic_array::GenericArray;
use tar::Builder;
use tar::Archive;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use flate2::Compression;
use dialoguer::Password;
use regex::Regex;
use ring::{digest, pbkdf2};
use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use aes_gcm::aead::{Aead, KeyInit};
use rand::Rng;                          // For padding
use rand::distributions::Uniform;       // For padding
use zeroize::Zeroize;

const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

#[derive(Debug)]
pub struct LowIVEntropyError;

#[derive(Debug)]
pub struct LowSaltEntropyError;

#[derive(Debug)]
pub struct KeyDerivationError;

// Define the custom EncryptionError enum
#[derive(Debug)] // Implement the Debug trait for EncryptionError
enum EncryptionError {
    RandomSaltError(Unspecified),
    RandomIvError(Unspecified),
    AesGcmError(aes_gcm::Error),
    LowIVEntropyError,
    LowSaltEntropyError,
    KeyDerivationError,
}

// Implement the fmt::Display trait for EncryptionError
impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EncryptionError::RandomSaltError(err) => write!(f, "Random salt generation error: {}", err),
            EncryptionError::RandomIvError(err) => write!(f, "Random IV generation error: {}", err),
            EncryptionError::AesGcmError(err) => write!(f, "AES-GCM error: {}", err),
            EncryptionError::LowIVEntropyError => write!(f, "Low IV entropy error"),
            EncryptionError::LowSaltEntropyError => write!(f, "Low salt entropy error"),
            EncryptionError::KeyDerivationError => write!(f, "Key derivation error"),
        }
    }
}

// Implement the Error trait for EncryptionError
impl Error for EncryptionError {}

fn shannon_entropy_bits(data: &[u8]) -> f64 {
    let mut frequencies = [0; 2];
    let total_bits = data.len() as f64 * 8.0;

    // Count the occurrences of each bit value in the data
    for &byte in data {
        for i in 0..8 {
            let bit = (byte >> i) & 1;
            frequencies[bit as usize] += 1;
        }
    }

    // Calculate the Shannon entropy
    let mut entropy = 0.0;
    for &count in &frequencies {
        if count > 0 {
            let probability = count as f64 / total_bits;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/*
fn shannon_entropy_bytes(data: &[u8]) -> f64 {
    let mut frequencies = [0; 256];
    let total_count = data.len() as f64;

    // Count the occurrences of each byte value in the data
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    // Calculate the Shannon entropy
    let mut entropy = 0.0;
    for &count in &frequencies {
        if count > 0 {
            let probability = count as f64 / total_count;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}
 */


// Function to generate a random salt
fn generate_salt(config: &Config) -> Result<[u8; CREDENTIAL_LEN], EncryptionError> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; CREDENTIAL_LEN];

    // Create random for salt
    if let Err(err) = rng.fill(&mut salt) {
        return Err(EncryptionError::RandomSaltError(err));
    }

    let entropy = shannon_entropy_bits(&salt);

    if config.debug {
        let salt_string = hex::encode(salt);
        println!("DEBUG: Key salt: {}", salt_string);
        println!("DEBUG: Salt entropy per bit: {}", entropy);
    }
    
    if entropy <= 0.9 {
        return Err(EncryptionError::LowSaltEntropyError)
    }

    Ok(salt)
}

// Function to derive the encryption key from the passphrase using PBKDF2
fn derive_key_from_passphrase(config: &Config, passphrase: &[u8], salt: [u8; CREDENTIAL_LEN]) -> Result<[u8; CREDENTIAL_LEN], EncryptionError> {
    // Generate the encryption key
    let n_iter = NonZeroU32::new(1_000_000).unwrap();
    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];
    
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        n_iter,
        &salt,
        passphrase,
        &mut pbkdf2_hash,
    );

    // In case the derive() results in [0u8; CREDENTIAL_LEN] (not doing anything at all), return err
    if pbkdf2_hash.iter().all(|&x| x == 0) {
        return Err(EncryptionError::KeyDerivationError);
    }

    if config.show_keys {
        let mut pbkdf2_string = hex::encode(pbkdf2_hash);
        println!("DEBUG: Encryption key: {}", pbkdf2_string);
        pbkdf2_string.zeroize();
    }

    Ok(pbkdf2_hash)
}

// Function to perform AES-GCM encryption using given key.
// The IV is the first 12 bytes of the ciphertext
fn encrypt(config: &Config, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let rng = SystemRandom::new();
    let mut iv: [u8; 12] = [0; 12];

    // Create IV.
    if let Err(err) = rng.fill(&mut iv) {
        return Err(EncryptionError::RandomIvError(err));
    }

    if config.debug {
        let iv_string = hex::encode(iv);
        println!("DEBUG: Encryption IV: {}", iv_string);
    }

    // Entropy police.
    let entropy = shannon_entropy_bits(&iv);
    if config.debug {
        println!("DEBUG: IV entropy per bit: {}", entropy);
    }
    if entropy <= 0.9 {
        return Err(EncryptionError::LowIVEntropyError)
    }

    let key = GenericArray::from_slice(key);
    let cipher = aes_gcm::Aes256Gcm::new(key);

    let ciphertext = match cipher.encrypt(GenericArray::from_slice(&iv), plaintext) {
        Ok(ciphertext) => ciphertext,
        Err(err) => return Err(EncryptionError::AesGcmError(err)),
    };

    // Combine IV and ciphertext, and return the result.
    let mut result = iv.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}


// Function to perform AES-GCM decryption
// The IV is first 12 bytes of ciphertext.
fn decrypt(config: &Config, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = GenericArray::from_slice(key);
    let cipher = aes_gcm::Aes256Gcm::new(key);

    let iv: [u8; 12] = ciphertext[..12].try_into().expect("Invalid IV length");

    if config.debug {
        let iv_string = hex::encode(iv);
        println!("DEBUG: IV: {}", iv_string);
    }

    let plaintext = cipher.decrypt(GenericArray::from_slice(&iv), &ciphertext[12..])?;

    Ok(plaintext)
}

// Function to add random amount of null padding to a Vec<u8>
// Padding size is u32 on bytes 0..3
fn add_padding(input: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    // Find the amount of padding needed
    let padding_range = if input.len() < 1024 {
        Uniform::new_inclusive(128, 1024)
    } else {
        let min_padding = input.len() / 20; // 5% of the size
        let max_padding = input.len() / 4; // 25% of the size
        Uniform::new_inclusive(min_padding, max_padding)
    };

    let padding_size = rng.sample(padding_range);

    // Create the padding and 32 bit length
    let padding = vec![0; padding_size];
    let padding_len = padding_size as u32;

    // Combine padding length and padding with the input data
    let mut result = padding_len.to_be_bytes().to_vec();
    result.extend_from_slice(&padding);
    result.extend_from_slice(&input);

    result
}

// Function to remove padding from a Vec<u8>
// Padding size is u32 on bytes 0..3
fn remove_padding(padded_data: Vec<u8>) -> Option<Vec<u8>> {
    if padded_data.len() < 4 {
        return None; // Not enough data for padding length
    }

    let padding_len_bytes: [u8; 4] = padded_data[..4].try_into().unwrap();
    let padding_len = u32::from_be_bytes(padding_len_bytes) as usize;

    if padded_data.len() < 4 + padding_len {
        return None; // Not enough data for padding
    }

    let unpadded_data = padded_data[4 + padding_len..].to_vec();
    Some(unpadded_data)
}

// Function to write the Vec<u8> to a file
fn write_file(filename: &str, data: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(data)?;
    Ok(())
}

// Function to read the file into a Vec<u8>
fn read_file(filename: &str) -> Result<Vec<u8>, std::io::Error> {
    // Open the file
    let mut file = match File::open(filename) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };

    // Read the file contents into a variable
    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(_) => Ok(buffer),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone)]
enum Mode {
    ListFiles,
    CreateContainer,
    ExtractFiles,
}

#[derive(Debug, Clone)] // Add Clone trait to derive.
struct Config {
    program: String,
    verbose: bool,
    debug: bool,
    show_keys: bool,
    sidechannel_protection: bool,
    help: bool,
    mode: Option<Mode>,
    container_file: Option<String>,
    source_destination: Vec<String>,
}

impl Config {
    fn new(program: &str) -> Config {
        Config {
            program: program.to_string(),
            verbose: false,
            debug: false,
            show_keys: false,
            sidechannel_protection: true,
            help: false,
            mode: None,
            container_file: None,
            source_destination: Vec::new(),
        }
    }
}

fn print_usage(config: &Config) {
    println!("Usage: {} [OPTIONS] [MODE] [CONTAINER_FILE] [FILES_OR_DIRS...]", config.program);
    println!(" ");
    println!("    Options:");
    println!("        -v             Enable verbose mode");
    println!("        -d             Enable debug mode");
    println!("        --SHOWKEYS     Show actual keys (Only used with -d)");
    println!("        -h             Show this help message");
    println!(" ");
    println!("    Mode:");
    println!("        -l             List files in the container");
    println!("        -c             Create a new container");
    println!("        -x             Extract files from the container");
    println!(" ");
    println!("    CONTAINER_FILE     Path to the container file");
    println!("    FILES_OR_DIRS      Source files, directories, or destination directory ");
    println!("                       (depending on the mode of operation)");
}

fn parse_args(args: &[String]) -> Config {
    let mut config = Config::new(&args[0]);

    let mut iter = args.iter().peekable();
    iter.next(); // Skip the first argument (the program name)

    for arg in iter {
        match arg.as_str() {
            "-v" => {
                config.verbose = true;
            }
            "-d" => {
                config.debug = true;
            }
            "-h" => {
                config.help = true;
            }
            "--SHOWKEYS" => {
                if config.debug {
                    config.show_keys = true;
                } else {
                    eprintln!("Error: --SHOWKEYS can only be used with -d");
                    process::exit(1);
                }
            }
            "-l" => {
                config.mode = Some(Mode::ListFiles);
            }
            "-c" => {
                config.mode = Some(Mode::CreateContainer);
            }
            "-x" => {
                config.mode = Some(Mode::ExtractFiles);
            }
            _ => {
                if config.mode.is_none() {
                    eprintln!("Error: Invalid option");
                    print_usage(&config);
                    process::exit(1);
                } else if config.container_file.is_none() {
                    config.container_file = Some(arg.clone());
                } else {
                    config.source_destination.push(arg.clone());
                }
            }
        }
    }

    config
}


// Function to list and extract files from a container
fn extract_files(config: &Config, passphrase: &str) {
    if config.debug {
        println!("DEBUG: List/extract files");
    }

    let ciphertext_with_salt = match read_file(config.container_file.as_ref().unwrap()) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Error reading input file: {}", err);
            std::process::exit(1); // Exit with an error code
        }
    };

    // Extract the salt and ciphertext from the input data
    let salt: [u8; 32] = match ciphertext_with_salt[..32].try_into() {
        Ok(arr) => arr,
        Err(_) => {
            eprintln!("Error reading salt");
            std::process::exit(1); // Exit with an error code
        }
    };

    if config.debug {
        let salt_string = hex::encode(salt);
        println!("DEBUG: Key salt: {}", salt_string);
    }

    let ciphertext = &ciphertext_with_salt[32..];

    let mut key = match derive_key_from_passphrase(config, passphrase.as_bytes(), salt) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Error during key derivation: {:?}", err);
            std::process::exit(1); // Exit with an error code
        }
    };

    if config.show_keys {

        let mut key_string = hex::encode(key);
        println!("DEBUG: Encryption key: {}", key_string);
        key_string.zeroize();
    }
    
    if config.sidechannel_protection {
        if config.debug {
            println!("DEBUG: Launching dummy AES threads for sidechannel protection (TODO)");
        }
    }

    let start_time = Instant::now();

    match decrypt(config, &key, ciphertext) {
        Ok(data) => {

            if config.debug {
                let elapsed_time = start_time.elapsed().as_nanos();
                println!("DEBUG: AES encryption took {} nanoseconds", elapsed_time);
            }

            key.zeroize();
            if config.debug {
                println!("DEBUG: Key zeroized");
            }

            if config.sidechannel_protection {
                if config.debug {
                    println!("DEBUG: Stopping dummy AES threads for sidechannel protection (TODO)");
                }
            }

            // Remove padding
            if let Some(plaintext) = remove_padding(data.clone()) {

                let decoder = GzDecoder::new(&plaintext[..]);
                let mut archive = Archive::new(decoder);

                // tässä kohtaa katotaan mikä se moodi on ja mitä sille oikeasti tehdään...
                match config.mode {
                    Some(Mode::ListFiles) => {
                        if config.verbose {
                            println!("Files in the container:");
                        }
            
                        // Process all files in the tar archive and list them
                        for entry in archive.entries().unwrap() {
                            let entry = entry.unwrap();
                            println!("{}", entry.path().unwrap().display());
                        }
                    }
                    Some(Mode::ExtractFiles) => {
                        if config.verbose {
                            println!("Extracting files ");
                        }

                        // Determine the target extraction directory
                        let target_directory = if let Some(dir) = config.source_destination.get(0) {
                            PathBuf::from(dir)
                        } else {
                            Path::new(".").to_path_buf() // Use the current working directory if config.source_destination is empty
                        };

                        // Process all files in the tar archive and extract them
                        for entry in archive.entries().unwrap() {
                            let mut entry = entry.unwrap();

                            // Get the path of the current entry
                            let entry_path = entry.path().unwrap();
                            let target_path = target_directory.join(entry_path);

                            if config.verbose {
                                println!("{}", target_path.display());
                            }

                            // Check if the entry is a file
                            if entry.header().entry_type().is_file() {

                                // Create the necessary directories if they don't exist
                                if let Some(parent) = target_path.parent() {
                                    match std::fs::create_dir_all(parent) {
                                        Ok(_) => {},
                                        Err(err) => {
                                            eprintln!("Error creating directory: {}", err);
                                            std::process::exit(1); // Exit with an error code
                                        }
                                    }
                                }

                                if target_path.exists() {
                                    eprintln!("File '{}' already exists. Skipping.", target_path.to_string_lossy());
                                } else {
                                    let mut contents = Vec::new();
                                    entry.read_to_end(&mut contents).unwrap();
                                    
                                    match write_file(&target_path.to_string_lossy(), &contents) {
                                        Ok(_) => {},
                                        Err(err) => {
                                            eprintln!("Error writing output file: {}", err);
                                            std::process::exit(1); // Exit with an error code
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                println!("Error: Invalid padding");
                std::process::exit(1); // Exit with an error code
            }
        }
        Err(_) => {
            key.zeroize();
            if config.debug {
                println!("DEBUG: Key zeroized");
            }            
            eprintln!("Decryption error. Either container is corrupted or passphrase is invalid.");
            std::process::exit(1); // Exit with an error code
        }
    }
}


// Function to create a container
fn create_container(config: &Config, passphrase: &str) {
    if config.debug {
        println!("DEBUG: Create container");
    }

    // Make sure the container file is writable by creating it
    if File::create(config.container_file.as_ref().unwrap()).is_err() {
        std::process::exit(1); // Exit with an error code
    }

    // Create a GzEncoder to compress the tar archive
    let encoder = GzEncoder::new(Vec::new(), Compression::default());

    // Create a tar builder writing directly to the GzEncoder
    let mut builder = Builder::new(encoder);

    // Process all source files into the tar archive
    for source_file in &config.source_destination {
        if let Ok(metadata) = fs::metadata(source_file) {
            if config.verbose {
                println!("{}", source_file);
            }
            // Add the source file to the tar archive
            if metadata.is_dir() {
                builder.append_dir_all(source_file, source_file).unwrap();
            } else {
                builder.append_path_with_name(source_file, source_file).unwrap();
            }
        } else {
            eprintln!("Error: Source file/directory '{}' not found.", source_file);
            std::process::exit(1);
        }
    }

    // Finish the tar archive and retrieve the compressed data as Vec<u8>
    let compressed_data = builder.into_inner().unwrap().finish().unwrap();

    // Add random padding
    let plaintext = add_padding(compressed_data);

    // Generate salt for key generation
    let salt = match generate_salt(config) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Error during salt derivation: {}", err);
            std::process::exit(1); // Exit with an error code
        }
    };

    let mut key = match derive_key_from_passphrase(config, passphrase.as_bytes(), salt) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Error during key derivation: {:?}", err);
            std::process::exit(1); // Exit with an error code
        }
    };

    if config.sidechannel_protection {
        if config.debug {
            println!("DEBUG: Launching dummy AES threads for sidechannel protection (TODO)");
        }
    }

    let start_time = Instant::now();

    match encrypt(config, &key, &plaintext) {
        Ok(ciphertext) => {

            if config.debug {
                let elapsed_time = start_time.elapsed().as_nanos();
                println!("DEBUG: AES encryption took {} nanoseconds", elapsed_time);
            }

            key.zeroize();
            if config.debug {
                println!("DEBUG: Key zeroized");
            }            

            if config.sidechannel_protection {
                if config.debug {
                    println!("DEBUG: Stopping dummy AES threads for sidechannel protection (TODO)");
                }
            }

            // Prepend the key generation salt to the ciphertext
            let mut output_data = salt.to_vec();
            output_data.extend_from_slice(&ciphertext);

            match write_file(config.container_file.as_ref().unwrap(), &output_data) {
                Ok(_) => {
                    if config.verbose {
                        println!("Encryption successful. Ciphertext saved to {}", config.container_file.as_ref().unwrap())
                    }
                },
                Err(err) => {
                    eprintln!("Error writing output file: {}", err);
                    std::process::exit(1); // Exit with an error code
                }
            }
        }
        Err(err) => {
            key.zeroize();
            if config.debug {
                println!("DEBUG: Key zeroized");
            }            

            eprintln!("Error during encryption: {:?}", err);
            std::process::exit(1); // Exit with an error code
        }
    }

}


// Main
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let config = parse_args(&args);

    if config.help {
        let program = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        println!("{} version: {}", program, version);
        print_usage(&config);
        return Ok(());
    }

    // Program exit if mode is not set.
    if config.mode.is_none() {
        println!("Error: Mode is not set. Use {} -h for help", config.program);
        return Ok(());
    }    

    // Check container file for ListFiles and ExtractFiles modes
    if let Some(Mode::ListFiles) | Some(Mode::ExtractFiles) = config.mode {
        if let Some(container_file) = &config.container_file {
            if container_file.is_empty() || fs::metadata(container_file).is_err() {
                eprintln!("Error: Container file not found or is unreadable or empty");
                std::process::exit(1);
            }
        } else {
            eprintln!("Error: Container file not set");
            std::process::exit(1);
        }
    }

    // Check container file for CreateContainer mode
    if let Some(Mode::CreateContainer) = config.mode {
        let mut has_error = false; // Track if any errors occur

        if let Some(container_file) = &config.container_file {
            if container_file.is_empty() {
                eprintln!("Error: Container file not set");
                has_error = true;
            } else if fs::metadata(container_file).is_ok() {
                eprintln!("Error: Container file already exists");
                has_error = true;
            }
        } else {
            eprintln!("Error: Container file not set");
            has_error = true;
        }

        // Check source files
        if config.source_destination.is_empty() {
            eprintln!("Error: Source files/directories not defined.");
            has_error = true;
        }
        for source_file in &config.source_destination {
            if fs::metadata(source_file).is_err() {
                    eprintln!("Error: Source file/directory '{}' not found.", source_file);
                has_error = true;
            }
        }
        if has_error {
            std::process::exit(1); // Exit with an error code if any errors occurred
        }    
    }

    // Prompt for passphrase
    let mut passphrase = match Password::new().with_prompt("Enter passphrase").interact() {
        Ok(pass) => pass,
        Err(_) => {
            eprintln!("Error: Unable to read passphrase.");
            std::process::exit(1);
        }
    };

    // Do we need to verify?
    if let Some(Mode::CreateContainer) = config.mode {
        let mut passphrase2 = match Password::new().with_prompt("Repeat passphrase").interact() {
            Ok(pass) => pass,
            Err(_) => {
                eprintln!("Error: Unable to read passphrase.");
                std::process::exit(1);
            }
        };
        if passphrase != passphrase2 {
            eprintln!("Error: Passphrases do not match.");
            std::process::exit(1);
        }
        passphrase2.zeroize();
    }

    if config.debug {
        println!("DEBUG: Passphrase entered: {}", passphrase);
    }

    // Check if the passphrase matches the desired pattern.
    let regex_pattern = Regex::new(r#"^[a-zA-Z0-9 !\"@#$%&/()\[\]{}=+\\?\*\-_,.]+$"#).unwrap();
    if !regex_pattern.is_match(&passphrase) {
        eprintln!("Error: Invalid passphrase. It should contain only letters (a-z/A-Z), numbers, and ordinary special characters.");
        std::process::exit(1);
    }

    // Do the thing.
    match config.mode {
        Some(Mode::ListFiles) | Some(Mode::ExtractFiles) => {
            extract_files(&config, &passphrase);
        },
        Some(Mode::CreateContainer) => {
            create_container(&config, &passphrase);
        }
        _ => (),
    }

    // Zeroize passphrase
    passphrase.zeroize();
    if config.debug {
        println!("DEBUG: Passphrase zeroized");
    }

    Ok(())
}
