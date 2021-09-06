#![allow(dead_code)]

mod utils;

use std::fs;

use utils::xor::xor_brute_force_repeating_key;

fn main() {
    // Set 1 ex 6
    let mut ciphertext = fs::read_to_string("./data/6.txt").expect("Unable to read file.");
    ciphertext.retain(|c| !c.is_whitespace());
    let ciphertext = base64::decode(ciphertext).unwrap();
    let solutions = xor_brute_force_repeating_key(ciphertext);
    println!("{}", String::from_utf8(solutions[0].clone().1).unwrap());
    println!(
        "Key: {}",
        String::from_utf8(solutions[0].clone().0).unwrap()
    );
}

// let input = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
// let encoded = base64::encode_from_hex(input);
// println!("{}", encoded);

// Set 1 ex 3
// let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string();
// let xor_char = xor::find_xor_char(input);
// println!(
//     "[0x{} / `{}`] {}",
//     xor_char.1, xor_char.1 as char, xor_char.2
// );

// Set 1 ex 4
// Destructuring the embedded tuple
// let (line_num, result) = xor::detect_single_byte_file("./data/4.txt");
// println!(
//     "(Line {}) [0x{} / `{}`] {}",
//     line_num,
//     result.1,
//     result.1 as char,
//     String::from_utf8(result.2).unwrap()
// );

// Set 1 ex 5
// let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
// let encoded = xor::repeat_key(input.as_bytes().to_owned(), "ICE".as_bytes().to_owned());
// let hex_enc = hex::encode(encoded.iter().map(|&byte| byte as char).collect::<String>());
// println!("{}", hex_enc);
