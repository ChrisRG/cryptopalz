mod utils;

use utils::{conversion::base64, xor::xor};

fn main() {
    // let input = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    // let encoded = base64::encode_from_hex(input);
    // println!("{}", encoded);
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string();
    let xor_char = xor::find_xor_char(input);
    println!(
        "[0x{} / `{}`] {}",
        xor_char.0, xor_char.0 as char, xor_char.1
    );
}
