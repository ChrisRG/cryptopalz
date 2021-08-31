mod utils;

use utils::{conversion::base64, xor::xor};

fn main() {
    // let input = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    // let encoded = base64::encode_from_hex(input);
    // println!("{}", encoded);
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string();
    let mut hi_score = 0.0;
    for c in 0..255 as u8 {
        let decrypted = xor::single_byte(input.clone(), c as char);
        let score = xor::score_english(decrypted.clone());
        if score > hi_score {
            hi_score = score;
            println!(
                "[{} - {:x}] {} - {}",
                c,
                c,
                String::from_utf8(decrypted).unwrap(),
                hi_score
            );
        }
    }
}
