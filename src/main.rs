mod utils;

use utils::conversion::base64;

fn main() {
    let input = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    let encoded = base64::from_hex(input);
    println!("{}", encoded);
}
