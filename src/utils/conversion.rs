// Set 1, exercise 1
pub mod my_base64 {
    // Built using the tutorial found here: https://dev.to/tiemen/implementing-base64-from-scratch-in-rust-kb1
    const UPPERCASEOFFSET: i8 = 65;
    const LOWERCASEOFFSET: i8 = 71;
    const DIGITOFFSET: i8 = -4;

    pub fn encode_from_hex(input: Vec<u8>) -> String {
        let byte_chunks = input
            .chunks(3)
            .map(split)
            .flat_map(encode_chunk)
            .map(|char| char.to_string());

        byte_chunks.collect::<Vec<String>>().join("")
    }

    // convert three 8-bit chunks into 6-bit chunks: 2 bits carry from one byte to the next
    pub fn split(bytes: &[u8]) -> Vec<u8> {
        // check number of bytes
        match bytes.len() {
            1 => vec![bytes[0] >> 2, (bytes[0] & 0b00000011) << 4],
            2 => vec![
                bytes[0] >> 2,
                (bytes[0] & 0b00000011) << 4 | bytes[1] >> 4,
                (bytes[1] & 0b00001111) << 2,
            ],
            3 => vec![
                bytes[0] >> 2,
                (bytes[0] & 0b00000011) << 4 | bytes[1] >> 4,
                (bytes[1] & 0b00001111) << 2 | bytes[2] >> 6,
                bytes[2] & 0b00111111,
            ],
            _ => unreachable!(),
        }
    }

    fn encode_chunk(chunks: Vec<u8>) -> Vec<char> {
        let mut char_map = vec!['='; 4];

        for idx in 0..chunks.len() {
            if let Some(b64_char) = get_char(chunks[idx]) {
                char_map[idx] = b64_char;
            }
        }
        char_map
    }

    fn get_char(input_char: u8) -> Option<char> {
        let index = input_char as i8;

        let ascii_index = match index {
            0..=25 => index + UPPERCASEOFFSET,  // A-Z
            26..=51 => index + LOWERCASEOFFSET, // a-z
            52..=61 => index + DIGITOFFSET,     // 0-9
            62 => 43,                           // +
            63 => 47,                           // /

            _ => return None,
        } as u8;

        Some(ascii_index as char)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::conversion::my_base64;

    #[test]
    fn split_hi() {
        let input = "Hi!".as_bytes(); // 01001000 01101001 00100001
        let output_split = "010010 000110 100100 100001";
        let split: Vec<String> = my_base64::split(input)
            .iter()
            .map(|byte| format!("{:06b}", byte))
            .collect();
        assert_eq!(output_split, split.join(" "));
    }

    #[test]
    fn encode_hi() {
        let input = "Hi".as_bytes().to_vec();
        let output_b64 = String::from("SGk=");

        assert_eq!(output_b64, my_base64::encode_from_hex(input));
    }

    #[test]
    fn encode_hex() {
        let input = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        let output_b64 =
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(output_b64, my_base64::encode_from_hex(input));
    }

    #[test]
    fn enc_with_crate() {
        let input = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        let enc_input = base64::encode(input);
        let output_b64 =
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(output_b64, enc_input);
    }

    #[test]
    fn dec_with_crate() {
        let input = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();
        let output_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string();
        if let Ok(dec_input) = base64::decode(input) {
            assert_eq!(output_hex, hex::encode(dec_input));
        }
    }
}
