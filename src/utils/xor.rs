pub mod xor {
    use std::collections::HashMap;

    // Set 1 exercise 2
    pub fn fixed(plaintext: String, key: String) -> String {
        // Iterate through bytes of plaintext, XOR each byte with corresponding byte of equal-length key string
        let plaintext = hex::decode(plaintext).unwrap();
        let key = hex::decode(key).unwrap();
        let mut output: Vec<u8> = Vec::new();
        for (idx, byte) in plaintext.iter().enumerate() {
            output.push(byte ^ key[idx]);
        }
        String::from_utf8(output).unwrap()
    }

    // Set 1 exercise 3
    pub fn single_byte(plaintext: &String, key: char) -> Vec<u8> {
        // XOR key with each byte of plaintext string to encode/decode
        let plaintext = hex::decode(plaintext).unwrap();
        let key = key as u8;
        let mut output: Vec<u8> = Vec::new();
        plaintext.iter().for_each(|byte| {
            output.push(byte ^ key);
        });
        output
    }

    pub fn score_english(decoded_text: &[u8]) -> f32 {
        // Return score of given byte array, i.e. proximity to English using letter frequency (ETAOIN SHRDLU + SPC)
        let char_frequencies: HashMap<char, f32> = [
            ('a', 8.0),
            ('d', 4.0),
            ('e', 12.0),
            ('h', 6.0),
            ('i', 6.0),
            ('l', 4.0),
            ('n', 6.0),
            ('o', 7.0),
            ('r', 6.0),
            ('s', 6.0),
            ('t', 9.0),
            ('u', 3.0),
            (' ', 20.0),
        ]
        .iter()
        .cloned()
        .collect();

        let scores = decoded_text
            .iter()
            .filter_map(|&c| char_frequencies.get(&(c as char)))
            .sum::<f32>();

        (scores * decoded_text.len() as f32) / 100.0
    }

    pub fn find_xor_char(encrypted: String) -> (u8, String) {
        // Iterate through possible keys (i.e. all ASCII chars)
        // Update key with highest English score, return key and decrypted String
        let mut hi_score = (0.0, 0x00, String::new());
        for c in 0..255 as u8 {
            let decrypted = single_byte(&encrypted, c as char);
            let score = score_english(&decrypted);
            if score > hi_score.0 {
                hi_score = (score, c, String::from_utf8(decrypted).unwrap());
            }
        }
        (hi_score.1, hi_score.2)
    }

    // Set 1 exercise 4
    pub fn detect_single_byte_file(path: String) {
        // Read file, return line that has been encrypted by single-character XOR
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::xor::xor;

    #[test]
    fn xor_str() {
        let plaintext = "1c0111001f010100061a024b53535009181c".to_string();
        let key = "686974207468652062756c6c277320657965".to_string();
        let solution = "746865206b696420646f6e277420706c6179".to_string();
        let xored = xor::fixed(plaintext, key);
        assert_eq!(solution, hex::encode(xored));
    }

    #[test]
    fn xor_single_byte() {
        let plaintext = hex::encode("Hello");
        let key = 's';
        let solution = ";\x16\x1f\x1f\x1c".to_string();
        let xored = xor::single_byte(&plaintext, key);

        assert_eq!(solution, String::from_utf8(xored).unwrap());
    }
}
