pub mod xor {
    use std::{collections::HashMap, fs, ops::Range};

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

    pub fn find_xor_char(encrypted: String) -> (f32, u8, Vec<u8>) {
        // Iterate through possible keys (i.e. all ASCII chars)
        // Update key with highest English score, return key and decrypted String
        let mut hi_score = (0.0, 0x00, Vec::new());
        for c in 0..255 as u8 {
            let decrypted = single_byte(&encrypted, c as char);
            let score = score_english(&decrypted);
            if score > hi_score.0 {
                hi_score = (score, c, decrypted);
            }
        }
        (hi_score.0, hi_score.1, hi_score.2)
    }

    // Set 1 exercise 4
    pub fn detect_single_byte_file(path: &str) -> (usize, (f32, u8, Vec<u8>)) {
        // Read file, return line that has been encrypted by single-character XOR
        let source = fs::read_to_string(path).expect("Unable to read file.");
        // Ugly tuple: (score, XOR byte, decrypted string)
        let mut hi_score = (0.0, 0x00, Vec::new());
        let mut line_num = 0;
        for (idx, line) in source.lines().enumerate() {
            let result = find_xor_char(line.to_string());
            if result.0 > hi_score.0 {
                hi_score = result;
                line_num = idx + 1;
            }
        }
        // Ugly double tuples to pass some data around
        (line_num, hi_score)
    }

    // Set 1 exercise 5
    // Repeating-key XOR: XOR multi-byte key with plaintext, first byte of key to first byte of text, second to second, etc., wrapping around
    pub fn repeat_key(plaintext: &str, key: &str) -> Vec<u8> {
        let key = key.bytes().collect::<Vec<u8>>();
        plaintext
            .bytes()
            .enumerate()
            .map(|(idx, byte)| {
                let key_idx = idx % key.len();
                byte ^ key[key_idx]
            })
            .collect::<Vec<u8>>()
    }

    // Set 1 exercise 6 -- breaking repeating key XOR
    pub fn ham_dist(str1: &[u8], str2: &[u8]) -> u32 {
        // Compares Hamming distance between two strings:
        // XORs each byte, adding up total number of resulting 1 bits,
        // which indicate a bitwise difference
        str1.iter()
            .zip(str2)
            .fold(0, |acc, (byte1, byte2)| acc + (byte1 ^ byte2).count_ones())
    }

    // For each KEYSIZE, take the first KEYSIZE worth of bytes,
    // and the second KEYSIZE worth of bytes, and find the edit distance between them.
    // Normalize this result by dividing by KEYSIZE.
    // The KEYSIZE with the smallest normalized edit distance is probably the key.
    // You could proceed perhaps with the smallest 2-3 KEYSIZE values.
    // Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    const KEYSIZE_RANGE: Range<usize> = (2..40);
    pub fn calc_keysize(enc_text: &[u8]) -> Vec<(u32, usize)> {
        let mut lo_score = (u32::MAX, 0);
        let mut scores: Vec<(u32, usize)> = Vec::new();
        for keysize in KEYSIZE_RANGE {
            let mut blocks = enc_text.chunks(keysize).take(2);
            let norm_ham_dist =
                ham_dist(blocks.next().unwrap(), blocks.next().unwrap()) / keysize as u32;
            scores.push((norm_ham_dist, keysize));
        }
        scores.sort_by(|a, b| b.0.cmp(&a.0));
        scores.into_iter().take(3).collect::<Vec<(u32, usize)>>()
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::xor::xor::{self, calc_keysize};

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

    #[test]
    fn hamming_dist() {
        let str1 = "this is a test".as_bytes();
        let str2 = "wokka wokka!!!".as_bytes();
        assert_eq!(37, xor::ham_dist(str1, str2));
    }

    #[test]
    fn calc_keysize_ice() {
        let input = hex::decode(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        )
        .unwrap();
        let keysize_scores = calc_keysize(&input);
        println!("{:?}", keysize_scores);
    }
}
