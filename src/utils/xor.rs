/* To refactor:
- lib.rs instead of multiple files inside utils
- individual public functions for each exercise
- tests for all functions
- use clap or another args crate;
- match on value of flag to call library (e.g. "cargo run --excercise=1.5")
    which directs to secondary entrypoint, which will ask for user input
*/

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
    pub fn single_byte(plaintext: Vec<u8>, key: u8) -> Vec<u8> {
        // XOR key with each byte of plaintext string to encode/decode
        plaintext.iter().map(|byte| byte ^ key).collect::<Vec<u8>>()
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

    pub fn find_xor_char(encrypted: &[u8]) -> (f32, u8, Vec<u8>) {
        // Iterate through possible keys (i.e. all ASCII chars)
        // Update key with highest English score, return key and decrypted String
        let mut hi_score = (0.0, 0x00, Vec::new());
        for c in 0..255_u8 {
            let decrypted = single_byte(encrypted.to_owned(), c);
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
            let result = find_xor_char(line.as_bytes());
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
    pub fn repeat_key(plaintext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        plaintext
            .iter()
            .enumerate()
            .map(|(idx, byte)| {
                let key_idx = idx % key.len();
                byte ^ key[key_idx]
            })
            .collect::<Vec<u8>>()
    }

    // Set 1 exercise 6 -- breaking repeating key XOR
    const KEYSIZE_RANGE: Range<usize> = 2..41;

    pub fn ham_dist(str1: Vec<u8>, str2: Vec<u8>) -> u32 {
        // Compares Hamming distance between two strings:
        // XORs each byte, adding up total number of resulting 1 bits,
        // which indicate a bitwise difference
        str1.iter()
            .zip(str2)
            .fold(0, |acc, (byte1, byte2)| acc + (byte1 ^ byte2).count_ones())
    }

    pub fn calc_keysize(enc_text: Vec<u8>) -> Vec<(f32, usize)> {
        // Iterates through range of possible keysizes (2..41), breaks encrypted text into keysize-sized blocks
        // Finds edit distance between consecutive pairs of blocks, averages edit distances for given keysize
        // Returns lowest scored normalized score
        let mut scores: Vec<(f32, usize)> = Vec::new();
        for keysize in KEYSIZE_RANGE {
            let mut keysize_scores = 0.0;
            let blocks: Vec<Vec<u8>> = enc_text
                .chunks(keysize)
                .map(|chunk| chunk.to_owned())
                .collect();
            for windows in blocks.windows(2) {
                let ham_dist = ham_dist(windows[0].clone(), windows[1].clone());
                keysize_scores += ham_dist as f32;
            }
            let avg_score = keysize_scores / (blocks.len() as f32 / 2.0);
            let norm_score = avg_score / keysize as f32;
            scores.push((norm_score as f32, keysize));
        }
        scores.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        scores.into_iter().take(1).collect::<Vec<(f32, usize)>>()
    }

    pub fn block_ciphertext(ciphertext: &[u8], keysize: usize) -> Vec<Vec<u8>> {
        // Breaks the ciphertext into blocks of keysize length
        ciphertext
            .chunks(keysize)
            .map(|block| block.to_owned())
            .collect()
    }

    pub fn transpose_blocks(in_blocks: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        // Transposes the blocks: make a block that is the first byte of every block,
        // and a block that is the second byte of every block, and so on.
        let block_size = in_blocks[0].len();
        let mut out_blocks: Vec<Vec<u8>> = vec![Vec::new(); block_size];
        // let flat_blocks = in_blocks.into_iter().flatten().collect::<Vec<_>>();
        for (idx, byte) in in_blocks.into_iter().flatten().enumerate() {
            let block_idx = idx % block_size; // which index inside block
            out_blocks[block_idx].push(byte);
        }
        out_blocks
    }

    pub fn repeating_xor_key(blocks: Vec<Vec<u8>>, keysize: usize) -> Vec<u8> {
        // For each block, the single-byte XOR key that produces the best looking histogram is
        // the repeating-key XOR key byte for that block. Returns combined key bytes.
        let mut key: Vec<u8> = Vec::new();
        for block in blocks.iter().take(keysize) {
            let scored_key = find_xor_char(block);
            key.push(scored_key.1);
        }
        key
    }

    pub fn brute_force_repeating_xor(ciphertext: Vec<u8>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let keysizes = calc_keysize(ciphertext.clone());
        let mut solutions = Vec::new();
        for keysize in keysizes {
            let blocks = block_ciphertext(&ciphertext.clone(), keysize.1);
            let transposed_blocks = transpose_blocks(blocks.clone());
            let key_try = repeating_xor_key(transposed_blocks.clone(), keysize.1);
            let decrypted = repeat_key(ciphertext.clone(), key_try.clone());
            solutions.push((key_try.clone(), decrypted.clone()));
        }
        solutions
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::utils::xor::xor::{self, calc_keysize, repeat_key, score_english, transpose_blocks};

    use super::xor::{block_ciphertext, brute_force_repeating_xor, repeating_xor_key};

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
        let plaintext = "Hello";
        let key = 's' as u8;
        let solution = ";\x16\x1f\x1f\x1c".to_string();
        let xored = xor::single_byte(plaintext.as_bytes().to_owned(), key);

        assert_eq!(solution, String::from_utf8(xored).unwrap());
    }

    #[test]
    fn hamming_dist() {
        let str1 = "this is a test".as_bytes().to_owned();
        let str2 = "wokka wokka!!!".as_bytes().to_owned();
        assert_eq!(37, xor::ham_dist(str1, str2));
    }

    fn calc_keysize_ice() {
        let input = hex::decode(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        )
        .unwrap();
        let keysize_scores = calc_keysize(input);
        println!("{:?}", keysize_scores);
        let (_, keysizes): (Vec<f32>, Vec<usize>) = keysize_scores.iter().cloned().unzip();
        assert_eq!(3, keysizes[0]);
    }

    #[test]
    fn test_block_transpose() {
        let in_blocks = vec![vec![1 as u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let out_blocks = transpose_blocks(in_blocks);
        let solution = vec![vec![1, 4, 7], vec![2, 5, 8], vec![3, 6, 9]];
        assert_eq!(solution, out_blocks);
    }

    fn test_break_repeating_xor() {
        let mut ciphertext = fs::read_to_string("./data/6.txt").expect("Unable to read file.");
        ciphertext.retain(|c| !c.is_whitespace());
        let ciphertext = base64::decode(ciphertext).unwrap();
        let solutions = brute_force_repeating_xor(ciphertext);
    }
}
