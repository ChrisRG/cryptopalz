/* To refactor:
- lib.rs instead of multiple files inside utils
- individual public functions for each exercise
- tests for all functions
- use clap or another args crate;
- match on value of flag to call library (e.g. "cargo run --excercise=1.5")
    which directs to secondary entrypoint, which will ask for user input
*/

use std::{collections::HashMap, fs};

pub fn xor_fixed_len(plaintext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    // Iterate through bytes of plaintext and key of equal length, XOR them together
    let mut output: Vec<u8> = Vec::new();
    for (plain_byte, key_byte) in plaintext.iter().zip(key.iter()) {
        output.push(plain_byte ^ key_byte);
    }
    output
}

pub fn xor_single_byte(plaintext: Vec<u8>, key: u8) -> Vec<u8> {
    // XOR single-byte key with each byte of plaintext
    plaintext.iter().map(|byte| byte ^ key).collect::<Vec<u8>>()
}

pub fn score_english(decoded_text: &[u8]) -> f32 {
    // Return score of given byte array in terms of proximity to English
    // using letter frequency (ETAOIN SHRDLU + SPC)
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

    (scores / decoded_text.len() as f32) * 100.0
}

pub fn find_xor_char(encrypted: &[u8]) -> (f32, u8, Vec<u8>) {
    // Iterate through possible single-byte keys (all ASCII chars)
    // Update key with highest English score, return key and decrypted String
    let mut hi_score = (0.0, 0x00, Vec::new());
    for c in 0..255_u8 {
        let decrypted = xor_single_byte(encrypted.to_owned(), c);
        let score = score_english(&decrypted);
        if score > hi_score.0 {
            hi_score = (score, c, decrypted);
        }
    }
    (hi_score.0, hi_score.1, hi_score.2)
}

pub fn read_file_to_lines(path: &str) -> Vec<String> {
    let source = fs::read_to_string(path).expect("Unable to read file.");
    source
        .lines()
        .map(|line| line.to_owned())
        .collect::<Vec<String>>()
}

pub fn detect_encrypted_line(source: Vec<String>) -> (usize, (f32, u8, Vec<u8>)) {
    // Read through lines, return one line that has been encrypted with single-character XOR
    // Ugly tuple: (score, XOR byte, decrypted string)
    let mut hi_score = (0.0, 0x00, Vec::new());
    let mut line_num = 0;
    for (idx, line) in source.iter().enumerate() {
        let result = find_xor_char(line.as_bytes());
        if result.0 > hi_score.0 {
            hi_score = result;
            line_num = idx + 1;
        }
    }
    // Ugly double tuples to pass some data around
    (line_num, hi_score)
}

pub fn xor_repeat_key(plaintext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    // Apply multi-byte key to plaintext: XOR first byte of key to first byte of text
    // ... n-th byte of key to n-th of text, then wrap around
    plaintext
        .iter()
        .enumerate()
        .map(|(idx, byte)| {
            // Use key length as a modulo operator to find correct character to XOR
            let key_idx = idx % key.len();
            byte ^ key[key_idx]
        })
        .collect::<Vec<u8>>()
}

fn hamming_distance(str1: Vec<u8>, str2: Vec<u8>) -> u32 {
    // Compares Hamming distance between two strings:
    // XORs each byte, adding up total number of resulting 1 bits, which indicate bitwise difference
    str1.iter()
        .zip(str2)
        .fold(0, |acc, (byte1, byte2)| acc + (byte1 ^ byte2).count_ones())
}

fn block_text(text: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    // Breaks plain/encrypted text into keysize-sized blocks
    // e.g. block_text(&[1,2,3,4], 2) => [[1,2],[3,4]]
    text.chunks(keysize)
        .map(|chunk| chunk.to_owned())
        .collect::<Vec<Vec<u8>>>()
}

fn calc_keysize(enc_text: Vec<u8>) -> Vec<(f32, usize)> {
    // Iterates through range of possible keysizes (2..41), breaks encrypted text into keysize-sized blocks
    // Finds edit distance between consecutive pairs of blocks [[1,2],[3,4],[5,6]]
    // Averages edit distances for given keysize, returns lowest scored normalized score
    let mut scores: Vec<(f32, usize)> = Vec::new();
    for keysize in 2..41 {
        let mut keysize_scores = 0.0;
        let blocks = block_text(&enc_text, keysize);
        for windows in blocks.windows(2) {
            let ham_dist = hamming_distance(windows[0].clone(), windows[1].clone());
            keysize_scores += ham_dist as f32;
        }
        let avg_score = keysize_scores / blocks.len() as f32;
        let norm_score = avg_score / keysize as f32;
        scores.push((norm_score as f32, keysize));
    }
    scores.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    scores.into_iter().take(3).collect::<Vec<(f32, usize)>>()
}

fn transpose_blocks(in_blocks: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    // Transposes the blocks: make a block that is the first byte of every block,
    // and a block that is the second byte of every block, etc.
    let block_size = in_blocks[0].len();
    let mut out_blocks: Vec<Vec<u8>> = vec![Vec::new(); block_size];
    for (idx, byte) in in_blocks.into_iter().flatten().enumerate() {
        let block_idx = idx % block_size; // which index inside block
        out_blocks[block_idx].push(byte);
    }
    out_blocks
}

pub fn xor_repeating_key(blocks: Vec<Vec<u8>>, keysize: usize) -> Vec<u8> {
    // For each block, the single-byte XOR key that produces the best looking histogram is
    // the repeating-key XOR key byte for that block. Returns combined key bytes.
    let mut key: Vec<u8> = Vec::new();
    for block in blocks.iter().take(keysize) {
        let scored_key = find_xor_char(block);
        key.push(scored_key.1);
    }
    key
}

pub fn xor_brute_force_repeating_key(ciphertext: Vec<u8>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let keysizes = calc_keysize(ciphertext.clone());
    let mut solutions = Vec::new();
    for keysize in keysizes {
        let blocks = block_text(&ciphertext.clone(), keysize.1);
        let transposed_blocks = transpose_blocks(blocks.clone());
        let key_try = xor_repeating_key(transposed_blocks.clone(), keysize.1);
        let decrypted = xor_repeat_key(ciphertext.clone(), key_try.clone());
        solutions.push((key_try.clone(), decrypted.clone()));
    }
    solutions
}

#[cfg(test)]
mod tests {
    // use std::fs;

    use crate::utils::xor::{
        calc_keysize, hamming_distance, transpose_blocks, xor_brute_force_repeating_key,
        xor_fixed_len, xor_single_byte,
    };

    #[test]
    fn xor_str() {
        let plaintext_hex = "1c0111001f010100061a024b53535009181c";
        let key_hex = "686974207468652062756c6c277320657965";
        let solution_hex = "746865206b696420646f6e277420706c6179";
        let plaintext = hex::decode(plaintext_hex).unwrap();
        let key = hex::decode(key_hex).unwrap();
        let fixed_len_xor = xor_fixed_len(plaintext, key);
        assert_eq!(solution_hex, hex::encode(fixed_len_xor));
    }

    #[test]
    fn test_xor_single_byte() {
        let plaintext = "Hello";
        let key = 's' as u8;
        let solution = ";\x16\x1f\x1f\x1c".to_string();
        let xored = xor_single_byte(plaintext.as_bytes().to_owned(), key);

        assert_eq!(solution, String::from_utf8(xored).unwrap());
    }

    #[test]
    fn hamming_dist() {
        let str1 = "this is a test".as_bytes().to_owned();
        let str2 = "wokka wokka!!!".as_bytes().to_owned();
        assert_eq!(37, hamming_distance(str1, str2));
    }

    #[test]
    fn calc_keysize_ice() {
        let input = hex::decode(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        )
        .unwrap();
        let keysize_scores = calc_keysize(input);
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

    #[test]
    fn test_break_repeating_xor() {
        // let mut ciphertext = fs::read_to_string("./data/6.txt").expect("Unable to read file.");
        // ciphertext.retain(|c| !c.is_whitespace());
        // let ciphertext = base64::decode(ciphertext).unwrap();
        // let solutions = brute_force_repeating_xor(ciphertext);

        // Trying to brute force a shorter string is not very effective
        let input = hex::decode(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        )
        .unwrap();
        let solutions = xor_brute_force_repeating_key(input);
        println!("Solutions {}", solutions.len());
        for sol in solutions.into_iter() {
            println!("{}", String::from_utf8(sol.1).unwrap());
            println!("Key: {}", String::from_utf8(sol.0).unwrap());
        }
    }
}
