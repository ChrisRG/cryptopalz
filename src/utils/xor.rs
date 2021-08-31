pub mod xor {
    use std::collections::HashMap;

    pub fn fixed(plaintext: String, key: String) -> String {
        let plaintext = hex::decode(plaintext).unwrap();
        let key = hex::decode(key).unwrap();
        let mut output: Vec<u8> = Vec::new();
        for (idx, byte) in plaintext.iter().enumerate() {
            output.push(byte ^ key[idx]);
        }
        String::from_utf8(output).unwrap()
    }

    pub fn single_byte(plaintext: String, key: char) -> Vec<u8> {
        let plaintext = hex::decode(plaintext).unwrap();
        let key = key as u8;
        let mut output: Vec<u8> = Vec::new();
        plaintext.iter().for_each(|byte| {
            output.push(byte ^ key);
        });
        output
    }

    pub fn score_english(decoded_text: Vec<u8>) -> f32 {
        let char_frequencies: HashMap<char, f32> = [
            ('a', 0.082),
            ('b', 0.015),
            ('c', 0.028),
            ('d', 0.042),
            ('e', 0.127),
            ('f', 0.022),
            ('g', 0.020),
            ('h', 0.061),
            ('i', 0.061),
            ('j', 0.001),
            ('k', 0.008),
            ('l', 0.040),
            ('m', 0.024),
            ('n', 0.067),
            ('o', 0.075),
            ('p', 0.019),
            ('q', 0.001),
            ('r', 0.060),
            ('s', 0.063),
            ('t', 0.091),
            ('u', 0.028),
            ('v', 0.010),
            ('w', 0.024),
            ('x', 0.002),
            ('y', 0.020),
            ('z', 0.001),
            (' ', 0.130),
        ]
        .iter()
        .cloned()
        .collect();
        let mut score: f32 = 0.0;
        for c in decoded_text {
            score += match char_frequencies.get(&(c as char)) {
                Some(num) => *num,
                None => 0.0,
            };
        }
        score
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
        let xored = xor::single_byte(plaintext, key);

        assert_eq!(solution, String::from_utf8(xored).unwrap());
    }
}
