pub mod xor {

    pub fn fixed(plaintext: String, key: String) -> String {
        let plaintext = hex::decode(plaintext).unwrap();
        let key = hex::decode(key).unwrap();
        let mut output: Vec<u8> = Vec::new();
        for (idx, byte) in plaintext.iter().enumerate() {
            output.push(byte ^ key[idx]);
        }
        println!("{:?}", output);
        String::from_utf8(output).unwrap()
    }

    pub fn single_byte(enc_string: String, enc_char: char) -> String {}
}

#[cfg(test)]
mod tests {
    use crate::utils::xor::xor;

    #[test]
    fn xor_str() {
        let plaintext = "1c0111001f010100061a024b53535009181c".to_string();
        let key = "686974207468652062756c6c277320657965".to_string();

        let xored = xor::fixed(plaintext, key);

        let solution = "746865206b696420646f6e277420706c6179".to_string();
        assert_eq!(solution, hex::encode(xored));
    }
}
