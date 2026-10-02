mod reference_impl;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mf = BufReader::new(File::open(&args[1]).unwrap());
    let mut bf = File::open(&args[2]).unwrap();
    for (idx, line) in mf.lines().enumerate() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split_whitespace().collect();
        let (mode, len, keyh, ctxh, outlen, off) = (f[0], f[1].parse::<usize>().unwrap(), f[2], f[3], f[4].parse::<usize>().unwrap(), f[5].parse::<u64>().unwrap());
        let mut data = vec![0u8; len];
        bf.seek(SeekFrom::Start(off)).unwrap();
        bf.read_exact(&mut data).unwrap();
        let mut h = match mode {
            "hash" => reference_impl::Hasher::new(),
            "keyed" => { let k: [u8; 32] = unhex(keyh).try_into().unwrap(); reference_impl::Hasher::new_keyed(&k) }
            _ => reference_impl::Hasher::new_derive_key(std::str::from_utf8(&unhex(ctxh)).unwrap()),
        };
        h.update(&data);
        let mut out = vec![0u8; outlen];
        h.finalize(&mut out);
        let hex: String = out.iter().map(|b| format!("{:02x}", b)).collect();
        println!("{} {}", idx, hex);
    }
}
