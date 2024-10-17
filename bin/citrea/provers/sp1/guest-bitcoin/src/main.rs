#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::io;

pub fn main() {
    let data = io::read_vec();
    println!("IN GUEST RECEIVED DATA SIZE: {}", data.len());
}
