use std::env::args;
use std::fs::File;
use std::io::{Read, BufReader};
use std::process::exit;

mod instruction;
use instruction::execute;

fn main() {
    let mut mem: [u8; 4096] = [0; 4096];
    let mut sp: usize = 4096;  // stack pointer (grows downward)
    let mut pc: isize  = 0;    // program counter, in *instructions*
    let mut magic = [0u8; 4];

    // 1) Open file and verify magic
    let args: Vec<String> = args().collect();
    let file = File::open(&args[1]).expect("Unable to open bytecode file");
    let mut reader = BufReader::new(file);
    reader
        .read_exact(&mut magic)
        .expect("Failed to read magic bytes");
    if magic != [0xde, 0xad, 0xbe, 0xef] {
        eprintln!("error: file did not contain magic 0xDEADBEEF");
        return;
    }

    // 2) Load the rest of the file into memory at address 0
    reader
        .read(&mut mem)
        .expect("Failed to read program into memory");

    // 3) Fetch–execute until exit or PC runs past end of RAM
    loop {
        let byte_addr = (pc * 4) as usize;
        if byte_addr + 4 > mem.len() {
            // fell off the end → normal exit code 0
            break;
        }
        if let Some(code) = execute(&mut mem, &mut sp, &mut pc) {
            exit(code);
        }
    }
}
