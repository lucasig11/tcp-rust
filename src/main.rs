use std::{
    io::{self, Read},
    thread,
};

use tcp_rust::Interface;

fn main() -> io::Result<()> {
    eprintln!("\u{001b}c");
    let port = std::env::args()
        .collect::<Vec<String>>()
        .get(1)
        .or(Some(&String::from("9000")))
        .unwrap()
        .parse::<u16>()
        .unwrap();

    let mut interface = Interface::new()?;

    let mut listener = interface.bind(port)?;

    while let Ok(mut stream) = listener.accept() {
        thread::spawn(move || loop {
            let mut buf = [0; 512];
            let n = stream.read(&mut buf[..]).unwrap();

            if let std::cmp::Ordering::Equal = n.cmp(&0) {
                eprintln!("\x1b[1;32m[INFO]\x1b[;m Buffer is empty. No data left to read.");
                break;
            }

            eprintln!(
                "\x1b[1;33m[READ]\x1b[;m {} bytes | UTF-8: {:?} | Raw: {:?}",
                n,
                std::str::from_utf8(&buf[..n]).unwrap(),
                &buf[..n],
            );
        });
    }

    Ok(())
}
