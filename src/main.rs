use std::{
    io::{self, Read},
    thread,
};

use tcp_rust::Interface;
fn main() -> io::Result<()> {
    let port = std::env::args()
        .collect::<Vec<String>>()
        .get(1)
        .or(Some(&String::from("9000")))
        .unwrap()
        .parse::<u16>()
        .unwrap();

    let mut interface = Interface::new()?;
    let mut listener = interface.bind(port)?;

    eprintln!("Bound listener on port {}", port);

    while let Ok(mut stream) = listener.accept() {
        eprintln!("Got connection!");
        thread::spawn(move || {
            let n = stream.read(&mut [0]).unwrap();
            eprintln!("Read {} bytes of data", n);
            assert_eq!(n, 0);
        });
    }

    Ok(())
}
