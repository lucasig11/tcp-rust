use std::process;
use tcp_rust::TCP;

fn main() {
    if let Err(e) = TCP::run() {
        eprintln!("{}", e);
        process::exit(1);
    }
}
