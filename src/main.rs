use std::process;
use tcp_rust::TcpSocket;
fn main() {
    if let Err(e) = TcpSocket::run() {
        eprintln!("{}", e);
        process::exit(1);
    }
}
