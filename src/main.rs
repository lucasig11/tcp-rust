use std::error::Error;

const IPV4_PROTO_NO: u16 = 0x0800;

fn main() -> Result<(), Box<dyn Error>> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        if proto != IPV4_PROTO_NO {
            continue;
        }
        eprintln!(
            "read {} bytes: (flags: {} proto: {:x?}) {:x?}",
            nbytes,
            flags,
            proto,
            &buf[4..nbytes]
        );
    }
    // Ok(())
}
