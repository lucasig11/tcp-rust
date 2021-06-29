pub mod connection;

use connection::{Connection, Quad};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::{
    collections::{hash_map::Entry, HashMap},
    error::Error,
};

const TCP_PROTO_NO: u8 = 0x06;
pub struct TcpSocket;

impl TcpSocket {
    pub fn run() -> Result<(), Box<dyn Error>> {
        let mut connections: HashMap<Quad, Connection> = Default::default();

        // Kernel network interface
        let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        // Ethernet packet buffer
        let mut buf = [0u8; 1504];

        loop {
            let nbytes = nic.recv(&mut buf[..])?;

            // Parse IPV4 packet
            if let Ok(iph) = Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
                // Filter non-TCP packets
                if iph.protocol() != TCP_PROTO_NO {
                    continue;
                }

                let p_src = iph.source_addr();
                let p_dest = iph.destination_addr();

                if let Ok(tcph) = TcpHeaderSlice::from_slice(&buf[iph.slice().len()..]) {
                    // Here we know we have a TCP packet
                    let data = iph.slice().len() + tcph.slice().len();
                    match connections.entry(Quad {
                        src: (p_src, tcph.source_port()),
                        dst: (p_dest, tcph.destination_port()),
                    }) {
                        Entry::Occupied(mut c) => {
                            c.get_mut()
                                .on_packet(&mut nic, iph, tcph, &buf[data..nbytes])?;
                        }
                        Entry::Vacant(e) => {
                            if let Some(c) =
                                Connection::accept(&mut nic, iph, tcph, &buf[data..nbytes])?
                            {
                                e.insert(c);
                            }
                        }
                    }
                }
            }
        }
    }
}
