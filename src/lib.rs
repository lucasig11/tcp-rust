pub mod connection;

use connection::{Connection, Quad};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::{collections::HashMap, error::Error};

// const IPV4_PROTO_NO: u16 = 0x0800;
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
            // let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
            // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
            // if eth_proto != IPV4_PROTO_NO {
            //     continue;
            // }

            // Parse IPV4 packet
            match Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
                // Filter TCP packets
                Ok(iph) if iph.protocol() == TCP_PROTO_NO => {
                    let p_src = iph.source_addr();
                    let p_dest = iph.destination_addr();

                    match TcpHeaderSlice::from_slice(&buf[iph.slice().len()..]) {
                        Ok(tcph) => {
                            // Here we know we have a TCP packet
                            // Connection quad
                            // (src_ip, src_port, dst_ip, dst_port)
                            use std::collections::hash_map::Entry;
                            let data = iph.slice().len() + tcph.slice().len();
                            match connections.entry(Quad {
                                src: (p_src, tcph.source_port()),
                                dst: (p_dest, tcph.destination_port()),
                            }) {
                                Entry::Occupied(mut c) => {
                                    c.get_mut().on_packet(
                                        &mut nic,
                                        iph,
                                        tcph,
                                        &buf[data..nbytes],
                                    )?;
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
                        Err(e) => {
                            eprintln!("Ignoring TCP packet {:?}", e);
                        }
                    }
                }
                _ => {
                    eprintln!("Ignoring IPV4 packet");
                }
            }
        }
    }
}
