use std::{
    cmp,
    collections::{hash_map::Entry, HashMap, VecDeque},
    io::{self, Read, Write},
    net::Ipv4Addr,
    sync::{Arc, Condvar, Mutex},
    thread,
};

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

use tcp::Connection;

pub mod tcp;

const SENDQUEUE_SIZE: usize = 1024;
const TCP_PROTO_NO: u8 = 0x06;

/// Connection quad
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
struct Quad {
    /// Source IP and Port
    src: (Ipv4Addr, u16),
    /// Destination IP and Port
    dst: (Ipv4Addr, u16),
}

#[derive(Default)]
struct Handler {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    recv_var: Condvar,
}

type InterfaceHandle = Arc<Handler>;

pub struct Interface {
    /// Interface handle
    ih: Option<InterfaceHandle>,
    /// Join handle
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}

#[derive(Default)]
struct ConnectionManager {
    // TODO: terminate: bool,
    /// Connections map
    connections: HashMap<Quad, Connection>,
    /// List of pending connections to a port
    pending: HashMap<u16, VecDeque<Quad>>,
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
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
                // Try to lock the thread
                let mut cmg = ih.manager.lock().unwrap();
                // Dereference to get a mutable reference to the CM, instead of the Mutex
                let cm = &mut *cmg;

                let data = iph.slice().len() + tcph.slice().len();
                let quad = Quad {
                    src: (p_src, tcph.source_port()),
                    dst: (p_dest, tcph.destination_port()),
                };

                // Is the incoming connection known already?
                match cm.connections.entry(quad) {
                    Entry::Occupied(mut c) => {
                        let available =
                            c.get_mut()
                                .on_packet(&mut nic, iph, tcph, &buf[data..nbytes])?;

                        // TODO: compare before/after
                        drop(cmg);

                        if available.contains(tcp::Available::READ) {
                            ih.recv_var.notify_all();
                        }

                        if available.contains(tcp::Available::WRITE) {
                            // TODO: ih.send_var.notify_all();
                        }
                    }
                    Entry::Vacant(e) => {
                        // Do we have a listener for this port?
                        if let Some(pending) = cm.pending.get_mut(&tcph.destination_port()) {
                            if let Some(c) =
                                Connection::accept(&mut nic, iph, tcph, &buf[data..nbytes])?
                            {
                                e.insert(c);
                                pending.push_back(quad);
                                drop(cmg);
                                ih.pending_var.notify_all();
                                // TODO: wake up pending connection
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        // TODO: self.ih.as_mut().unwrap().lock().unwrap().terminate = true;

        drop(&self.ih.take());
        self.jh
            .take()
            .expect("Interface dropped more than once")
            .join()
            .unwrap()
            .unwrap();
    }
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;

        let ih: InterfaceHandle = Arc::default();

        let jh = {
            let ih = ih.clone();
            thread::spawn(move || packet_loop(nic, ih))
        };

        Ok(Interface {
            ih: Some(ih),
            jh: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        // Take the lock
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
                eprintln!("\x1b[1;32m[INFO]\x1b[;m Listening at port {}", port);
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Port already bound",
                ));
            }
        };
        drop(cm);
        Ok(TcpListener {
            port,
            ih: self.ih.as_mut().unwrap().clone(),
        })
    }
}

pub struct TcpListener {
    port: u16,
    ih: InterfaceHandle,
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.ih.manager.lock().unwrap();
        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("Port closed while listener still active")
                .pop_front()
            {
                return Ok(TcpStream {
                    ih: self.ih.clone(),
                    quad,
                });
            }
            cm = self.ih.pending_var.wait(cm).unwrap();
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.ih.manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("Port closed while listener still active");

        // Terminate the connections that are being dropped here
        for _quad in pending {
            // TODO: terminate cm.connections[quad]
            unimplemented!()
        }
    }
}

pub struct TcpStream {
    quad: Quad,
    ih: InterfaceHandle,
}

impl TcpStream {
    pub fn shutdown(&self, _how: std::net::Shutdown) -> io::Result<()> {
        // Sets a Fin Flag
        /*
            Terminate the connection
            println!("Sending FIN, expecting an ACK!");
            self.tcp.fin = true;
            self.write(nic, &[])?;
            self.state = State::FinWait1;
        */
        unimplemented!()
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to take the lock
        let mut cm = self.ih.manager.lock().unwrap();

        loop {
            // Lookup the connection for the TCP Stream we're trying to read from
            let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Stream was terminated unexpectedly",
                )
            })?;

            if c.is_recv_closed() && c.incoming.is_empty() {
                // No more data to read and no need to block
                // because there won't be anymore
                return Ok(0);
            }

            if !c.incoming.is_empty() {
                // Try to read as much data as we can
                let mut n_read = 0;

                // c.incoming is a VecDeque, so read from head and from tail
                let (head, tail) = c.incoming.as_slices();

                // Read from head without overflowing the buf len
                let h_read = cmp::min(buf.len(), head.len());
                buf[..h_read].copy_from_slice(&head[..h_read]);
                n_read += h_read;

                // Read from tail without overflowing the buf len
                let t_read = cmp::min(buf.len() - n_read, tail.len());
                buf[..t_read].copy_from_slice(&tail[..]);
                n_read += t_read;

                // Drop the read bytes
                drop(c.incoming.drain(..n_read));

                // Return amount of bytes read
                return Ok(n_read);
            }

            cm = self.ih.recv_var.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Try to take the lock
        let mut cm = self.ih.manager.lock().unwrap();

        // Lookup the connection for the TCP Stream we're trying to read from
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.len() >= SENDQUEUE_SIZE {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Too many bytes buffered",
            ));
        };

        let nwrite = std::cmp::min(buf.len(), SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(&buf[..nwrite]);

        // TODO: Wake up writer
        Ok(nwrite)
    }

    // Block until there are no bytes in the local buffer
    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.ih.manager.lock().unwrap();

        // Lookup the connection for the TCP Stream we're trying to read from
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.is_empty() {
            Ok(())
        } else {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Too many bytes buffered",
            ));
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut _cm = self.ih.manager.lock().unwrap();
        // TODO: send FIN cm.connections[quad]
        // Terminate the connections that are being dropped here
    }
}
