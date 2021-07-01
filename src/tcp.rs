use bitflags::bitflags;
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::{collections::VecDeque, error::Error, io, u32};

bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b000000001;
        const WRITE = 0b00000010;
    }
}

/// TCP connection states
#[derive(Clone)]
pub enum State {
    /// SYN Received
    SynRecvd,
    /// Connection established
    Estab,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
}

// TCB - transmition control block
#[derive(Clone)]
pub struct Connection {
    /// Connection's current state. See [`State`].
    state: State,
    /// Connection IP Header
    ip: etherparse::Ipv4Header,
    /// Connection TCP Header
    tcp: etherparse::TcpHeader,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
}

/// Send Sequence Space (RFC 793 S3.2 F4)
/// ```md
/// 1         2          3          4
/// ----------|----------|----------|----------
///        SND.UNA    SND.NXT    SND.UNA
///                             +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
#[derive(Clone)]
pub struct SendSequenceSpace {
    /// Send Unacknowledged
    una: u32,
    /// Send Next
    nxt: u32,
    /// Send window
    wnd: u16,
    /// Send urgent pointer
    up: bool,
    /// Segment sequence number for last window update
    wl1: u32,
    /// Segment acknowledgement numebr use for alast window update
    wl2: u32,
    /// Initial sequence number
    iss: u32,
}

/// Receive Sequence Space (RFC 793 S3.2 F5)
/// ```md
///     1          2          3
/// ----------|----------|----------
///         RCV.NXT    RCV.NXT
///                   +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
#[derive(Clone)]
pub struct ReceiveSequenceSpace {
    /// Receive Next
    nxt: u32,
    /// Receive window
    wnd: u16,
    /// Receive urgent pointer
    up: bool,
    /// Initial receive sequence number
    irs: u32,
}

impl State {
    pub fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRecvd => false,
            _ => true,
        }
    }
}

impl Connection {
    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_recv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        };
        // TODO: set available::WRITE
        a
    }

    /// Accepts a new incoming connection, setting the initial handshake,
    /// receiving the SYN and returning an ACK and a SYN.
    /// The 'a here is the lifetime of the packet itself,
    /// which is the lifetime of the buffer at [`crate::TcpSocket::run`].
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        // Expect a packet that has the SYN bit set
        if !tcph.syn() {
            return Ok(None);
        }

        let iss = 0;
        let wnd_size = 10;
        let mut c = Self {
            state: State::SynRecvd,
            recv: ReceiveSequenceSpace {
                // Keep track of sender info
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            send: SendSequenceSpace {
                // Decide on stuff we're sending them
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: wnd_size,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                iph.destination_addr().octets(),
                iph.source_addr().octets(),
            ),

            // Construct a new TCP header to send the acknowledgment
            tcp: etherparse::TcpHeader::new(
                tcph.destination_port(),
                tcph.source_port(),
                iss,
                wnd_size,
            ),

            incoming: Default::default(),
            unacked: Default::default(),
        };

        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, &[])?;

        Ok(Some(c))
    }

    /// Gets called when the connection is already known.
    /// Expecting an ACK for the SYN we sent on [`Connection::accept()`].
    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        _iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // Is this packet even worth looking into?
        // Valid segment check
        // RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND // First bit
        // RCV.NXT =< SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND // Last bit
        let seqn = tcph.sequence_number();
        let w_end = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let mut slen = data.len() as u32;
        if tcph.syn() {
            slen += 1;
        };
        if tcph.fin() {
            slen += 1;
        };

        let okay = if slen.eq(&0) {
            // Zero-length segment and zero-length window
            if self.recv.wnd.eq(&0) {
                // In this case, the seq number must be equal to nxt
                seqn.eq(&self.recv.nxt)
            } else {
                seqn.is_between_wrapped(self.recv.nxt.wrapping_sub(1), w_end)
            }
        } else {
            // If window is 0 than its not acceptable
            !self.recv.wnd.eq(&0) ||
            // if !(!false and !false) return false
            !(!seqn.is_between_wrapped(self.recv.nxt.wrapping_sub(1), w_end)
                && !seqn
                    .wrapping_add(slen - 1)
                    .is_between_wrapped(self.recv.nxt.wrapping_sub(1), w_end))
        };

        if !okay {
            self.write(nic, &[])?;
            return Ok(self.availability());
        }

        self.recv.nxt = seqn.wrapping_add(slen);

        // Acceptable ACK check
        // SND.UNA < SEG.ACK <= SND.NEXT
        let ackn = tcph.acknowledgment_number();
        if let State::SynRecvd = self.state {
            println!("SYN Received");
            if ackn.is_between_wrapped(self.send.una.wrapping_sub(1), self.send.nxt.wrapping_add(1))
            {
                self.state = State::Estab;
            } else {
                // @TODO: RESET <SEQ=SEG.ACK> <CTL=RST>
            }
        };

        if let State::Estab = self.state {
            println!("Connection established");
            if !ackn.is_between_wrapped(self.send.una, self.send.nxt.wrapping_add(1)) {
                return Ok(self.availability());
            }

            self.send.una = ackn;
            assert!(data.is_empty());

            // Terminate the connection
            self.tcp.fin = true;
            self.write(nic, &[])?;
            self.state = State::FinWait1;
        };

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // Our FIN has been ACKed
                println!("Our FIN has been ACKed. FIN: {}", tcph.fin());
                self.state = State::FinWait2;
            }
        };

        if tcph.fin() {
            if let State::FinWait2 = self.state {
                // We're done with the connection
                println!("Client has FINed.");
                self.write(nic, &[])?;
                self.state = State::TimeWait;
                return Ok(self.availability());
            }
        };

        Ok(self.availability())
    }

    /// Sends a chunk of data through the tun_tap interface.
    pub fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1504];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf.len(),
            self.ip.header_len() + self.tcp.header_len() as usize + payload.len(),
        );

        self.ip
            .set_payload_len(size - self.ip.header_len())
            .or_else(|_e| {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Error calculating checksum",
                ))
            })?;

        self.tcp.checksum = self.tcp.calc_checksum_ipv4(&self.ip, &[]).or_else(|_e| {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Error calculating IPV4 checksum",
            ))
        })?;

        // Write headers to buffer
        use std::io::Write;

        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten).or_else(|_e| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Error writing headers to buffer",
            ))
        })?;

        self.tcp.write(&mut unwritten)?;
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);

        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1u32);
            self.tcp.syn = false;
        }

        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1u32);
            self.tcp.fin = false;
        }

        // Send the data back through the the network interface
        nic.send(&buf[..buf.len() - unwritten])?;

        Ok(payload_bytes)
    }

    /// Helper function that sends a reset packet back to the client
    pub fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> Result<(), Box<dyn Error>> {
        self.tcp.rst = true;
        self.tcp.acknowledgment_number = 0;
        self.tcp.sequence_number = 0;
        self.write(nic, &[])?;

        Ok(())
    }

    pub(crate) fn is_recv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // PTPD: CloseWait, LastAck, Closed, Closing
            return true;
        }
        false
    }
}

/// Trait to deal with comparison of wrapping numbers.
pub trait Wrap {
    fn is_wrapping(&self, rhs: u32) -> bool;
    fn is_between_wrapped(&self, start: u32, end: u32) -> bool;
}

impl Wrap for u32 {
    fn is_wrapping(&self, rhs: u32) -> bool {
        self.wrapping_sub(rhs) > (1 << 31)
    }
    /// Compare numbers taking into consideration that they can be
    /// wrapped.
    /// # Examples
    /// ```
    /// # use tcp_rust::connection::Wrap;
    /// // Tests this case (X > S)
    /// //  0 |------E-----S---------X-------------| OK
    /// //           10    30        50
    /// let start = 30u32;
    /// let x = 50u32;
    /// let end = 10u32;
    ///
    /// assert!(x.is_between_wrapped(start, end.wrapping_add(1)));
    /// ```
    ///
    /// ```
    /// # use tcp_rust::connection::Wrap;
    /// // Tests this case (X < S)
    /// //  0 |------X-----E---------S------------| OK
    /// //           10    20        50
    /// let start = 50u32;
    /// let x = 10u32;
    /// let end = 20u32;
    ///   
    /// assert!(x.is_between_wrapped(start, end.wrapping_add(1)));
    /// ```
    fn is_between_wrapped(&self, start: u32, end: u32) -> bool {
        start.is_wrapping(*self) && self.is_wrapping(end)
    }
}
