#![allow(unused_variables)]
#![allow(dead_code)]
use std::{convert::TryInto, error::Error, io, net::Ipv4Addr, u32};

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

/// TCP connection states
pub enum State {
    /// SYN Received
    SynRecvd,
    /// Connection established
    Estab,
}

// TCB - transmition control block
pub struct Connection {
    /// Connection's current state. See [`State`].
    pub state: State,
    /// Connection IP Header
    pub ip: etherparse::Ipv4Header,
    pub send: SendSequenceSpace,
    pub recv: ReceiveSequenceSpace,
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
pub struct SendSequenceSpace {
    /// Send Unacknowledged
    pub una: u32,
    /// Send Next
    pub nxt: u32,
    /// Send window
    pub wnd: u16,
    /// Send urgent pointer
    pub up: bool,
    /// Segment sequence number for last window update
    pub wl1: u32,
    /// Segment acknowledgement numebr use for alast window update
    pub wl2: u32,
    /// Initial sequence number
    pub iss: u32,
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
pub struct ReceiveSequenceSpace {
    /// Receive Next
    pub nxt: u32,
    /// Receive window
    pub wnd: u16,
    /// Receive urgent pointer
    pub up: bool,
    /// Initial receive sequence number
    pub irs: u32,
}

/// Connection quad
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    /// Source IP and Port
    pub src: (Ipv4Addr, u16),
    /// Destination IP and Port
    pub dst: (Ipv4Addr, u16),
}

impl Connection {
    /// Accepts a new incoming connection, setting the initial handshake,
    /// receiving the SYN and returning an ACK and a SYN.
    /// The 'a here is the lifetime of the packet itself,
    /// which is the lifetime of the buffer at [`crate::TcpSocket::run`].
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> Result<Option<Self>, Box<dyn Error>> {
        let mut buf = [0u8; 1504];

        // Expect a packet that has the SYN bit set
        if !tcph.syn() {
            return Ok(None);
        }

        let iss = 0;
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
                wnd: 10,
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
        };

        // Construct a new TCP header to send the acknowledgment
        // The kernel sets the checksum for us
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );

        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        c.ip.set_payload_len(syn_ack.header_len() as usize + 0)?;

        // Write headers to buffer
        let unwritten = {
            let mut unwritten = &mut buf[..];
            c.ip.write(&mut unwritten)?;
            syn_ack.write(&mut unwritten)?;
            unwritten.len()
        };

        // Send the data back through the the network interface
        nic.send(&buf[..buf.len() - unwritten])?;

        Ok(Some(c))
    }

    /// Gets called when the connection is already known.
    /// Expecting an ACK for the SYN we sent on [`Connection::accept()`].
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // Acceptable ACK check
        // SND.UNA < SEG.ACK <= SND.NEXT
        let ackn = tcph.acknowledgment_number();
        if !ackn.is_between_wrapped(self.send.una, self.send.nxt.wrapping_add(1)) {
            return Ok(());
        }

        // Valid segment check
        // RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND // First bit
        // RCV.NXT =< SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND // Last bit
        let seqn = tcph.sequence_number();
        let len: u32 = data.len().try_into().unwrap();

        if !seqn.is_between_wrapped(
            self.recv.nxt.wrapping_sub(1),
            self.recv.nxt.wrapping_add(self.recv.wnd as u32),
        ) && !(seqn + len - 1).is_between_wrapped(
            self.recv.nxt.wrapping_sub(1),
            self.recv.nxt.wrapping_add(self.recv.wnd as u32),
        ) {
            return Ok(());
        }

        match self.state {
            State::SynRecvd => {
                // Expect to get an ACK for our SYN
            }
            State::Estab => {
                todo!()
            }
        }
        Ok(())
    }
}

/// Trait to deal with comparison of wrapping numbers.
pub trait Wrap {
    fn is_between_wrapped(&self, start: u32, end: u32) -> bool;
}

impl Wrap for u32 {
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
        use std::cmp::Ordering;

        match start.cmp(&self) {
            Ordering::Equal => false,

            // Check is violated iff end is between start and x
            //  0 |------------S---------X--------E----| OK
            //  0 |------E-----S---------X-------------| OK
            //
            //  0 |----S------------E----X-------------| Not OK
            Ordering::Less => !(end >= start && end <= *self),

            // Check is ok iff end is between start and x (S < E < X)
            // Only this case (S > X)
            //  0 |------X-----E---------S------------| OK
            Ordering::Greater => end < start && end > *self,
        }
    }
}
