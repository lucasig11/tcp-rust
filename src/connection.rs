#![allow(unused_variables)]
#![allow(dead_code)]
use std::{error::Error, io, net::Ipv4Addr};

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

/// TCP connection states
pub enum State {
    Closed,
    Listen,
    SynRecvd,
    Estab,
}

// TCB - transmition control block
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
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
struct SendSequenceSpace {
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

/// Receive Sequence Space
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
struct ReceiveSequenceSpace {
    /// Receive Next
    nxt: u32,
    /// Receive window
    wnd: u16,
    /// Receive urgent pointer
    up: bool,
    /// Initial receive sequence number
    irs: u32,
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
    /// The 'a here is the lifetime of the packet itself,
    /// which is the lifetime of the buffer at TCP::run
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
        let c = Self {
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
        };

        // Construct a new TCP header to send the acknowledgment
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );

        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        // Build an IP packet from the header
        let ip_packet = etherparse::Ipv4Header::new(
            syn_ack.header_len(),
            64,
            etherparse::IpTrafficClass::Tcp,
            iph.destination_addr().octets(),
            iph.source_addr().octets(),
        );

        // Write headers to buffer
        let unwritten = {
            let mut unwritten = &mut buf[..];
            ip_packet.write(&mut unwritten)?;
            syn_ack.write(&mut unwritten)?;
            unwritten.len()
        };

        // Send the data back through the the network interface
        nic.send(&buf[..buf.len() - unwritten])?;

        Ok(Some(c))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> io::Result<()> {
        // unimplemented!();
        Ok(())
    }
}
