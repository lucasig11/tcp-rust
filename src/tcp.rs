use bitflags::bitflags;
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::{
    collections::{BTreeMap, VecDeque},
    io, time, u32, usize,
};

bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b000000001;
        const WRITE = 0b00000010;
        const FLUSH = 0b00000100;
    }
}

/// TCP connection states
#[derive(Clone, Debug)]
pub enum State {
    SynRecvd,
    Estab,
    FinWait1,
    FinWait2,
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
    timers: Timers,
    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,

    pub(crate) closed: bool,
    closed_at: Option<u32>,
}

#[derive(Clone)]
struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    pub(crate) srtt: f64,
}

impl Default for Timers {
    fn default() -> Self {
        Self {
            send_times: Default::default(),
            srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
        }
    }
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

impl Connection {
    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_recv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        };

        if self.unacked.is_empty() {
            a |= Available::FLUSH;
        };

        // TODO: set available::WRITE
        a
    }

    pub fn on_tick(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        if let State::FinWait2 | State::TimeWait = self.state {
            // we have shutdown our write side and the other side acked, no need to (re)transmit anything
            return Ok(());
        }

        let n_unacked: usize = self
            .closed_at
            .unwrap_or(self.send.nxt)
            .wrapping_sub(self.send.una) as usize;
        let unsent: usize = self.unacked.len() - n_unacked as usize;

        let one_sec = time::Duration::from_secs_f64(1.0);

        let waited_secs = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|(_s, t)| t.elapsed());

        let should_retransmit = if let Some(waited_secs) = waited_secs {
            waited_secs > one_sec && waited_secs.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }

            self.write(nic, self.send.una, resend as usize)?;
        } else {
            // TODO: send new data if we have new data and space in the window
            if unsent.eq(&0) && self.closed_at.is_some() {
                // Nothing to retransmit
                return Ok(());
            }

            let allowed: usize = self.send.wnd as usize - n_unacked;

            // Can't send any data
            if allowed == 0 {
                return Ok(());
            }

            let send = std::cmp::min(unsent, allowed);
            if send < allowed && self.closed && self.closed_at.is_none() {
                // If we are allowed to send more than we're sending
                // And we're supposed to send the fin
                // Than send the fin
                self.tcp.fin = true;
                self.closed_at = Some(self.send.nxt.wrapping_add(unsent as u32));
            }

            self.write(nic, self.send.nxt, send)?;
        }

        Ok(())
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
        let wnd_size = 1024;
        let mut c = Self {
            state: State::SynRecvd,
            timers: Default::default(),
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
                nxt: iss,
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
            closed: false,
            closed_at: None,
        };

        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, c.send.nxt, 0)?;

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
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

        if !tcph.ack() {
            if tcph.syn() {
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }

        // Acceptable ACK check
        // SND.UNA < SEG.ACK <= SND.NEXT
        let ackn = tcph.acknowledgment_number();
        if let State::SynRecvd = self.state {
            if ackn.is_between_wrapped(self.send.una.wrapping_sub(1), self.send.nxt.wrapping_add(1))
            {
                self.state = State::Estab;
            } else {
                // TODO: RESET <SEQ=SEG.ACK> <CTL=RST>
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if ackn.is_between_wrapped(self.send.una, self.send.nxt.wrapping_add(1)) {
                if !self.unacked.is_empty() {
                    // send.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                    let data_start = self
                        .send
                        .una
                        .wrapping_add((self.send.una == self.send.iss).into());

                    let acked_data_end =
                        std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());

                    self.unacked.drain(..acked_data_end);

                    let una = self.send.una;
                    let srtt = &mut self.timers.srtt;

                    self.timers.send_times.retain(|&seq, sent| {
                        if seq.is_between_wrapped(una, ackn) {
                            *srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                            return false;
                        }
                        true
                    });
                }

                self.send.una = ackn;
            }

            // TODO: update window
        }

        if let State::FinWait1 = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.una == closed_at.wrapping_add(1) {
                    // our FIN has been ACKed!
                    self.state = State::FinWait2;
                }
            }
        }

        if !data.is_empty() {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                let mut unread_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;

                if unread_data_at > data.len() {
                    assert_eq!(unread_data_at, data.len() + 1);
                    unread_data_at = 0;
                }

                self.incoming.extend(&data[unread_data_at..]);

                /*
                Once the TCP takes responsibility for the data, it advances
                RCV.NXT over  the  data  accepted  and  adjust  RCV.WND  as
                appropriate   to   the   current    buffer    availability.
                The total of RCV.NXT and RCV.WND  should  not  be  reduced.
                */
                self.recv.nxt = seqn.wrapping_add(data.len() as u32);

                // Send an Ack of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                self.write(nic, self.send.nxt, 0)?;
            };
        }

        if tcph.fin() {
            if let State::FinWait2 = self.state {
                // We're done with the connection
                // Client has FINed
                self.recv.nxt = self.recv.nxt.wrapping_add(1);
                self.write(nic, self.send.nxt, 0)?;
                self.state = State::TimeWait;
            }
        }

        Ok(self.availability())
    }

    /// Sends a chunk of data through the tun_tap interface.
    pub fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32, limit: usize) -> io::Result<usize> {
        let mut buf = [0u8; 1504];
        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let mut offset = seq.wrapping_sub(self.send.una) as usize;

        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                offset = 0;
            }
        };

        // we want self.unacked[n_unacked..]
        let (mut head, mut tail) = self.unacked.as_slices();
        if head.len() >= offset {
            head = &head[offset..];
        } else {
            let skipped = head.len();
            head = &[];
            tail = &tail[(offset - skipped)..];
        }

        let max_data = std::cmp::min(limit, head.len() + tail.len());

        let size = std::cmp::min(
            buf.len(),
            self.ip.header_len() + self.tcp.header_len() as usize + max_data,
        );

        self.ip
            .set_payload_len(size - self.ip.header_len())
            .or_else(|_e| {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Error calculating checksum",
                ))
            })?;

        // Write headers to buffer
        use std::io::Write;
        let buf_len = buf.len();
        let mut unwritten = &mut buf[..];

        self.ip.write(&mut unwritten).unwrap();
        let iph_end = buf_len - unwritten.len();

        unwritten = &mut unwritten[self.tcp.header_len() as usize..];
        let tcph_end = buf_len - unwritten.len();

        // write the payload to the in-memory buffer
        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            // write as much as we can from payload1
            let p1l = std::cmp::min(limit, head.len());
            written += unwritten.write(&head[..p1l])?;
            limit -= written;

            // then, write more (if we can) from payload2
            let p2l = std::cmp::min(limit, tail.len());
            written += unwritten.write(&tail[..p2l])?;
            written
        };

        let payload_end = buf_len - unwritten.len();

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &buf[tcph_end..payload_end])
            .or_else(|_e| {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Error calculating IPV4 checksum",
                ))
            })?;

        let mut tcph_buf = &mut buf[iph_end..tcph_end];
        self.tcp.write(&mut tcph_buf).unwrap();

        let mut next_seq = seq.wrapping_add(payload_bytes as u32);

        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }

        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }

        if self.send.nxt.wrapping_lt(next_seq) {
            self.send.nxt = next_seq;
        }

        self.timers.send_times.insert(seq, time::Instant::now());

        // Send the data back through the the network interface
        nic.send(&buf[..payload_end])?;

        Ok(payload_bytes)
    }

    /*
    Helper function that sends a reset packet back to the client (not used)
    pub fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> Result<(), Box<dyn Error>> {
        self.tcp.rst = true;
        self.tcp.acknowledgment_number = 0;
        self.tcp.sequence_number = 0;
        self.write(nic, self.send.nxt, 0)?;
        Ok(())
    }
    */

    pub(crate) fn is_recv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // PTPD: CloseWait, LastAck, Closed, Closing
            return true;
        }
        false
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        match self.state {
            State::SynRecvd | State::Estab => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Connection is already closing",
                ));
            }
        };
        Ok(())
    }
}

/// Trait to deal with comparison of wrapping numbers.
pub trait Wrap {
    fn wrapping_lt(&self, rhs: u32) -> bool;
    fn is_between_wrapped(&self, start: u32, end: u32) -> bool;
}

impl Wrap for u32 {
    fn wrapping_lt(&self, rhs: u32) -> bool {
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
        start.wrapping_lt(*self) && self.wrapping_lt(end)
    }
}
