## TCP Protocol implementation in Rust

**Jon Gjengset series** _(highly recommended)_
[Part 1](https://youtu.be/bzja9fQWzdA)
[Part 2](https://youtu.be/OCpt1I0MWXE)
[Part 3](https://youtu.be/8GE6ltLRJA4)

* Uses Linux's `TUN/TAP` driver to create a virtual network device 
in userland that communicates with the kernel, which understands it as it's own NIC. As per the [docs](https://www.kernel.org/doc/Documentation/networking/tuntap.txt): 

<p text-align="justify">

Virtual network device can be viewed as a simple Point-to-Point or
Ethernet device, which instead of receiving packets from a physical 
media, receives them from user space program and instead of sending 
packets via physical media sends them to the user space program. 

</p>

* See also: [tun-tap](https://docs.rs/tun-tap/0.1.2/tun_tap/) crate on crates.io.

### Running (Linux or WSL2)
```sh
cd tcp-rust

# Generate the docs
cargo doc --open 

# Give execution permission to the script and run it
chmod +x run.sh
./run.sh

# See the 'tun0' interface created
ip addr

```

