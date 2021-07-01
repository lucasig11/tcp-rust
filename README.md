<h1 align="center"> Implementing RFC 793 (TCP) in Rust </h1>

<p align="center">
    <a href="#about">About</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
    <a href="#running-linux-or-wsl2">Running</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
    <a href="#more">More</a>&nbsp;&nbsp;&nbsp;
</p>

## About
* Uses Linux's `TUN/TAP` driver to create a virtual network device 
in userland that communicates with the kernel. As per the [docs](https://www.kernel.org/doc/Documentation/networking/tuntap.txt): 

> Virtual network device can be viewed as a simple Point-to-Point or
Ethernet device, which instead of receiving packets from a physical 
media, receives them from user space program and instead of sending 
packets via physical media sends them to the user space program. 

* See also: [tun-tap](https://docs.rs/tun-tap/0.1.2/tun_tap/) crate.

## Running (Linux or WSL2)
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

---
## More
<p align="center">
    <strong>Jon Gjengset's series (Implementing TCP in Rust)</strong> 
    </br>
    <a href="https://youtu.be/bzja9fQWzdA">Part 1</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
    <a href="https://youtu.be/OCpt1I0MWXE">Part 2</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
    <a href="https://youtu.be/8GE6ltLRJA4">Part 3</a>&nbsp;&nbsp;&nbsp;
</p>
