## TCP Protocol implementation in Rust

**Jon Gjengset series** _(highly recommended)_
[Part 1](https://youtu.be/bzja9fQWzdA)
[Part 2](https://youtu.be/OCpt1I0MWXE)
[Part 3](https://youtu.be/8GE6ltLRJA4)

* Uses Linux's `tun_tap` (see [tun-tap](https://docs.rs/tun-tap/0.1.2/tun_tap/)) to create a virtual network interface in userland that communicates with the kernel, which understands it as it's own NIC.


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

