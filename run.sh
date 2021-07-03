#!/bin/bash
cargo b --release 
ext=$?
if [ $ext -ne 0 ]; then
	exit $ext
fi
sudo setcap CAP_NET_ADMIN=eip target/release/tcp_rust
./target/release/tcp_rust $1 &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
