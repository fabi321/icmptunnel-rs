# Icmptunnel-rs

A rust implementation of an icmp tunnel, complete with authentication and encryption. Inspired by
https://github.com/DhavalKapil/icmptunnel

# Quickstart

```commandline
git clone https://github.com/fabi321/icmptunnel-rs.git
cd icmptunnel-rs
cargo build --release
```

running the server

```commandline
sudo ./target/release/icmptunnel-rs server --password <password>
```

running the client

```commandline
sudo ./target/release/icmptunnel-rs client --password <password> --server-address <server ip>
```

# Features

 - Authentication
 - Transparent server (if packet is not a tunnel packet, will reply with normal icmp echo reply)
 - Encryption
 - Automatic IP allocation for connecting clients (up to 253 clients per server)
 - Session handling with timeouts
 - Session key renewal

# Known limitations

 - MTU of transfer medium is hardcoded (no support if MTU between server and client are below hardcoded MTU)
 - IPv4 only, both for transmitted packets and encapsulating ICMP packets
 - Only tested on linux

# Known security issues

 - Passwords are exposed as they are visible in process list
 - It is possible to reuse the hashed password. However, sessions created this way are effectively useless as the
   attacker would need the private dh-key in order to actually use it
 - Timing side channels allow for server discovery (at least in theory)
