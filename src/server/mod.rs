use crate::configure_network;
use crate::server::icmp_handler::IcmpHandler;
use crate::server::tun_handler::TunHandler;
use crate::shared::get_transport_channel;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tun_tap::{Iface, Mode};

mod icmp_handler;
mod tun_handler;

#[derive(Debug, Clone)]
struct AuthenticatedUser {
    pub address: IpAddr,
    pub identifier: u16,
    /// Mapping from session id to key and key timestamp
    pub session_keys: HashMap<u8, ([u8; 32], Instant)>,
    pub keep_alive: Instant,
}

#[derive(Debug, Clone)]
enum UserUpdate {
    AddUser {
        client_id: u8,
        user: AuthenticatedUser,
    },
    AddSession {
        client_id: u8,
        session_id: u8,
        session_key: [u8; 32],
    },
    IpChanged(u8, IpAddr),
    DeleteUser(u8),
    IdentifierChanged(u8, u16),
    Stop,
}

pub fn start_server(password: String) {
    // Set up channels and tunnel
    let (mut transport_tx, transport_rx) = get_transport_channel();
    let (stop_icmp_tx, stop_icmp_rx) = channel();
    let (tun_tx, tun_rx) = channel();
    let (send_icmp_tx, send_icmp_rx) = channel();
    let tunnel = Arc::new(Iface::new("tun0", Mode::Tun).expect("Error creating tunnel"));

    // set up sigint handler
    let send_icmp_tx_clone = send_icmp_tx.clone();
    let tun_tx_clone = tun_tx.clone();
    ctrlc::set_handler(move || {
        configure_network::restore_server_network()
            .expect("Error while restoring network configuration");
        stop_icmp_tx.send(()).expect("couldn't send stop signal");
        tun_tx_clone
            .send(UserUpdate::Stop)
            .expect("couldn't send stop signal");
        send_icmp_tx_clone
            .send(None)
            .expect("couldn't send stop signal");
    })
    .expect("Error while setting up sigint handler");

    // configure network
    configure_network::configure_server_network().expect("Error setting up network");

    // Spawn a separate thread to handle incoming ICMP packets
    let mut icmp_handler = IcmpHandler::new(
        send_icmp_tx.clone(),
        tun_tx,
        stop_icmp_rx,
        tunnel.clone(),
        password,
    );
    let icmp_recv_thread = thread::spawn(move || {
        icmp_handler.run(transport_rx);
    });

    let icmp_send_thread = thread::spawn(move || {
        while let Ok(Some((packet, addr))) = send_icmp_rx.recv() {
            let _ = transport_tx.send_to(packet, addr);
        }
    });

    let mut tun_handler = TunHandler::new(send_icmp_tx, tun_rx, tunnel);
    let _tun_thread = thread::spawn(move || {
        tun_handler.run();
    });

    icmp_recv_thread.join().unwrap();
    icmp_send_thread.join().unwrap();
    // tun has no timeout and thus waits pretty long
    // tun_thread.join().unwrap();
}
