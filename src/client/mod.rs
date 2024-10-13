use crate::client::icmp_handler::IcmpHandler;
use crate::client::tun_handler::TunHandler;
use crate::configure_network;
use crate::shared::get_transport_channel;
use std::net::IpAddr;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use tun_tap::{Iface, Mode};

mod icmp_handler;
mod tun_handler;

pub fn start_client(server_address: IpAddr, password: String) {
    let (mut transport_tx, mut transport_rx) = get_transport_channel();
    let (icmp_tx, icmp_rx) = channel();
    let (stop_tx, stop_rx) = channel();
    let mut icmp_handler = IcmpHandler::new(icmp_tx.clone(), password, server_address);

    let (gateway, interface) =
        configure_network::get_gateway_interface().expect("Error getting default route");
    let icmp_tx_clone = icmp_tx.clone();
    let gateway_clone = gateway.clone();
    let interface_clone = interface.clone();
    ctrlc::set_handler(move || {
        configure_network::restore_client_network(gateway_clone.clone(), interface_clone.clone())
            .expect("Error while restoring network configuration");
        stop_tx.send(()).expect("couldn't send stop signal");
        icmp_tx_clone.send(None).expect("couldn't send stop signal");
    })
    .expect("Error while setting up sigint handler");

    let icmp_send_thread = thread::spawn(move || {
        while let Ok(Some((packet, addr))) = icmp_rx.recv() {
            let _ = transport_tx.send_to(packet, addr);
        }
    });

    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }
        println!("authenticating");
        if let Ok(mut icmp_handler) = icmp_handler.auth(&mut transport_rx) {
            println!("authentication successful, starting tunnel");
            let tunnel = Arc::new(Iface::new("tun0", Mode::Tun).expect("Error creating tunnel"));
            let (tun_tx, tun_rx) = channel();
            icmp_handler.add_tunnel(tunnel.clone(), tun_tx.clone());
            configure_network::configure_client_network(server_address, icmp_handler.client_id)
                .expect("Error configuring network");

            let credentials = icmp_handler.get_credentials();

            let mut tun_handler = TunHandler::new(
                tunnel,
                icmp_tx.clone(),
                server_address,
                icmp_handler.client_id,
                credentials.0,
                credentials.1,
                tun_rx,
                icmp_handler.identifier,
            );

            let tun_thread = thread::spawn(move || {
                tun_handler.run();
            });

            println!("tunnel started, operating now");
            let stop = icmp_handler.run(&mut transport_rx, &stop_rx);
            println!(
                "stopped due to {}",
                if stop { "interrupt" } else { "timeout" }
            );

            configure_network::restore_client_network(gateway.clone(), interface.clone())
                .expect("could not restore network");

            tun_tx.send(None).expect("could not stop tun thread");
            tun_thread.join().unwrap();

            if stop {
                break;
            }
        } else {
            println!("Timeout while trying to connect to server")
        }
    }
    println!("stopping icmptunnel");
    let _ = icmp_tx.send(None);

    icmp_send_thread.join().unwrap();
}
