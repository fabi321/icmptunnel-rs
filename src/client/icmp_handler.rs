use crate::icmp_packets::IcmpRequest;
use crate::shared::packages::{
    AuthenticationReply, AuthenticationRequest, DataPacket, SessionExtension,
};
use crate::shared::{ids_to_sequence_number, sequence_number_to_ids, RECV_TIMEOUT, TIMEOUT};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes::EchoReply;
use pnet::packet::Packet;
use pnet::transport::{ipv4_packet_iter, TransportReceiver};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tun_tap::Iface;
use x25519_dalek::{PublicKey, ReusableSecret};

#[derive(Debug)]
pub struct IcmpHandler {
    icmp_tx: Sender<Option<(IcmpPacket<'static>, IpAddr)>>,
    password: String,
    server_ip: IpAddr,
}

impl IcmpHandler {
    pub fn new(
        icmp_tx: Sender<Option<(IcmpPacket<'static>, IpAddr)>>,
        password: String,
        server_ip: IpAddr,
    ) -> IcmpHandler {
        IcmpHandler {
            icmp_tx,
            password,
            server_ip,
        }
    }

    pub fn auth(&mut self, receiver: &mut TransportReceiver) -> io::Result<AuthedIcmpHandler> {
        // generate key pair
        let key = ReusableSecret::random_from_rng(&mut OsRng);
        let pub_key = PublicKey::from(&key);

        // pack key into auth request packet and send it
        let request = AuthenticationRequest::new(pub_key);
        let request_bytes = request.to_bytes(&self.password);
        let mut request_packet = IcmpRequest::new(AuthenticationRequest::SIZE);
        request_packet.set_identifier(0);
        request_packet.set_payload(request_bytes.as_slice());
        let _ = self
            .icmp_tx
            .send(Some((request_packet.to_packet(), self.server_ip)));

        let mut iterator = ipv4_packet_iter(receiver);
        let target = Instant::now() + Duration::from_secs(15);
        while let Ok(Some((ip_packet, _))) =
            iterator.next_with_timeout(target.duration_since(Instant::now()))
        {
            if let Some(echo_packet) = EchoReplyPacket::new(ip_packet.packet()) {
                if let Ok(auth_reply) = AuthenticationReply::verified_from_bytes(
                    echo_packet.payload(),
                    &key,
                    &self.password,
                ) {
                    let mut old_sessions = HashMap::new();
                    old_sessions.insert(auth_reply.session_id, auth_reply.session_key);
                    return Ok(AuthedIcmpHandler {
                        icmp_tx: self.icmp_tx.clone(),
                        server_ip: self.server_ip,
                        client_id: auth_reply.client_id,
                        current_session_id: auth_reply.session_id,
                        old_sessions,
                        keep_alive: Instant::now(),
                        timeout: Instant::now(),
                        tunnel: None,
                        tun_tx: None,
                        identifier: OsRng.next_u32() as u16,
                    });
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Time out while trying to establish a connection",
        ))
    }
}

#[derive(Debug)]
pub struct AuthedIcmpHandler {
    icmp_tx: Sender<Option<(IcmpPacket<'static>, IpAddr)>>,
    server_ip: IpAddr,
    pub client_id: u8,
    current_session_id: u8,
    old_sessions: HashMap<u8, [u8; 32]>,
    keep_alive: Instant,
    timeout: Instant,
    tunnel: Option<Arc<Iface>>,
    tun_tx: Option<Sender<Option<(u8, [u8; 32])>>>,
    pub identifier: u16,
}

impl AuthedIcmpHandler {
    pub fn add_tunnel(&mut self, tunnel: Arc<Iface>, tun_tx: Sender<Option<(u8, [u8; 32])>>) {
        self.tunnel = Some(tunnel);
        self.tun_tx = Some(tun_tx);
    }

    pub fn run(&mut self, receiver: &mut TransportReceiver, stop_rx: &Receiver<()>) -> bool {
        let mut iterator = ipv4_packet_iter(receiver);
        while let Ok(packet) = iterator.next_with_timeout(RECV_TIMEOUT) {
            if let Ok(_) = stop_rx.try_recv() {
                return true;
            }
            if self.keep_alive.elapsed() > TIMEOUT {
                // unable to refresh session in time
                break;
            } else if self.keep_alive.elapsed() > Duration::from_secs(60)
                && self.timeout.elapsed() > Duration::from_secs(15)
            {
                self.send_keep_alive()
            }
            if let Some((ip_packet, addr)) = packet {
                if let Some(echo_packet) = EchoReplyPacket::new(ip_packet.packet()) {
                    if echo_packet.get_icmp_type() == EchoReply && addr == self.server_ip {
                        if let Err(error) = self.handle_packet(echo_packet) {
                            println!("Error while processing icmp packet: {error:?}");
                        }
                    }
                }
            }
        }
        false
    }

    pub fn send_keep_alive(&mut self) {
        println!("Extending session");
        self.timeout = Instant::now();
        let new_session_id = self.current_session_id.wrapping_add(1);
        let mut new_key = [0u8; 32];
        OsRng.fill_bytes(&mut new_key[..]);
        self.old_sessions.insert(new_session_id, new_key);
        let packet = SessionExtension::new(new_key, new_session_id);
        let (session_id, key) = self.get_credentials();
        let bytes = packet.to_bytes(&key);

        let mut icmp_packet = IcmpRequest::new(bytes.len());
        icmp_packet.set_payload(bytes.as_slice());
        icmp_packet.set_identifier(self.identifier);
        icmp_packet.set_sequence_number(ids_to_sequence_number(self.client_id, session_id));

        let _ = self
            .icmp_tx
            .send(Some((icmp_packet.to_packet(), self.server_ip)));
    }

    pub fn get_credentials(&self) -> (u8, [u8; 32]) {
        (
            self.current_session_id,
            self.old_sessions
                .get(&self.current_session_id)
                .unwrap()
                .clone(),
        )
    }

    fn handle_packet(&mut self, echo_packet: EchoReplyPacket) -> io::Result<()> {
        let (client_id, _) = sequence_number_to_ids(echo_packet.get_sequence_number());
        if client_id == self.client_id && echo_packet.payload().len() == DataPacket::SIZE {
            self.relay_data_packet(&echo_packet)?
        } else if client_id == self.client_id
            && echo_packet.payload().len() == SessionExtension::SIZE
        {
            self.handle_session_extension(echo_packet)?
        }
        Ok(())
    }

    fn relay_data_packet(&self, echo_packet: &EchoReplyPacket) -> io::Result<()> {
        let (_, session_id) = sequence_number_to_ids(echo_packet.get_sequence_number());
        let key = self
            .old_sessions
            .get(&session_id)
            .ok_or(io::Error::new(io::ErrorKind::NotFound, "Key not found"))?;
        let data_packet = DataPacket::verified_from_bytes(echo_packet.payload(), key)?;
        let _ = self
            .tunnel
            .as_ref()
            .unwrap()
            .send(data_packet.data.as_slice());
        Ok(())
    }

    fn handle_session_extension(&mut self, echo_packet: EchoReplyPacket) -> io::Result<()> {
        println!("successfully extended session");
        let (_, key) = self.get_credentials();
        let packet = SessionExtension::verified_from_bytes(echo_packet.payload(), &key)?;
        self.current_session_id = packet.session_id;
        self.keep_alive = Instant::now();
        let _ = self
            .tun_tx
            .as_ref()
            .unwrap()
            .send(Some((packet.session_id, packet.new_key)));
        Ok(())
    }
}
