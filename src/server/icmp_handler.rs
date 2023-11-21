use crate::icmp_packets::IcmpReply;
use crate::server::{AuthenticatedUser, UserUpdate};
use crate::shared::packages::{AuthenticationReply, AuthenticationRequest, DataPacket, SessionExtension};
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::IcmpTypes::EchoRequest;
use pnet::packet::Packet;
use pnet::transport::{ipv4_packet_iter, TransportReceiver};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use pnet::packet::icmp::IcmpPacket;
use rand_core::OsRng;
use tun_tap::Iface;
use x25519_dalek::{EphemeralSecret, PublicKey};
use crate::shared::{RECV_TIMEOUT, sequence_number_to_ids, TIMEOUT};

pub struct IcmpHandler {
    icmp_tx: Sender<Option<(IcmpPacket<'static>, IpAddr)>>,
    tun_tx: Sender<UserUpdate>,
    stop_rx: Receiver<()>,
    tunnel: Arc<Iface>,
    password: String,
    authenticated: HashMap<u8, AuthenticatedUser>,
}

impl IcmpHandler {
    pub(super) fn new(
        icmp_tx: Sender<Option<(IcmpPacket<'static>, IpAddr)>>,
        tun_tx: Sender<UserUpdate>,
        stop_rx: Receiver<()>,
        tunnel: Arc<Iface>,
        password: String,
    ) -> IcmpHandler {
        IcmpHandler {
            icmp_tx,
            tun_tx,
            stop_rx,
            tunnel,
            password,
            authenticated: HashMap::new(),
        }
    }

    pub fn run(&mut self, mut receiver: TransportReceiver) {
        let mut iterator = ipv4_packet_iter(&mut receiver);
        let mut last_update =Instant::now();

        while let Ok(value) = iterator.next_with_timeout(RECV_TIMEOUT) {
            if let Ok(_) = self.stop_rx.try_recv() {
                break;
            }
            if let Some((ip_packet, addr)) = value {

                if let Some(echo_packet) = EchoRequestPacket::new(ip_packet.packet()) {
                    if echo_packet.get_icmp_type() == EchoRequest {
                        self.handle_packet(echo_packet, addr);
                    }
                }

                if last_update.elapsed() > Duration::from_secs(10) {
                    last_update = Instant::now();
                    self.discard_sessions();
                }
            }
        }
    }

    fn handle_packet(&mut self, echo_packet: EchoRequestPacket, addr: IpAddr) {
        let error = if echo_packet.payload().len() == DataPacket::SIZE
        {
            self.relay_data_packet(&echo_packet, addr)
        } else if echo_packet.payload().len() == AuthenticationRequest::SIZE
        {
            self.perform_handshake(&echo_packet, addr)
        } else if echo_packet.payload().len() == SessionExtension::SIZE {
            self.extend_session(&echo_packet, addr)
        } else {
            // No need to send normal echo reply if it is a normal echo reply anyways
            let _ = self.send_normal_icmp_echo_reply(&echo_packet, addr);
            Ok(())
        };
        // Default policy: send icmp reply
        if let Err(error) = error {
            println!("Encountered error {error:?}");
            let _ = self.send_normal_icmp_echo_reply(&echo_packet, addr);
        }
    }

    /// Sends a normal icmp reply, as if this is a regular machine
    fn send_normal_icmp_echo_reply(
        &self,
        echo_packet: &EchoRequestPacket,
        sender: IpAddr,
    ) -> io::Result<()> {
        // Construct new packet
        let mut reply = IcmpReply::new(echo_packet.payload().len());

        // Set parameters as per request
        reply.set_identifier(echo_packet.get_identifier());
        reply.set_sequence_number(echo_packet.get_sequence_number());
        reply.set_payload(echo_packet.payload());

        // Send it and ignore send errors
        let _ = self.icmp_tx.send(Some((reply.to_packet(), sender)));
        Ok(())
    }

    fn get_key_and_update_client(&mut self, echo_packet: &EchoRequestPacket, sender: IpAddr) -> io::Result<([u8; 32], u16)> {
        let (client_id, session_id) = sequence_number_to_ids(echo_packet.get_sequence_number());
        let client = self.authenticated.get_mut(&client_id)
            .ok_or(io::Error::new(io::ErrorKind::NotFound, "client id not found"))?;
        let (key, _) = client.session_keys.get(&session_id)
            .ok_or(io::Error::new(io::ErrorKind::NotFound, "session id not found"))?;
        // Update address if changed
        if client.address != sender {
            client.address = sender;
            let _ = self.tun_tx.send(UserUpdate::IpChanged(client_id, sender));
        }
        if client.identifier != echo_packet.get_identifier() {
            client.identifier = echo_packet.get_identifier();
            let _ = self.tun_tx.send(UserUpdate::IdentifierChanged(client_id, client.identifier));
        }
        Ok((key.clone(), client.identifier))
    }

    /// Relays a data packet from icmp to tun
    fn relay_data_packet(&mut self, echo_packet: &EchoRequestPacket, sender: IpAddr) -> io::Result<()> {
        let (key, _) = self.get_key_and_update_client(echo_packet, sender)?;
        let packet = DataPacket::verified_from_bytes(echo_packet.payload(), &key)?;
        self.tunnel.send(packet.data.as_slice())?;
        Ok(())
    }

    /// Perform a handshake, initiating a session
    fn perform_handshake(
        &mut self,
        echo_packet: &EchoRequestPacket,
        sender: IpAddr,
    ) -> io::Result<()> {
        println!("performing handshake");

        // verify package and password
        let request = AuthenticationRequest::verified_from_bytes(echo_packet.payload(), &self.password)?;

        // Get next available client id
        let client_id = (2..255u8).filter(|v| !self.authenticated.contains_key(v)).next()
            .ok_or(io::Error::new(io::ErrorKind::AddrInUse, "No available client id"))?;

        // Generate Diffie Hellman key pair and shared secret
        let private_key = EphemeralSecret::random_from_rng(&mut OsRng);
        let public_key = PublicKey::from(&private_key);
        let shared_secret = private_key.diffie_hellman(&request.dh_key);

        // Generate session key
        let session_id = 1u8;
        let session_key = ChaCha20Poly1305::generate_key(&mut OsRng);

        // Send icmp reply
        let auth_reply = AuthenticationReply::new(public_key, client_id, session_id, session_key.as_ref());
        let payload = auth_reply.to_bytes(&shared_secret, &self.password);

        let mut reply = IcmpReply::new(AuthenticationReply::SIZE);

        // Set parameters as per request
        reply.set_identifier(echo_packet.get_identifier());
        reply.set_sequence_number(echo_packet.get_sequence_number());
        reply.set_payload(&payload);

        // Send it and ignore send errors
        let _ = self.icmp_tx.send(Some((reply.to_packet(), sender)));

        // add client to authenticated users hash map
        let mut session_keys: HashMap<u8, ([u8; 32], Instant)> = HashMap::new();
        session_keys.insert(session_id, (*session_key.as_ref(), Instant::now()));
        let user = AuthenticatedUser {
            address: sender,
            session_keys,
            keep_alive: Instant::now(),
            identifier: echo_packet.get_identifier(),
        };
        self.authenticated.insert(client_id, user.clone());
        let _ = self.tun_tx.send(UserUpdate::AddUser {
            client_id,
            user,
        });
        Ok(())
    }

    fn extend_session(&mut self, echo_packet: &EchoRequestPacket,
        sender: IpAddr,) -> io::Result<()> {
        println!("handling session extension");
        let (key, identifier) = self.get_key_and_update_client(echo_packet, sender)?;
        let packet = SessionExtension::verified_from_bytes(echo_packet.payload(), &key)?;
        let (user_id, _) = sequence_number_to_ids(echo_packet.get_sequence_number());
        if let Some(user) = self.authenticated.get_mut(&user_id) {
            user.keep_alive = Instant::now();
            user.session_keys.insert(packet.session_id, (packet.new_key, Instant::now()));
        }
        let _ = self.tun_tx.send(UserUpdate::AddSession {
            client_id: user_id,
            session_id: packet.session_id,
            session_key: packet.new_key,
        });

        let bytes = packet.to_bytes(&key);

        let mut icmp_packet = IcmpReply::new(bytes.len());
        icmp_packet.set_identifier(identifier);
        icmp_packet.set_sequence_number(echo_packet.get_sequence_number());
        icmp_packet.set_payload(bytes.as_slice());

        let _ = self.icmp_tx.send(Some((icmp_packet.to_packet(), sender)));

        Ok(())
    }

    fn discard_sessions(&mut self) {
        let clients = self.authenticated.keys().cloned().collect::<Vec<u8>>();
        for client_id in clients {
            let user = self.authenticated.get_mut(&client_id).unwrap();
            if user.keep_alive.elapsed() > TIMEOUT {
                let _ = self.tun_tx.send(UserUpdate::DeleteUser(client_id));
                self.authenticated.remove(&client_id);
            } else {
                let sessions = user.session_keys.keys().cloned().collect::<Vec<u8>>();
                for session_id in sessions {
                    let (_, last_seen) = user.session_keys.get(&session_id).unwrap();
                    if last_seen.elapsed() > TIMEOUT {
                        user.session_keys.remove(&session_id);
                    }
                }
            }
        }
    }
}
