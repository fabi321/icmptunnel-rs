use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::PrimitiveValues;
use pnet::packet::icmp::IcmpPacket;
use tun_tap::Iface;
use crate::constants::MAX_PAYLOAD_SIZE;
use crate::icmp_packets::{IcmpReply, IcmpTooBig};
use crate::server::UserUpdate;
use crate::shared::ids_to_sequence_number;
use crate::shared::packages::DataPacket;

pub struct TunHandler {
    icmp_tx: Sender<Option<(IcmpPacket<'static>, IpAddr)>>,
    tun_rx: Receiver<UserUpdate>,
    tunnel: Arc<Iface>,
    users: HashMap<u8, (u8, IpAddr, [u8; 32], u16)>
}

impl TunHandler {
    pub(super) fn new(
        icmp_tx: Sender<Option<(IcmpPacket<'static>, IpAddr)>>,
        tun_rx: Receiver<UserUpdate>,
        tunnel: Arc<Iface>,
    ) -> TunHandler {
        TunHandler {
            icmp_tx,
            tun_rx,
            tunnel,
            users: HashMap::new(),
        }
    }

    pub fn run(&mut self) {
        let mut buf = [0u8; MAX_PAYLOAD_SIZE + 4];

        'main: while let Ok(packet_size) = self.tunnel.recv(&mut buf) {
            while let Ok(message) = self.tun_rx.try_recv() {
                if self.update_users(message) {
                    break 'main
                }
            }

            let error = self.send_data(&buf, packet_size);
            if let Err(error) = error {
                println!("Error processing tun packet: {error:?}");
            }
        }
    }

    fn send_data(&self, buf: &[u8; MAX_PAYLOAD_SIZE + 4], size: usize) -> io::Result<()> {
        // Get ipv4 packet for retrieving destination address and checking in general
        let packet = Ipv4Packet::new(&buf[4..size])
            .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Not a valid ipv4 packet"))?;
        if packet.get_version() != 4 {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "Only ipv4 is supported",
            ));
        }

        if size > MAX_PAYLOAD_SIZE + 4 {
            // Send Destination unreachable fragmentation needed
            let mut icmp_reply = IcmpTooBig::new();
            icmp_reply.set_next_hop_max_mtu(MAX_PAYLOAD_SIZE as u16 - 4);
            icmp_reply.set_raw(&buf[4..]);

            let _ = self.icmp_tx.send(Some((icmp_reply.to_packet(), IpAddr::from(packet.get_source()))));

            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Too large packet"
            ));
        }

        // get user id by looking at ip address
        let user_id = if let (10, 0, 1, user_id) = packet.get_destination().to_primitive_values() {
            if user_id > 1 {
                Ok(user_id)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "Can't send to self"
                ))
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "not in address range"
            ))
        }?;

        // retrieve user
        let user = self.users.get(&user_id)
            .ok_or(io::Error::new(io::ErrorKind::NotFound, "User not found"))?;

        // encrypt payload data
        let data = Vec::from(&buf[..size]);
        let data_packet = DataPacket::new(data);
        let to_send = data_packet.to_bytes(&user.2)?;

        // Finalize icmp reply and send it
        let mut icmp_packet = IcmpReply::new(DataPacket::SIZE);
        icmp_packet.set_identifier(user.3);
        icmp_packet.set_sequence_number(ids_to_sequence_number(user_id, user.0));
        icmp_packet.set_payload(&to_send);

        let _ = self.icmp_tx.send(Some((icmp_packet.to_packet(), user.1)));

        Ok(())
    }

    fn update_users(&mut self, message: UserUpdate) -> bool {
        match message {
            UserUpdate::AddUser { client_id, user } => {
                // There should always be at least one session
                let (session_id, (key, _)) = user.session_keys.into_iter().next().unwrap();
                self.users.insert(
                    client_id,
                    (session_id, user.address, key, user.identifier)
                );
                false
            }
            UserUpdate::AddSession { client_id, session_id, session_key, .. } => {
                if let Some(user) = self.users.get_mut(&client_id) {
                    user.0 = session_id;
                    user.2 = session_key;
                };
                false
            }
            UserUpdate::IpChanged(user_id, address) => {
                if let Some(user) = self.users.get_mut(&user_id) {
                    user.1 = address
                }
                false
            }
            UserUpdate::DeleteUser(user_id) => {
                self.users.remove(&user_id);
                false
            }
            UserUpdate::IdentifierChanged(client_id, identifier) => {
                if let Some(user) = self.users.get_mut(&client_id) {
                    user.3 = identifier
                }
                false
            }
            UserUpdate::Stop => {true}
        }
    }
}
