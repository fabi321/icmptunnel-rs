use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::PrimitiveValues;
use pnet::packet::icmp::IcmpPacket;
use tun_tap::Iface;
use crate::constants::MAX_PAYLOAD_SIZE;
use crate::icmp_packets::{IcmpRequest, IcmpTooBig};
use crate::shared::ids_to_sequence_number;
use crate::shared::packages::DataPacket;

pub struct TunHandler {
    tunnel: Arc<Iface>,
    icmp_tx: Sender<Option<(IcmpPacket<'static>, IpAddr)>>,
    server_ip: IpAddr,
    client_id: u8,
    session_id: u8,
    key: [u8; 32],
    tun_rx: Receiver<Option<(u8, [u8; 32])>>,
    identifier: u16,
}

impl TunHandler {
    pub fn new(
        tunnel: Arc<Iface>,
        icmp_tx: Sender<Option<(IcmpPacket<'static>, IpAddr)>>,
        server_ip: IpAddr,
        client_id: u8,
        session_id: u8,
        key: [u8; 32],
        tun_rx: Receiver<Option<(u8, [u8; 32])>>,
        identifier: u16,
    ) -> TunHandler {
        TunHandler {
            tunnel,
            icmp_tx,
            server_ip,
            client_id,
            session_id,
            key,
            tun_rx,
            identifier,
        }
    }

    pub fn run(&mut self) {
        let mut buf = [0u8; MAX_PAYLOAD_SIZE + 4];

        'main: while let Ok(packet_size) = self.tunnel.recv(&mut buf) {
            while let Ok(message) = self.tun_rx.try_recv() {
                if let Some((session_id, key)) = message {
                    self.session_id = session_id;
                    self.key = key;
                } else {
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

        if size > MAX_PAYLOAD_SIZE {
            // Send Destination unreachable fragmentation needed
            let mut icmp_reply = IcmpTooBig::new();
            icmp_reply.set_next_hop_max_mtu(MAX_PAYLOAD_SIZE as u16 - 4);
            icmp_reply.set_raw(buf.as_slice());

            println!("{packet:?}");

            let _ = self.icmp_tx.send(Some((icmp_reply.to_packet(), IpAddr::from(packet.get_source()))));

            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Too large packet"
            ));
        }

        // Filter own packets
        if packet.get_destination().to_primitive_values() == (10, 0, 1, self.client_id) {
            return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "Can't send to self"
            ))
        }

        // encrypt payload data
        let data = Vec::from(&buf[..size]);
        let data_packet = DataPacket::new(data);
        let to_send = data_packet.to_bytes(&self.key)?;

        // Finalize icmp reply and send it
        let mut icmp_packet = IcmpRequest::new(DataPacket::SIZE);
        icmp_packet.set_identifier(self.identifier);
        icmp_packet.set_sequence_number(ids_to_sequence_number(self.client_id, self.session_id));
        icmp_packet.set_payload(&to_send);

        let _ = self.icmp_tx.send(Some((icmp_packet.to_packet(), self.server_ip)));

        Ok(())
    }
}
