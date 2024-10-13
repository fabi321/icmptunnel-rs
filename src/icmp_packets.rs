use crate::constants::ICMP_HEADER_LEN;
use pnet::packet::icmp::destination_unreachable::{IcmpCodes, MutableDestinationUnreachablePacket};
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::checksum;

pub struct IcmpReply {
    packet: MutableEchoReplyPacket<'static>,
}

impl IcmpReply {
    pub fn new(payload_size: usize) -> IcmpReply {
        let reply_buffer = vec![0u8; ICMP_HEADER_LEN + payload_size];
        // Fails if size is too small, but size is ensured by adding header length above
        let mut packet = MutableEchoReplyPacket::owned(reply_buffer).unwrap();

        // Set the ICMP type to Echo Reply
        packet.set_icmp_type(IcmpTypes::EchoReply);

        IcmpReply { packet }
    }

    pub fn set_sequence_number(&mut self, sequence_number: u16) {
        self.packet.set_sequence_number(sequence_number)
    }

    pub fn set_identifier(&mut self, identifier: u16) {
        self.packet.set_identifier(identifier)
    }

    pub fn set_payload(&mut self, values: &[u8]) {
        self.packet.set_payload(values)
    }

    pub fn to_packet(mut self) -> IcmpPacket<'static> {
        self.packet.set_checksum(checksum(self.packet.packet(), 1));
        let vec = Vec::from(self.packet.packet());
        IcmpPacket::owned(vec).unwrap()
    }
}

pub struct IcmpRequest {
    packet: MutableEchoRequestPacket<'static>,
}

impl IcmpRequest {
    pub fn new(payload_size: usize) -> IcmpRequest {
        let request_buffer = vec![0u8; ICMP_HEADER_LEN + payload_size];
        // Fails if size is too small, but size is ensured by adding header length above
        let mut packet = MutableEchoRequestPacket::owned(request_buffer).unwrap();

        // Set the ICMP type to Echo Reply
        packet.set_icmp_type(IcmpTypes::EchoRequest);

        IcmpRequest { packet }
    }

    pub fn set_sequence_number(&mut self, sequence_number: u16) {
        self.packet.set_sequence_number(sequence_number)
    }

    pub fn set_identifier(&mut self, identifier: u16) {
        self.packet.set_identifier(identifier)
    }

    pub fn set_payload(&mut self, values: &[u8]) {
        self.packet.set_payload(values)
    }

    pub fn to_packet(mut self) -> IcmpPacket<'static> {
        self.packet.set_checksum(checksum(self.packet.packet(), 1));
        let vec = Vec::from(self.packet.packet());
        IcmpPacket::owned(vec).unwrap()
    }
}

pub struct IcmpTooBig {
    packet: MutableDestinationUnreachablePacket<'static>,
}

impl IcmpTooBig {
    pub fn new() -> IcmpTooBig {
        // 12 bytes icmp header, 20 bytes ipv4 header, 8 bytes data
        let reply_buffer = vec![0u8; 12 + 20 + 8];
        // Fails if size is too small, but size is ensured by adding header length above
        let mut packet = MutableDestinationUnreachablePacket::owned(reply_buffer).unwrap();

        // Set the ICMP type to Echo Reply
        packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        packet.set_icmp_code(IcmpCodes::FragmentationRequiredAndDFFlagSet);

        IcmpTooBig { packet }
    }

    pub fn set_ip_packet(&mut self, packet: Ipv4Packet) {
        // 20 bytes header + 8 bytes content
        self.set_raw(packet.packet())
    }

    pub fn set_raw(&mut self, packet: &[u8]) {
        self.packet.set_payload(&packet[..28])
    }

    pub fn set_next_hop_max_mtu(&mut self, mtu: u16) {
        self.packet.set_unused(mtu);
    }

    pub fn to_packet(mut self) -> IcmpPacket<'static> {
        self.packet.set_checksum(checksum(self.packet.packet(), 1));
        let vec = Vec::from(self.packet.packet());
        IcmpPacket::owned(vec).unwrap()
    }
}
