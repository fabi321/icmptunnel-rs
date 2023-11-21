use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender,
};
use std::time::Duration;

pub mod packages;

pub fn get_transport_channel() -> (TransportSender, TransportReceiver) {
    transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .expect("Error creating transport channel")
}

pub fn sequence_number_to_ids(sequence_number: u16) -> (u8, u8) {
    let [client_id, session_id] = sequence_number.to_be_bytes();
    (client_id, session_id)
}

pub fn ids_to_sequence_number(client_id: u8, session_id: u8) -> u16 {
    u16::from_be_bytes([client_id, session_id])
}

pub const TIMEOUT: Duration = Duration::from_secs(60 * 5);
pub const RECV_TIMEOUT: Duration = Duration::from_secs(1);
