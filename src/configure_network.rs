use crate::constants::MAX_PAYLOAD_SIZE;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::process::Command;

fn write_proc(path: &str, content: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.write_all(content)?;
    Ok(())
}

pub fn configure_server_network() -> io::Result<()> {
    Command::new("ifconfig")
        .args([
            "tun0",
            "mtu",
            &(MAX_PAYLOAD_SIZE - 4).to_string(),
            "up",
            "10.0.1.1",
            "netmask",
            "255.255.255.0",
        ])
        .output()?;
    write_proc("/proc/sys/net/ipv4/icmp_echo_ignore_all", b"1")?;
    write_proc("/proc/sys/net/ipv4/ip_forward", b"1")?;
    // iptables nat
    Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            "10.0.1.0/24",
            "-j",
            "MASQUERADE",
        ])
        .output()?;
    Ok(())
}

pub fn restore_server_network() -> io::Result<()> {
    write_proc("/proc/sys/net/ipv4/icmp_echo_ignore_all", b"0")?;
    Ok(())
}

pub fn get_gateway_interface() -> io::Result<(String, String)> {
    let routing_info = Command::new("route").arg("-n").output()?;
    let str_stdout = String::from_utf8_lossy(&routing_info.stdout);
    for line in str_stdout.lines() {
        if line.starts_with("0.0.0.0") {
            let columns = line
                .split(" ")
                .filter(|s| !s.is_empty())
                .collect::<Vec<&str>>();
            let gateway = columns[1];
            let interface = columns[columns.len() - 1];
            return Ok((gateway.to_string(), interface.to_string()));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No default route found",
    ))
}

pub fn configure_client_network(server: IpAddr, client_id: u8) -> io::Result<()> {
    Command::new("ifconfig")
        .args([
            "tun0",
            "mtu",
            &(MAX_PAYLOAD_SIZE - 4).to_string(),
            "up",
            &format!("10.0.1.{client_id}"),
            "netmask",
            "255.255.255.0",
        ])
        .output()?;
    let (gateway, interface) = get_gateway_interface()?;
    Command::new("route")
        .args([
            "del", "-net", "0.0.0.0", "gw", &gateway, "netmask", "0.0.0.0", "dev", &interface,
        ])
        .output()?;
    Command::new("route")
        .args([
            "add",
            "-host",
            &server.to_string(),
            "gw",
            &gateway,
            "dev",
            &interface,
        ])
        .output()?;
    Command::new("route")
        .args(["add", "default", "gw", "10.0.1.1", "tun0"])
        .output()?;
    Ok(())
}

pub fn restore_client_network(gateway: String, interface: String) -> io::Result<()> {
    Command::new("route")
        .args(["add", "default", "gw", &gateway, "dev", &interface])
        .output()?;
    Ok(())
}
