use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use pnet_packet::Packet;
use pnet_packet::icmp::IcmpCode;
use pnet_packet::icmp::IcmpTypes;
use pnet_packet::icmp::MutableIcmpPacket;
use pnet_packet::icmp::echo_request;
use pnet_packet::icmp::{self};
use pnet_packet::ip::IpNextHeaderProtocols::{self};
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::tcp::ipv4_checksum;

use types::{NetworkProtocol, PayloadProtocol};

pub mod types;

pub fn build_packet(
    network_proto: NetworkProtocol,
    payload_proto: PayloadProtocol,
    src: IpAddr,
    dst: IpAddr,
) -> Result<Vec<u8>> {
    match network_proto {
        NetworkProtocol::Ipv4 => {
            let src_v4 = match src {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => panic!("Expected ipv4 address got ipv6"),
            };
            let dst_v4 = match dst {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => panic!("Expected ipv4 address got ipv6"),
            };

            build_ipv4(&payload_proto, src_v4, dst_v4)
        }

        NetworkProtocol::Ipv6 => {
            let src_v6 = match src {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(_) => panic!("Expected ipv6 address got ipv4"),
            };
            let dst_v6 = match dst {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(_) => panic!("Expected ipv6 address got ipv4"),
            };

            build_ipv6(&payload_proto, src_v6, dst_v6)
        }
    }
}

pub fn build_ipv4(
    payload_proto: &PayloadProtocol,
    src: Ipv4Addr,
    dst: Ipv4Addr,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let mut total_len = 0;

    {
        let mut packet = MutableIpv4Packet::new(&mut buf[..]).unwrap();
        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_ttl(64);
        packet.set_source(src);
        packet.set_destination(dst);
        packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    }

    match payload_proto {
        PayloadProtocol::Icmp => {
            let icmp_start = 5 * 4;
            let icmp_buf = &mut buf[icmp_start..];

            let mut echo_packet = echo_request::MutableEchoRequestPacket::new(icmp_buf).unwrap();
            echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
            echo_packet.set_icmp_code(echo_request::IcmpCodes::NoCode);
            echo_packet.set_identifier(62);
            echo_packet.set_sequence_number(1);
            echo_packet.set_payload(b"test");

            // Compute checksum using generic ICMP packet
            let mut owned_packet = echo_packet.payload().to_owned();
            let icmp_generic = MutableIcmpPacket::new(&mut owned_packet).unwrap();
            let cksum = icmp::checksum(&icmp_generic.to_immutable());
            echo_packet.set_checksum(cksum);

            // Update IPv4 total length
            total_len = 20 + echo_packet.packet().len(); // header + ICMP
            let mut packet = MutableIpv4Packet::new(&mut buf[..]).unwrap();
            packet.set_total_length(total_len as u16);
            let ipv4_cksum = pnet_packet::ipv4::checksum(&packet.to_immutable());
            packet.set_checksum(ipv4_cksum);

            println!("packet: {:?}", packet);
        }
        _ => {}
    }

    Ok(buf[0..total_len].to_owned())
}

pub fn build_ipv6(
    payload_proto: &PayloadProtocol,
    src: Ipv6Addr,
    dst: Ipv6Addr,
) -> Result<Vec<u8>> {
    let mut buf = vec![0; 4096];
    let packet = MutableIpv4Packet::new(&mut buf).unwrap();

    Ok(buf)
}
