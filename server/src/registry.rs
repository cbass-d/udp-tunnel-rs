use crate::errors::{NoAddressLeft, NoSuchClient};
use anyhow::Result;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    time::Instant,
};

#[derive(Debug, Clone)]
pub struct ClientConnection {
    pub sock_addr: SocketAddr,
    pub assigned_ip: Ipv4Addr,
    pub last_seen: Instant,
}

impl ClientConnection {
    pub fn update_last_seen(&mut self, instant: Instant) {
        self.last_seen = instant;
    }
}

pub struct ClientRegistry {
    pub clients: HashMap<SocketAddr, ClientConnection>,
    pub ip_to_sock: HashMap<Ipv4Addr, SocketAddr>,
    pub dead_connections: HashSet<ClientConnection>,
    pub address_pool: VecDeque<Ipv4Addr>,
}

impl ClientRegistry {
    pub fn new() -> Self {
        let addresses =
            ipnet::Ipv4AddrRange::new("10.0.0.2".parse().unwrap(), "10.0.0.10".parse().unwrap());
        Self {
            clients: HashMap::new(),
            ip_to_sock: HashMap::new(),
            dead_connections: HashSet::new(),
            address_pool: VecDeque::from_iter(addresses),
        }
    }

    pub fn add_client(&mut self, peer: SocketAddr) -> Result<()> {
        if let Some(address) = self.address_pool.pop_front() {
            println!("[+] Adding new peer {peer} to hashset with IP {address}");
            self.clients.insert(
                peer,
                ClientConnection {
                    sock_addr: peer,
                    assigned_ip: address,
                    last_seen: Instant::now(),
                },
            );
            self.ip_to_sock.insert(address, peer);
        } else {
            return Err(NoAddressLeft.into());
        }

        Ok(())
    }

    pub fn get_client(&self, peer: &SocketAddr) -> Option<ClientConnection> {
        self.clients.get(peer).cloned()
    }

    pub fn get_client_mut(&mut self, peer: &SocketAddr) -> Option<&mut ClientConnection> {
        self.clients.get_mut(peer)
    }

    pub fn get_all_clients(&self) -> Vec<ClientConnection> {
        self.clients.values().map(|client| client.clone()).collect()
    }

    pub fn get_route(&self, ip: &Ipv4Addr) -> Option<SocketAddr> {
        self.ip_to_sock.get(ip).cloned()
    }

    pub fn remove_client(&mut self, peer: SocketAddr) -> Result<()> {
        if let Some(client) = self.clients.get(&peer) {
            println!("[-] Removing {peer} from connections");
            let ip = client.assigned_ip;
            self.address_pool.push_front(ip);
            self.ip_to_sock.remove_entry(&ip);
        } else {
            return Err(NoSuchClient.into());
        }

        self.clients.remove_entry(&peer);
        Ok(())
    }

    pub fn update_last_seen(&mut self, peer: SocketAddr, instant: Instant) -> Result<()> {
        if let Some(client) = self.clients.get_mut(&peer) {
            client.update_last_seen(instant);
        } else {
            return Err(NoSuchClient.into());
        }
        Ok(())
    }
}
