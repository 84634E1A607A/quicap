use std::{net::SocketAddr, sync::Arc};

use compio::{
    self,
    buf::bytes::{Bytes, BytesMut},
    runtime::{self, Task},
};
use dashmap::DashMap;

#[derive(PartialEq, Eq, Hash)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

type Peer = SocketAddr;
type Interface = (Peer, Direction);

use super::{QuicClient, QuicServer, QuicTunnel, Tap};

pub struct Switch {
    tap: Tap,
    server: Arc<QuicServer>,
    client: Arc<QuicClient>,
    arp: Arc<DashMap<Interface, QuicTunnel>>,
}

impl Switch {
    pub fn from(tap: Tap, server: QuicServer, client: QuicClient) -> Self {
        let server = Arc::new(server);
        let client = Arc::new(client);
        Self {
            tap,
            server,
            client,
            arp: Arc::new(DashMap::new()),
        }
    }

    async fn switch(&mut self) {
        let server = self.server.clone();
        let client = self.client.clone();
        let dashmap = self.arp.clone();
        todo!()
    }
}
