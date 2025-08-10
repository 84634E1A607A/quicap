use compio::{buf::bytes::Bytes, quic::Connection};

trait Interface {
    async fn send(&self, buf: Bytes) -> Result<(), Box<dyn std::error::Error>>;
    async fn recv(&self) -> Result<Bytes, Box<dyn std::error::Error>>;
    async fn close(self) -> Result<(), Box<dyn std::any::Any + Send>>;
}

pub struct QuicTunnel {
    conn: Connection,
}

impl Interface for QuicTunnel {
    async fn recv(&self) -> Result<Bytes, Box<dyn std::error::Error>> {
        self.conn.recv_datagram().await.map_err(|e| e.into())
    }

    async fn send(&self, buf: Bytes) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.send_datagram(buf).map_err(|e| e.into())
    }

    async fn close(self) -> Result<(), Box<dyn std::any::Any + Send>> {
        Ok(())
    }
}
