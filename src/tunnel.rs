use compio::{
    buf::bytes::Bytes,
    quic::{self, Connection},
    runtime,
};
use futures_channel::mpsc::{Receiver, Sender, channel};
use futures_util::{FutureExt, StreamExt, select};

pub trait Tunnel {
    fn sender(&mut self) -> &mut Sender<Bytes>;
    fn receiver(&mut self) -> &mut Receiver<Bytes>;
}

pub struct QuicTunnelBuilder {
    conn: Connection,
}

fn handle_incoming_datagram(
    result: Result<Bytes, quic::ConnectionError>,
    sender: &mut Sender<Bytes>,
) -> bool {
    match result {
        Ok(buf) => match sender.try_send(buf) {
            Ok(_) => true,
            Err(e) => {
                log::warn!("error sending data: {e}");
                false
            }
        },
        Err(e) => {
            log::warn!("error receiving data: {e}");
            false
        }
    }
}
fn handle_outgoing_datagram(buf: Option<Bytes>, conn: &Connection) -> bool {
    match buf {
        Some(buf) => {
            if let Err(e) = conn.send_datagram(buf) {
                log::warn!("error sending data: {e}");
            }
            true
        }
        None => {
            log::info!("sender dropped, stopping send task");
            false
        }
    }
}

impl QuicTunnelBuilder {
    pub fn build(self) -> QuicTunnel {
        let (tx, mut inner_rx) = channel::<Bytes>(1);
        let (mut inner_tx, rx) = channel::<Bytes>(1);
        let task = runtime::spawn(async move {
            let connection = self.conn;
            loop {
                select! {
                    res = connection.recv_datagram().fuse() => {
                        if !handle_incoming_datagram(res, &mut inner_tx) {
                            break;
                        }
                    }
                    buf = inner_rx.next().fuse() => {
                        if !handle_outgoing_datagram(buf, &connection) {
                            break;
                        }
                    }
                }
            }
        });
        QuicTunnel { tx, rx, task }
    }
}

pub struct QuicTunnel {
    tx: Sender<Bytes>,
    rx: Receiver<Bytes>,
    task: runtime::Task<Result<(), Box<dyn std::any::Any + Send>>>,
}

impl Tunnel for QuicTunnel {
    fn sender(&mut self) -> &mut Sender<Bytes> {
        &mut self.tx
    }

    fn receiver(&mut self) -> &mut Receiver<Bytes> {
        &mut self.rx
    }
}
