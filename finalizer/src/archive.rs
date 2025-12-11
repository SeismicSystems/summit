use std::{
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
};

use commonware_codec::Encode as _;
use summit_types::checkpoint::Checkpoint;
use tracing::info;

const ENCLAVE_SOCKET_PATH: &str = "/tmp/reth_enclave_socket.ipc";

pub(crate) fn backup_with_enclave(epoch: u64, checkpoint: Checkpoint) -> std::io::Result<()> {
    info!("Starting backup procedure with enclave for epoch {epoch}");
    // Connect to socket
    let mut stream = UnixStream::connect(ENCLAVE_SOCKET_PATH)?;

    info!("Connected to enclave unix socket");
    // Send epoch that is being backed up
    stream.write_all(&epoch.to_le_bytes())?;
    info!("Sent current epoch to enclave, waiting for ack");
    // wait for ack
    wait_for_ack(&mut stream)?;
    // send checkpoint length
    let checkpoint_bytes = checkpoint.encode();

    let len = checkpoint_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes())?;

    // send rest of data
    stream.write_all(&checkpoint_bytes)?;
    // block until final ack
    wait_for_ack(&mut stream)?;

    Ok(())
}

fn wait_for_ack(stream: &mut UnixStream) -> std::io::Result<()> {
    let mut buffer = [0; 3];
    stream.read_exact(&mut buffer)?;

    if &buffer == b"ACK" {
        println!("Received ACK");
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected ACK but got something else",
        ))
    }
}
