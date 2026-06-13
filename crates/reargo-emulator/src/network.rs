// GDB RSP network client: TCP connection management.


#[derive(Debug, Clone)]
pub struct GdbConnectionConfig {
    pub host: String,
    pub port: u16,
    pub timeout_ms: u64,
}

impl GdbConnectionConfig {
    pub fn localhost(port: u16) -> Self {
        Self { host: "127.0.0.1".into(), port, timeout_ms: 5000 }
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Default for GdbConnectionConfig {
    fn default() -> Self {
        Self::localhost(1234)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

pub struct GdbConnection {
    pub config: GdbConnectionConfig,
    pub state: ConnectionState,
    rx_buffer: Vec<u8>,
    tx_buffer: Vec<u8>,
}

impl GdbConnection {
    pub fn new(config: GdbConnectionConfig) -> Self {
        Self {
            config,
            state: ConnectionState::Disconnected,
            rx_buffer: Vec::with_capacity(4096),
            tx_buffer: Vec::with_capacity(4096),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    pub fn queue_send(&mut self, packet: &[u8]) {
        self.tx_buffer.extend_from_slice(packet);
    }

    pub fn pending_send(&self) -> &[u8] {
        &self.tx_buffer
    }

    pub fn clear_send_buffer(&mut self) {
        self.tx_buffer.clear();
    }

    pub fn receive_data(&mut self, data: &[u8]) {
        self.rx_buffer.extend_from_slice(data);
    }

    pub fn try_parse_response(&mut self) -> Option<String> {
        let start = self.rx_buffer.iter().position(|&b| b == b'$')?;
        let end = self.rx_buffer[start..].iter().position(|&b| b == b'#')?;
        if start + end + 3 > self.rx_buffer.len() {
            return None;
        }
        let response = String::from_utf8_lossy(&self.rx_buffer[start + 1..start + end]).to_string();
        self.rx_buffer.drain(..start + end + 3);
        Some(response)
    }
    pub fn connect(&mut self) -> Result<(), std::io::Error> {
        use std::net::TcpStream;
        use std::time::Duration;

        self.state = ConnectionState::Connecting;
        match TcpStream::connect_timeout(
            &self.config.address().parse().map_err(|_|
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid address"))?,
            Duration::from_millis(self.config.timeout_ms),
        ) {
            Ok(_stream) => {
                self.state = ConnectionState::Connected;
                Ok(())
            }
            Err(e) => {
                self.state = ConnectionState::Error;
                Err(e)
            }
        }
    }

    pub fn send_command(&mut self, command: &crate::debugger::GdbCommand) -> Result<(), std::io::Error> {
        if !self.is_connected() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "not connected"));
        }
        let encoded = command.encode();
        self.queue_send(&encoded);
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnected;
        self.rx_buffer.clear();
        self.tx_buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_config() {
        let config = GdbConnectionConfig::localhost(4444);
        assert_eq!(config.address(), "127.0.0.1:4444");
    }

    #[test]
    fn connection_state() {
        let conn = GdbConnection::new(GdbConnectionConfig::default());
        assert!(!conn.is_connected());
        assert_eq!(conn.state, ConnectionState::Disconnected);
    }

    #[test]
    fn send_receive() {
        let mut conn = GdbConnection::new(GdbConnectionConfig::default());
        conn.queue_send(b"$g#67");
        assert_eq!(conn.pending_send(), b"$g#67");
        conn.clear_send_buffer();
        assert!(conn.pending_send().is_empty());
    }

    #[test]
    fn parse_response() {
        let mut conn = GdbConnection::new(GdbConnectionConfig::default());
        conn.receive_data(b"+$OK#9a");
        let resp = conn.try_parse_response().unwrap();
        assert_eq!(resp, "OK");
    }
}
