# QUICAP - TUN Device Packet Capture Tool

A Rust-based TUN device implementation that captures and analyzes network packets with automatic ping injection capabilities.

## Features

- **TUN Interface Management**: Creates and configures TUN network interfaces
- **Packet Capture**: Captures and analyzes all packets sent to the TUN interface
- **Protocol Analysis**: Parses and displays information for IP, ICMP, TCP, and UDP packets
- **Automatic Ping Injection**: Injects ping packets to 172.30.12.5 for testing
- **Configurable Settings**: Command-line arguments for IP address, netmask, and interface name
- **Verbose Output**: Optional hex dump of captured packets

## Prerequisites

- Rust (latest stable version)
- Linux operating system
- Root privileges (for TUN interface creation)
- `ip` command available (usually part of iproute2 package)

## Installation

1. Clone or download the project
2. Build the project:
   ```bash
   cargo build --release
   ```

## Usage

**Important**: This tool requires root privileges to create TUN interfaces.

### Basic Usage

```bash
sudo ./target/release/quicap
```

This will create a TUN interface named `quicap0` with IP address `10.0.0.1/24`.

### Command Line Options

```bash
sudo ./target/release/quicap [OPTIONS]
```

**Options:**
- `-i, --ip <IP>`: TUN interface IP address (default: 10.0.0.1)
- `-n, --netmask <MASK>`: TUN interface netmask (default: 255.255.255.0)
- `--name <NAME>`: TUN interface name (default: quicap0)
- `-v, --verbose`: Enable verbose output with hex dumps
- `-h, --help`: Show help message

### Examples

1. **Custom IP address:**
   ```bash
   sudo ./target/release/quicap --ip 192.168.1.100
   ```

2. **Custom interface name with verbose output:**
   ```bash
   sudo ./target/release/quicap --name mytun0 --verbose
   ```

3. **Complete custom configuration:**
   ```bash
   sudo ./target/release/quicap --ip 172.16.0.1 --netmask 255.255.0.0 --name custom_tun --verbose
   ```

## Testing

Once the tool is running, you can test it by sending packets to the configured IP address:

1. **Ping the TUN interface:**
   ```bash
   ping 10.0.0.1  # (or your configured IP)
   ```

2. **Send TCP traffic:**
   ```bash
   telnet 10.0.0.1 80
   ```

3. **Send UDP traffic:**
   ```bash
   echo "test" | nc -u 10.0.0.1 1234
   ```

## Output Format

The tool displays captured packets in a structured format:

```
📦 IP Packet: 10.0.0.2 -> 10.0.0.1 (Protocol: 1, Version: 4, Length: 84)
   🏓 ICMP Echo Request (Ping) - Code: 0
```

With verbose mode enabled (`-v`), you'll also see hex dumps:

```
0000: 45 00 00 54 12 34 40 00 40 01 b8 7c 0a 00 00 02  |E..T.4@.@..|....|
0010: 0a 00 00 01 08 00 f7 fc 00 00 00 00 48 65 6c 6c  |............Hell|
...
```

## Protocol Support

- **IP (IPv4)**: Basic header parsing
- **ICMP**: Echo Request/Reply detection
- **TCP**: Port information and flag analysis (SYN, ACK, FIN, RST)
- **UDP**: Port and length information

## Automatic Features

- **Ping Injection**: Automatically injects a ping packet to 172.30.12.5 after startup (2-second delay)
- **Interface Configuration**: Automatically configures the TUN interface with the specified IP and brings it up

## Architecture

The project consists of three main modules:

1. **`args.rs`**: Command-line argument parsing and configuration management
2. **`tun_device.rs`**: TUN device creation, configuration, and packet processing
3. **`main.rs`**: Application entry point and coordination

## Troubleshooting

1. **Permission denied**: Make sure to run with `sudo`
2. **Interface already exists**: Try using a different interface name with `--name`
3. **IP command not found**: Install the `iproute2` package
4. **Build errors**: Ensure you have the latest stable Rust version

## Dependencies

- `tokio`: Async runtime
- `tokio-tun`: TUN interface creation and management
- `quiche`: QUIC protocol support (for future enhancements)

## Future Enhancements

- QUIC packet support
- Packet filtering capabilities
- Network traffic statistics
- Configuration file support
- IPv6 support
