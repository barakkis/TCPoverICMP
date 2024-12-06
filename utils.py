"""
utils.py

Combined utility functions and class for managing ICMP packets, handling ICMP-based communication and creating/managing
sockets.

This module includes:
- ICMP packet creation and parsing.
- Utility functions for checksum calculation and packet handling.
- Creation of ICMP and TCP sockets.

Classes:
- ICMPPacket: Represents an ICMP packet, parsing its attributes from raw data.

Functions:
- calculate_checksum: Calculates checksums for ICMP packets.
- build_icmp_request: Builds an ICMP request packet with a specified payload and metadata.
- send_icmp: Sends ICMP packets over a given socket.
- create_icmp_socket: Creates a raw ICMP socket for network operations.
- create_tcp_server_socket: Creates a TCP server socket bound to a specific port.
"""

import socket
import struct
from typing import Tuple

# ICMP message types
ICMP_ECHO_REPLY = 0  # ICMP type for Echo Reply messages
ICMP_ECHO_REQUEST = 8  # ICMP type for Echo Request messages

# Constants
ICMP_PACKET_OFFSET = 20
ICMP_BUFFER_SIZE = 65565  # Maximum buffer size for ICMP packets
MIN_STARTING_SEQUENCE = 0  # Minimum sequence number for packets
MAX_STARTING_SEQUENCE = 200  # Maximum sequence number for packets
DATA_PACKET_ID = 1  # Identifier for data packets
ACK_PACKET_ID = 2  # Identifier for acknowledgment packets
SOCKET_REUSE = 1  # Value for SO_REUSEADDR to allow address reuse


class ICMPPacket:
    """
    Represents an ICMP packet, with methods to parse and access its attributes.
    """

    def __init__(self, icmp_data: bytes) -> None:
        """
        Parse ICMP packet data and initialize attributes.

        :param icmp_data: Raw bytes of the ICMP packet.
        """

        self.icmp_type, self.code, self.checksum, self.packet_id, self.sequence, self.local_ip, self.local_port, \
            self.remote_ip, self.remote_port = struct.unpack('!bbHHh4sH4sH', icmp_data[:20])
        self.payload: bytes = icmp_data[20:]


def calculate_checksum(packet: bytes) -> int:
    """
    Calculate the checksum for the given packet, used for error-checking in the ICMP protocol.

    :param packet: The byte sequence of the packet to calculate the checksum for.
    :return: The calculated checksum.
    """
    if len(packet) % 2 == 1:
        packet += b'\x00'  # Pad with a zero byte if the length is odd
    checksum = 0
    for i in range(0, len(packet), 2):
        part = packet[i] + (packet[i + 1] << 8)
        checksum += part
        checksum = (checksum & 0xffff) + (checksum >> 16)  # Handle overflow
    checksum = ~checksum & 0xffff  # Take one's complement
    return socket.htons(checksum)  # Convert to network byte order


def build_icmp_request(data: bytes, icmp_type: int, local_ip: str, local_port: int, remote_ip: str,
                       remote_port: int, packet_id: int, sequence: int) -> bytes:
    """
    Build an ICMP request packet with the specified parameters.

    :param data: The payload data for the ICMP packet.
    :param icmp_type: The type of ICMP packet (e.g., ICMP_ECHO_REQUEST).
    :param local_ip: Source IP address of the tunnel.
    :param local_port: Source port number of the tunnel.
    :param remote_ip: Destination IP address of the tunnel.
    :param remote_port: Destination port number of the tunnel.
    :param packet_id: The packet ID.
    :param sequence: The sequence number.
    :return: The constructed ICMP packet as raw bytes.
    """
    local_addr: bytes = struct.pack('!4sH', socket.inet_aton(local_ip), local_port)
    remote_addr: bytes = struct.pack('!4sH', socket.inet_aton(remote_ip), remote_port)
    payload: bytes = local_addr + remote_addr + data
    icmp_request: bytes = struct.pack('!bbHHh', icmp_type, 0, 0, packet_id, sequence) + payload
    checksum: int = calculate_checksum(icmp_request)
    icmp_request = struct.pack('!bbHHh', icmp_type, 0, checksum, packet_id, sequence) + payload
    return icmp_request


def send_icmp(icmp_sock: socket.socket, icmp_type: int, data: bytes, tunnel_address: Tuple[str, int], local_ip: str,
              local_port: int, remote_ip: str, remote_port: int, packet_id: int, sequence: int) -> None:
    """
    Send an ICMP packet with the given data as the payload.
    :param icmp_sock: Socket to send the ICMP packet through.
    :param icmp_type: The type of ICMP packet (e.g., ICMP_ECHO_REQUEST).
    :param data: Payload data to include in the ICMP packet.
    :param tunnel_address: Address of the tunnel server to send the packet to.
    :param local_ip: Source IP address of the tunnel.
    :param local_port: Source port number of the tunnel.
    :param remote_ip: Destination IP address of the tunnel.
    :param remote_port: Destination port number of the tunnel.
    :param packet_id: The packet ID.
    :param sequence: The sequence number.
    """
    icmp_request: bytes = build_icmp_request(data, icmp_type, local_ip, local_port, remote_ip, remote_port,
                                             packet_id, sequence)
    icmp_sock.sendto(icmp_request, tunnel_address)


def create_icmp_socket() -> socket.socket:
    """
    Create an ICMP socket for sending and receiving ICMP packets.

    :return: A raw ICMP socket.
    :raises RuntimeError: If the socket cannot be created due to a system-level error.
    """
    try:
        sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        return sock
    except socket.error as e:
        raise RuntimeError(f"Failed to create ICMP socket: {e}")


def create_tcp_server_socket(listen_port: int) -> socket.socket:
    """
    Create a TCP server socket that listens for incoming connections on the specified port.

    :param listen_port: int - The port number on which the server socket will listen (0–65535).
    :return: A configured TCP server socket.
    :raises ValueError: If the `listen_port` is out of the valid range (0–65535).
    :raises RuntimeError: If the socket cannot be created or bound due to a system-level error.
    """
    if not (0 <= listen_port <= 65535):
        raise ValueError(f"Invalid port number: {listen_port}. Must be between 0 and 65535.")

    try:
        sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, SOCKET_REUSE)
        sock.bind(("0.0.0.0", listen_port))
        return sock
    except socket.error as e:
        raise RuntimeError(f"Failed to create or bind TCP server socket on port {listen_port}: {e}")
