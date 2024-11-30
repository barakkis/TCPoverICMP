"""
tunnel_proxy.py

A proxy server that forwards data between TCP clients and a remote server using ICMP packets for tunneling.

This server uses the `select` mechanism to manage multiple connections concurrently. It supports:
- Receiving data from TCP clients and forwarding it via ICMP.
- Receiving ICMP packets and forwarding their payload to the appropriate TCP client.

Classes:
- Connection: Represents a single ICMP tunnel client connection.
- ICMPTunnelProxy: Implements the proxy server functionality.

Functions:
- parse_arguments: Parses command-line arguments for proxy configuration.

Main Execution:
- Starts the ICMP Tunnel Proxy using provided or default arguments.
"""

import argparse
import socket
from typing import Tuple, Dict, Optional
import select
from utils import ICMP_ECHO_REQUEST, ICMPPacket, build_icmp_request, ICMP_ECHO_REPLY, ICMP_BUFFER_SIZE, \
    ACK_PACKET_ID, send_icmp, DATA_PACKET_ID, PacketManager, create_icmp_socket, calculate_checksum


class Connection:
    """
    Represents a single ICMP tunnel client connection.
    """

    def __init__(self, tcp_sock: socket.socket, sequence: int, expected_seq: int, packet_manager: PacketManager,
                 icmp_address: Tuple[str, int]) -> None:
        """
        Initialize a new Connection instance.

        :param tcp_sock: The socket for the client connection.
        :param sequence: The current sequence number for outgoing packets.
        :param expected_seq: The next expected sequence number for incoming packets.
        :param packet_manager: A PacketManager instance for managing ICMP packets.
        :param icmp_address: The address of the ICMP connection.
        """
        self.tcp_sock: socket.socket = tcp_sock
        self.sequence: int = sequence
        self.expected_seq: int = expected_seq
        self.packet_manager: PacketManager = packet_manager
        self.reorder_buffer: Dict[int, bytes] = {}
        self.icmp_address: Tuple[str, int] = icmp_address


class ICMPTunnelProxy:
    """
    A proxy server that forwards data between TCP clients and a remote server using ICMP packets for tunneling.
    """

    def __init__(self, buffer_size: int) -> None:
        """
        Initialize the ICMP tunnel proxy server with a specified buffer size.

        :param buffer_size: Size of the buffer for receiving data from sockets.
        """
        self.buffer_size: int = buffer_size
        self.icmp_sock: socket.socket = create_icmp_socket()

        self.inputs: list[socket.socket] = [self.icmp_sock]  # List of sockets to monitor for incoming data
        self.connections: Dict[Tuple[str, int], Connection] = {}

    def handle_tcp(self, sock: socket.socket) -> None:
        """
        Handle incoming TCP data, forwarding it through ICMP to the corresponding remote server.

        :param sock: The TCP socket associated with a specific client.
        """
        try:
            data: bytes = sock.recv(self.buffer_size)
            key = self.get_key_connection_by_tcp_socket(sock)
            if data:
                connection = self.connections[key]
                # Build an ICMP packet with the received TCP data
                packet = build_icmp_request(data, ICMP_ECHO_REPLY, *key, *sock.getpeername(), DATA_PACKET_ID,
                                            connection.sequence)

                connection.packet_manager.track_packet(connection.sequence, packet)
                self.icmp_sock.sendto(packet, connection.icmp_address)
                print(f"Packet {connection.sequence} sent")
                connection.sequence += 1
            else:
                # Client disconnected
                print(f"Client disconnected: {sock.getsockname()}")
                self.inputs.remove(sock)
                del self.connections[key]
        except socket.error as e:
            print(f"Error handling TCP data: {e}")
            self.cleanup_socket(sock)

    def handle_icmp(self, sock: socket.socket) -> None:
        """
        Handle incoming ICMP packets and forward the payload to the appropriate TCP client.

        :param sock: The ICMP socket listening for packets from the tunnel server.
        """
        try:
            data, sender_address = sock.recvfrom(ICMP_BUFFER_SIZE)
            icmp_data = data[20:]
            icmp_packet = ICMPPacket(icmp_data)

            if icmp_packet.icmp_type == ICMP_ECHO_REQUEST:
                print(f"Received ICMP packet from: {sender_address}")
                key: Tuple[str, int] = (socket.inet_ntoa(icmp_packet.local_ip), icmp_packet.local_port)
                if icmp_packet.packet_id == ACK_PACKET_ID:
                    if key not in self.connections.keys():
                        print(f"No TCP connection found for ICMP request to {key}")
                        return
                    # Handle acknowledgment
                    self.connections[key].packet_manager.handle_ack(icmp_packet.sequence)
                else:
                    # Send acknowledgment back to the sender
                    received_checksum = calculate_checksum(icmp_data)
                    if received_checksum == 0:
                        send_icmp(self.icmp_sock, ICMP_ECHO_REPLY, b'', sender_address,
                                  socket.inet_ntoa(icmp_packet.local_ip), icmp_packet.local_port,
                                  socket.inet_ntoa(icmp_packet.remote_ip), icmp_packet.remote_port, ACK_PACKET_ID,
                                  icmp_packet.sequence)
                    else:
                        print(f"Error in Checksum to {icmp_packet.sequence} packet, drop it")
                        return

                    if key not in self.connections.keys():
                        # Establish a new TCP connection if not already existing
                        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        client_socket.connect((socket.inet_ntoa(icmp_packet.remote_ip), icmp_packet.remote_port))
                        self.inputs.append(client_socket)
                        self.connections[key] = Connection(client_socket, icmp_packet.sequence, icmp_packet.sequence,
                                                           PacketManager(), sender_address)
                    # Reorder packets and handle out-of-order delivery
                    if icmp_packet.sequence == self.connections[key].expected_seq:
                        self.connections[key].tcp_sock.send(icmp_packet.payload)
                        self.connections[key].expected_seq += 1
                        while self.connections[key].expected_seq in self.connections[key].reorder_buffer:
                            self.connections[key].tcp_sock.send(
                                self.connections[key].reorder_buffer.pop(self.connections[key].expected_seq))
                            self.connections[key].expected_seq += 1
                    else:
                        self.connections[key].reorder_buffer[icmp_packet.sequence] = icmp_packet.payload
                        print(f"Packet {icmp_packet.sequence} buffered (waiting for "
                              f"{self.connections[key].expected_seq})")

        except socket.error as e:
            print(f"Error handling ICMP data: {e}")

    def get_key_connection_by_tcp_socket(self, tcp_sock: socket.socket) -> Optional[Tuple[str, int]]:
        """
        Retrieve the key for a connection based on its TCP address.

        :param tcp_sock: The socket of the connection.
        :return: The connection key if found, otherwise None.
        """
        for key, connection in self.connections.items():
            if connection.tcp_sock == tcp_sock:
                return key
        return None

    def cleanup_socket(self, sock: socket.socket) -> None:
        """
        Clean up and close a socket, removing it from active lists and mappings.

        :param sock: The socket to close and remove.
        """
        sock.close()
        if sock in self.inputs:
            self.inputs.remove(sock)
        key = self.get_key_connection_by_tcp_socket(sock)
        if key is not None:
            del self.connections[key]

    def start_server(self) -> None:
        """
        Start the proxy server and use `select` to handle incoming data on ICMP and TCP sockets.
        """
        print("Starting Tunnel Proxy...")

        while True:
            readable, _, _ = select.select(self.inputs, [], [], 0.5)
            for sock in readable:
                if sock is self.icmp_sock:
                    # Handle incoming ICMP packet
                    self.handle_icmp(sock)
                else:
                    # Handle incoming TCP data
                    self.handle_tcp(sock)
            for connection in self.connections.values():
                connection.packet_manager.resend_unacknowledged_packets(self.icmp_sock.sendto, connection.icmp_address)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments to configure the tunnel proxy.

    :return: Parsed arguments as an argparse.Namespace object.
    """
    parser = argparse.ArgumentParser(description="ICMP Tunnel Proxy")
    parser.add_argument("--buffer-size", type=int, default=1024,
                        help="Buffer size for tcp operations (default: 1024).")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    server = ICMPTunnelProxy(args.buffer_size)
    server.start_server()
