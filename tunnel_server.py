"""
tunnel_server.py

An ICMP Tunnel Server that forwards TCP client data over ICMP to a remote target server.

This server uses the `select` mechanism to handle multiple connections concurrently. It supports:
- Accepting new TCP client connections.
- Forwarding data from TCP clients over ICMP.
- Handling ICMP packets and forwarding them back to the appropriate TCP client.

Classes:
- Connection: Represents a single ICMP tunnel client connection.
- ICMPTunnelServer: Implements the ICMP tunneling server functionality.

Functions:
- parse_arguments: Parses command-line arguments for server configuration.

Main Execution:
- Starts the ICMP Tunnel Server using provided or default arguments.
"""

import argparse
import socket
from typing import Tuple, Dict

import select

from utils import ICMP_ECHO_REPLY, ICMPPacket, ICMP_ECHO_REQUEST, ICMP_BUFFER_SIZE, \
    ACK_PACKET_ID, send_icmp, DATA_PACKET_ID, STARTING_SEQUENCE, PacketManager, build_icmp_request, \
    create_tcp_server_socket, create_icmp_socket


class Connection:
    """
    Represents a ICMP tunnel client connection, including its state and packet management.
    """

    def __init__(self, tcp_sock: socket.socket, sequence: int, expected_seq: int,
                 packet_manager: PacketManager) -> None:
        """
        Initialize a new Connection instance.

        :param tcp_sock: The socket for the client connection.
        :param sequence: The current sequence number for outgoing packets.
        :param expected_seq: The next expected sequence number for incoming packets.
        :param packet_manager: A PacketManager instance for tracking and retransmitting packets.
        """
        self.tcp_sock: socket.socket = tcp_sock
        self.sequence: int = sequence
        self.expected_seq: int = expected_seq
        self.packet_manager: PacketManager = packet_manager
        self.reorder_buffer: Dict[int, bytes] = {}


class ICMPTunnelServer:
    """
    ICMP Tunnel Server that forwards TCP client data over ICMP to a remote target server.
    """

    def __init__(self, target_ip: str, target_port: int, tunnel_ip: str, listen_port: int, buffer_size: int) -> None:
        """
        Initialize the tunnel server.

        :param target_ip: The IP address of the target server.
        :param target_port: The port of the target server.
        :param tunnel_ip: The IP address to use for tunneling.
        :param listen_port: Port for listening for incoming TCP connections.
        :param buffer_size: The buffer size for receiving data from sockets.
        """
        self.target_ip: str = socket.gethostbyname(target_ip)
        self.target_port: int = target_port
        self.tunnel_address: Tuple[str, int] = (tunnel_ip, 0)
        self.buffer_size: int = buffer_size

        # Set up ICMP and TCP sockets
        self.icmp_sock: socket.socket = create_icmp_socket()
        self.tcp_sock: socket.socket = create_tcp_server_socket(listen_port)
        self.tcp_sock.listen(5)

        self.inputs: list[socket.socket] = [self.icmp_sock, self.tcp_sock]
        self.connections: Dict[Tuple[str, int], Connection] = {}

    def handle_icmp(self, sock: socket.socket) -> None:
        """
        Handle incoming ICMP packet and forward its payload to the appropriate TCP client.

        :param sock: The ICMP socket.
        """
        try:
            data, sender_address = sock.recvfrom(ICMP_BUFFER_SIZE)
            icmp_packet = ICMPPacket(data[20:])

            if icmp_packet.icmp_type == ICMP_ECHO_REPLY:
                print("Received ICMP packet")
                key = (socket.inet_ntoa(icmp_packet.local_ip), icmp_packet.local_port)
                if key not in self.connections.keys():
                    print(f"No TCP connection found for ICMP reply to {key}")
                    return
                if icmp_packet.packet_id == ACK_PACKET_ID:
                    # Handle acknowledgment
                    self.connections[key].packet_manager.handle_ack(icmp_packet.sequence)
                else:
                    # Send acknowledgment back to the sender
                    send_icmp(self.icmp_sock, ICMP_ECHO_REQUEST, b'', sender_address,
                              socket.inet_ntoa(icmp_packet.local_ip), icmp_packet.local_port,
                              socket.inet_ntoa(icmp_packet.remote_ip), icmp_packet.remote_port, ACK_PACKET_ID,
                              icmp_packet.sequence)
                    print(icmp_packet.payload)
                    connection = self.connections[key]
                    # Handle packet reordering
                    if icmp_packet.sequence == connection.expected_seq:
                        connection.tcp_sock.send(icmp_packet.payload)
                        connection.expected_seq += 1

                        while connection.expected_seq in connection.reorder_buffer:
                            connection.tcp_sock.send(
                                connection.reorder_buffer.pop(connection.expected_seq))
                            connection.expected_seq += 1
                    else:
                        connection.reorder_buffer[icmp_packet.sequence] = icmp_packet.payload
                        print(f"Packet {icmp_packet.sequence} buffered (waiting for "
                              f"{connection.expected_seq})")

        except socket.error as e:
            print(f"Error handling ICMP packet: {e}")

    def handle_tcp_from_client(self, sock: socket.socket) -> None:
        """
        Handle incoming TCP data from a client and forward it over ICMP.

        :param sock: The client TCP socket.
        """
        try:
            data = sock.recv(self.buffer_size)
            if data:
                packet = build_icmp_request(data, ICMP_ECHO_REQUEST, *sock.getpeername(), self.target_ip,
                                            self.target_port, DATA_PACKET_ID,
                                            self.connections[sock.getpeername()].sequence)
                self.connections[sock.getpeername()].packet_manager.track_packet(
                    self.connections[sock.getpeername()].sequence, packet)
                self.icmp_sock.sendto(packet, self.tunnel_address)
                print(f"Packet {self.connections[sock.getpeername()].sequence} sent")
                self.connections[sock.getpeername()].sequence += 1
            else:
                # Client disconnected
                print("Client disconnected")
                self.cleanup_connection(sock)

        except socket.error as e:
            print(f"Error handling TCP data: {e}")
            self.inputs.remove(sock)

    def handle_new_client(self, sock: socket.socket) -> None:
        """
        Accept a new client connection and add it to the monitoring list.

        :param sock: The TCP socket listening for new connections.
        """
        client_socket, client_address = sock.accept()
        print(f"New connection from {client_address}")
        self.inputs.append(client_socket)
        self.connections[client_address] = Connection(client_socket, STARTING_SEQUENCE,
                                                      STARTING_SEQUENCE, PacketManager())

    def cleanup_connection(self, sock: socket.socket) -> None:
        """
        Clean up a client connection, removing it from monitored inputs and closing the socket.

        :param sock: The client socket to clean up.
        """
        client_address = sock.getpeername()
        sock.close()
        if sock in self.inputs:
            self.inputs.remove(sock)
        if client_address in self.connections:
            del self.connections[client_address]
        print(f"Closed connection from {client_address}")

    def start_server(self) -> None:
        """
        Start the server, using select to monitor incoming ICMP and TCP data.
        """
        print("Starting Tunnel Server...")

        while True:
            readable, _, _ = select.select(self.inputs, [], [], 0.5)
            for sock in readable:
                if sock is self.tcp_sock:
                    self.handle_new_client(sock)
                elif sock is self.icmp_sock:
                    self.handle_icmp(sock)
                else:
                    self.handle_tcp_from_client(sock)
            for connection in self.connections.values():
                connection.packet_manager.resend_unacknowledged_packets(self.icmp_sock.sendto, self.tunnel_address)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments to configure the tunnel server.

    :return: Parsed arguments as an argparse.Namespace object.
    """
    parser = argparse.ArgumentParser(description="ICMP Tunnel Server")
    parser.add_argument("--target-ip", type=str, required=True, help="The IP address of the target server.")
    parser.add_argument("--target-port", type=int, required=True, help="The port of the target server.")
    parser.add_argument("--tunnel-ip", type=str, required=True, help="The IP address for tunneling.")
    parser.add_argument("--listen-port", type=int, default=8000,
                        help="Port to listen for TCP connections (default: 8000).")
    parser.add_argument("--buffer-size", type=int, default=1024,
                        help="Buffer size for tcp operations (default: 1024).")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    server = ICMPTunnelServer(args.target_ip, args.target_port, args.tunnel_ip, args.listen_port, args.buffer_size)
    server.start_server()
