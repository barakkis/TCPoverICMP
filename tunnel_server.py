"""
tunnel_server.py

An ICMP Tunnel Server that forwards TCP client data over ICMP to a remote target server.

This server uses the `select` mechanism to handle multiple sessions concurrently. It supports:
- Accepting new TCP client sessions.
- Forwarding data from TCP clients over ICMP.
- Handling ICMP packets and forwarding them back to the appropriate TCP client.

Classes:
- ICMPTunnelServer: Implements the ICMP tunneling server functionality.

Functions:
- parse_arguments: Parses command-line arguments for server configuration.

Main Execution:
- Starts the ICMP Tunnel Server using provided or default arguments.
"""

import argparse
import random
import socket
from typing import Tuple

import select

from tunnel_shared import ICMPTunnelEndpoint, Session, PacketManager
from utils import ICMP_ECHO_REPLY, ICMPPacket, ICMP_ECHO_REQUEST, ICMP_BUFFER_SIZE, ACK_PACKET_ID, \
    MAX_STARTING_SEQUENCE, create_tcp_server_socket, MIN_STARTING_SEQUENCE, ICMP_PACKET_OFFSET, DATA_PACKET_ID


class ICMPTunnelServer(ICMPTunnelEndpoint):
    """
    ICMP Tunnel Server that forwards TCP client data over ICMP to a remote target server.
    """

    def __init__(self, target_ip: str, target_port: int, tunnel_ip: str, listen_port: int, buffer_size: int) -> None:
        """
        Initialize the tunnel server.

        :param target_ip: The IP address of the target server.
        :param target_port: The port of the target server.
        :param tunnel_ip: The IP address to use for tunneling.
        :param listen_port: Port for listening for incoming TCP sessions.
        :param buffer_size: The buffer size for receiving data from sockets.
        """
        super().__init__(buffer_size, ICMP_ECHO_REQUEST)
        self.target_ip: str = socket.gethostbyname(target_ip)
        self.target_port: int = target_port
        self.tunnel_address: Tuple[str, int] = (tunnel_ip, 0)

        # Sockets and session management
        self.tcp_sock: socket.socket = create_tcp_server_socket(listen_port)
        self.tcp_sock.listen(5)
        self.inputs.append(self.tcp_sock)

    def handle_tcp(self, sock: socket.socket) -> None:
        """
        Handle incoming TCP data from a client and forward it over ICMP.

        :param sock: The client TCP socket.
        """
        try:
            data = sock.recv(self.buffer_size)
            if data:
                session = self.sessions[sock.getpeername()]
                self.send_data_packet(data, session, *sock.getpeername(), self.target_ip, self.target_port)
            else:
                # Client disconnected
                print("Client disconnected")
                self.cleanup_session(sock)

        except socket.error as e:
            print(f"Error handling TCP data: {e}")
            self.inputs.remove(sock)

    def handle_icmp(self, sock: socket.socket) -> None:
        """
        Handle incoming ICMP packet and forward its payload to the appropriate TCP client.

        :param sock: The ICMP socket.
        """
        try:
            data, sender_address = sock.recvfrom(ICMP_BUFFER_SIZE)
            icmp_data = data[ICMP_PACKET_OFFSET:]
            icmp_packet = ICMPPacket(icmp_data)

            if icmp_packet.icmp_type == ICMP_ECHO_REPLY:
                print("Received ICMP packet")
                key = (socket.inet_ntoa(icmp_packet.local_ip), icmp_packet.local_port)
                if key not in self.sessions:
                    print(f"No TCP session found for ICMP reply to {key}")
                    return
                if icmp_packet.packet_id == ACK_PACKET_ID:
                    # Handle acknowledgment
                    self.sessions[key].packet_manager.handle_ack(icmp_packet.sequence)
                elif icmp_packet.packet_id == DATA_PACKET_ID:
                    # Send acknowledgment back to the sender
                    self.send_ack_packet(icmp_packet, icmp_data, sender_address)
                    print(icmp_packet.payload)
                    self.sessions[key].reorder_packets(icmp_packet)
        except socket.error as e:
            print(f"Error handling ICMP packet: {e}")

    def handle_new_client(self, sock: socket.socket) -> None:
        """
        Accept a new client session and add it to the monitoring list.

        :param sock: The TCP socket listening for new sessions.
        """
        client_socket, client_address = sock.accept()
        print(f"New session from {client_address}")
        self.inputs.append(client_socket)
        sequence = random.randint(MIN_STARTING_SEQUENCE, MAX_STARTING_SEQUENCE)
        self.sessions[client_address] = Session(client_socket, sequence, PacketManager(), self.tunnel_address)

    def cleanup_session(self, sock: socket.socket) -> None:
        """
        Clean up a client session, removing it from monitored inputs and closing the socket.

        :param sock: The client socket to clean up.
        """
        client_address = sock.getpeername()
        sock.close()
        if sock in self.inputs:
            self.inputs.remove(sock)
        if client_address in self.sessions:
            del self.sessions[client_address]

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
                    self.handle_tcp(sock)
            self.resend_unacknowledged_packets()


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
                        help="Port to listen for TCP sessions (default: 8000).")
    parser.add_argument("--buffer-size", type=int, default=1024,
                        help="Buffer size for tcp operations (default: 1024).")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    server = ICMPTunnelServer(args.target_ip, args.target_port, args.tunnel_ip, args.listen_port, args.buffer_size)
    server.start_server()
