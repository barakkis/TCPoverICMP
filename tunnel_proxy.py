"""
tunnel_proxy.py

A proxy server that forwards data between TCP clients and a remote server using ICMP packets for tunneling.

This server uses the `select` mechanism to manage multiple connections concurrently. It supports:
- Receiving data from TCP clients and forwarding it via ICMP.
- Receiving ICMP packets and forwarding their payload to the appropriate TCP client.

Classes:
- ICMPTunnelProxy: Implements the proxy server functionality.

Functions:
- parse_arguments: Parses command-line arguments for proxy configuration.

Main Execution:
- Starts the ICMP Tunnel Proxy using provided or default arguments.
"""

import argparse
import socket
from typing import Tuple, Optional

import select

from icmp_utils import ICMP_ECHO_REQUEST, ICMPPacket, ICMP_ECHO_REPLY, ICMP_BUFFER_SIZE, \
    ACK_PACKET_ID, ICMP_PACKET_OFFSET
from tunnel_utils import ICMPTunnelEndpoint, Connection, PacketManager


class ICMPTunnelProxy(ICMPTunnelEndpoint):
    """
    A proxy server that forwards data between TCP clients and a remote server using ICMP packets for tunneling.
    """

    def __init__(self, buffer_size: int) -> None:
        """
        Initialize the ICMP tunnel proxy server with a specified buffer size.

        :param buffer_size: Size of the buffer for receiving data from sockets.
        """
        super().__init__(buffer_size, ICMP_ECHO_REPLY)

    def handle_tcp(self, sock) -> None:
        """
        Handle incoming TCP data, forwarding it through ICMP to the corresponding remote server.

        :param sock: The TCP socket associated with a specific client.
        """
        try:
            data = sock.recv(self.buffer_size)
            key = self.get_key_connection_by_tcp_socket(sock)
            if data:
                connection = self.connections[key]
                self.send_data_packet(data, connection, *key, *sock.getpeername())
            else:
                # Client disconnected
                print("Client disconnected")
                self.cleanup_connection(sock)

        except socket.error as e:
            print(f"Error handling TCP data: {e}")
            self.inputs.remove(sock)

    def handle_icmp(self, sock: socket.socket) -> None:
        """
        Handle incoming ICMP packets and forward the payload to the appropriate TCP client.

        :param sock: The ICMP socket listening for packets from the tunnel server.
        """
        try:
            data, sender_address = sock.recvfrom(ICMP_BUFFER_SIZE)
            icmp_data = data[ICMP_PACKET_OFFSET:]
            icmp_packet = ICMPPacket(icmp_data)

            if icmp_packet.icmp_type == ICMP_ECHO_REQUEST:
                print(f"Received ICMP packet")
                key: Tuple[str, int] = (socket.inet_ntoa(icmp_packet.local_ip), icmp_packet.local_port)
                if icmp_packet.packet_id == ACK_PACKET_ID:
                    if key not in self.connections.keys():
                        print(f"No TCP connection found for ICMP request to {key}")
                        return
                    # Handle acknowledgment
                    self.connections[key].packet_manager.handle_ack(icmp_packet.sequence)
                else:
                    # Send acknowledgment back to the sender
                    self.send_ack_packet(icmp_packet, icmp_data, sender_address)

                    if key not in self.connections.keys():
                        # Establish a new TCP connection if not already existing
                        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        client_socket.connect((socket.inet_ntoa(icmp_packet.remote_ip), icmp_packet.remote_port))
                        self.inputs.append(client_socket)
                        self.connections[key] = Connection(client_socket, icmp_packet.sequence, PacketManager(),
                                                           sender_address)
                    # Reorder packets and handle out-of-order delivery
                    self.connections[key].reorder_packets(icmp_packet)

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

    def cleanup_connection(self, sock: socket.socket) -> None:
        """
        Clean up a client connection, removing it from monitored inputs and closing the socket.

        :param sock: The client socket to clean up.
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
                    self.handle_icmp(sock)
                else:
                    self.handle_tcp(sock)
            self.resend_unacknowledged_packets()


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
