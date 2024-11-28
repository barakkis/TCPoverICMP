"""
socket_utils.py

Utility functions for creating and managing sockets, including ICMP and TCP server sockets.

This module provides:
- Creation of ICMP sockets for raw packet communication.
- Creation of TCP server sockets with error handling and configuration.

Functions:
- create_icmp_socket: Creates a raw ICMP socket for network operations.
- create_tcp_server_socket: Creates a TCP server socket bound to a specific port.
"""

import socket

# Constants
SOCKET_REUSE: int = 1  # Value for SO_REUSEADDR to allow address reuse


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
