import socket
import time
from abc import ABC, abstractmethod
from typing import Tuple, Dict

from icmp_utils import create_icmp_socket, build_icmp_request, calculate_checksum, send_icmp, DATA_PACKET_ID, \
    ACK_PACKET_ID


class PacketManager:
    """
    Manages ICMP packets for acknowledgment and retransmission.
    Tracks unacknowledged packets and handles their retransmission based on a timeout.
    """

    def __init__(self, ack_timeout: int = 2, max_retries: int = 3) -> None:
        """
        Initialize the PacketManager.

        :param ack_timeout: Timeout (in seconds) before retransmitting unacknowledged packets.
        :param max_retries: Maximum number of retransmission attempts.
        """
        self.pending_packets: Dict[int, Dict[str, float | bytes | int]] = {}  # Tracks unacknowledged packets
        self.acknowledged_packets: set[int] = set()  # Tracks acknowledged sequence numbers
        self.ack_timeout: int = ack_timeout
        self.max_retries: int = max_retries

    def track_packet(self, seq_number: int, packet: bytes) -> None:
        """
        Add a packet to the pending list for tracking.

        :param seq_number: Sequence number of the packet.
        :param packet: The ICMP packet to track.
        """
        self.pending_packets[seq_number] = {
            "packet": packet,
            "timestamp": time.time(),
            "retries": 0
        }

    def handle_ack(self, seq_number: int) -> None:
        """
        Mark a packet as acknowledged and remove it from the pending list.

        :param seq_number: Sequence number of the acknowledged packet.
        """
        if seq_number in self.pending_packets:
            del self.pending_packets[seq_number]
            self.acknowledged_packets.add(seq_number)
            print(f"ACK received for packet {seq_number}")

    def resend_unacknowledged_packets(self, send_function, address: Tuple[str, int]) -> None:
        """
        Resend packets that haven't been acknowledged within the timeout period.

        :param send_function: Function to send a packet (e.g., `self.icmp_sock.sendto`).
        :param address: Destination address to send the packets to.
        """
        current_time = time.time()
        for seq_number, packet_info in list(self.pending_packets.items()):
            if current_time - packet_info["timestamp"] > self.ack_timeout:
                if packet_info["retries"] < self.max_retries:
                    send_function(packet_info["packet"], address)
                    self.pending_packets[seq_number]["timestamp"] = current_time
                    self.pending_packets[seq_number]["retries"] += 1
                    print(f"Packet {seq_number} retransmitted. Retry #{packet_info['retries']}")
                else:
                    print(f"Packet {seq_number} dropped after {self.max_retries} retries")
                    del self.pending_packets[seq_number]


class Connection:
    """
    Represents a ICMP tunnel client connection, including its state and packet management.
    """

    def __init__(self, tcp_sock: socket.socket, sequence: int, packet_manager: PacketManager,
                 icmp_address: Tuple[str, int]) -> None:
        """
        Initialize a new Connection instance.

        :param tcp_sock: The socket for the client connection.
        :param sequence: The current sequence number for outgoing packets and the next expected sequence number for
        incoming packets.
        :param packet_manager: A PacketManager instance for tracking and retransmitting packets.
        :param icmp_address: The address of the ICMP connection.
        """
        self.tcp_sock: socket.socket = tcp_sock
        self.sequence: int = sequence
        self.expected_seq: int = sequence
        self.packet_manager: PacketManager = packet_manager
        self.reorder_buffer: Dict[int, bytes] = {}
        self.icmp_address: Tuple[str, int] = icmp_address

    def reorder_packets(self, icmp_packet):
        if icmp_packet.sequence == self.expected_seq:
            self.tcp_sock.send(icmp_packet.payload)
            self.expected_seq += 1

            while self.expected_seq in self.reorder_buffer:
                self.tcp_sock.send(
                    self.reorder_buffer.pop(self.expected_seq))
                self.expected_seq += 1
        else:
            self.reorder_buffer[icmp_packet.sequence] = icmp_packet.payload
            print(f"Packet {icmp_packet.sequence} buffered (waiting for "
                  f"{self.expected_seq})")


class ICMPTunnelEndpoint(ABC):

    def __init__(self, buffer_size: int, icmp_type: int) -> None:
        self.buffer_size: int = buffer_size
        self.icmp_type: int = icmp_type
        self.icmp_sock: socket.socket = create_icmp_socket()

        self.inputs: list[socket.socket] = [self.icmp_sock]  # List of sockets to monitor for incoming data
        self.connections: Dict[Tuple[str, int], Connection] = {}

    @abstractmethod
    def handle_tcp(self, sock: socket.socket) -> None:
        pass

    @abstractmethod
    def handle_icmp(self, sock: socket.socket) -> None:
        pass

    @abstractmethod
    def start_server(self) -> None:
        pass

    def send_data_packet(self, data: bytes, connection: Connection, local_ip: str, local_port: int, remote_ip: str,
                         remote_port: int):
        packet = build_icmp_request(data, self.icmp_type, local_ip, local_port, remote_ip, remote_port, DATA_PACKET_ID,
                                    connection.sequence)
        connection.packet_manager.track_packet(connection.sequence, packet)
        self.icmp_sock.sendto(packet, connection.icmp_address)
        print(f"Packet {connection.sequence} sent")
        connection.sequence += 1

    def send_ack_packet(self, icmp_packet, icmp_data, sender_address):
        if calculate_checksum(icmp_data) == 0:
            send_icmp(self.icmp_sock, self.icmp_type, b'', sender_address,
                      socket.inet_ntoa(icmp_packet.local_ip), icmp_packet.local_port,
                      socket.inet_ntoa(icmp_packet.remote_ip), icmp_packet.remote_port, ACK_PACKET_ID,
                      icmp_packet.sequence)
        else:
            print(f"Error in Checksum to {icmp_packet.sequence} packet, drop it")
            return

    def resend_unacknowledged_packets(self):
        for connection in self.connections.values():
            connection.packet_manager.resend_unacknowledged_packets(self.icmp_sock.sendto, connection.icmp_address)
