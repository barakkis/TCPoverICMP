
# TCP Over ICMP

This project implements a TCP-over-ICMP tunneling solution. It allows TCP traffic to be forwarded between clients and servers using ICMP packets as the transport layer. This can be useful for situations where TCP traffic is restricted but ICMP is permitted.

The system consists of three main components:
1. **Tunnel Server**: Forwards TCP traffic from clients over ICMP packets to the proxy.
2. **Tunnel Proxy**: Acts as an intermediary, forwarding ICMP traffic to the final destination server and vice versa.
3. **Client**: Interacts with the server through the tunnel.

---

## Requirements

Before running the scripts, ensure the following:

- **Linux**: The system is tested on Linux, which supports raw sockets needed for ICMP operations.
- **Python 3.8 or above**: The scripts are written in Python 3 and require at least version 3.8 to run.
- **Root Access**: The scripts require root privileges to use raw sockets. Run them with `sudo`.
- **Disable Ping Reply**: Disable ICMP ping replies on both the server and proxy machines by modifying the `sysctl.conf` file:
  ```bash
  echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
  sysctl -p
  ```

---

## Usage Examples

### Example 1: HTTP 
```bash
python3 tunnel_server.py --target-ip www.testingmcafeesites.com --target-port 80 --tunnel-ip PROXY_HOST
```
#### Client
```bash
curl http://127.0.0.1:8000/ -H 'Host: www.testingmcafeesites.com'
```

### Example 2: HTTPS
```bash
python3 tunnel_server.py --target-ip google.com --target-port 443 --tunnel-ip PROXY_HOST
```
#### Client
```bash
curl -k https://127.0.0.1:8000/index.html -H 'Host: www.google.com'
```

### Example 3: FTP
#### Server
```bash
python3 tunnel_server.py --target-ip test.rebex.net --target-port 21 --tunnel-ip PROXY_HOST
```
#### Client
```bash
nc -C 127.0.0.1 8000
```

---

## Notes

- Replace `PROXY_HOST` with the IP address of your tunnel proxy.
- Ensure the tunnel proxy is running and reachable from both the client and server.
- Debug logs are printed to the console for troubleshooting. Redirect logs to a file if needed.

---

## Enjoy!

For questions or troubleshooting, feel free to contact the project contributors or raise an issue in the repository.
