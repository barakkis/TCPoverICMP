
# TCP Over ICMP
TODO

## Examples
```bash 
# Server
python3 tunnel_server.py  --target-ip www.testingmcafeesites.com --target-port 80 --tunnel-ip 127.0.0.1

# Client
curl http://127.0.0.1:8000/ -H 'Host: www.testingmcafeesites.com'
```

```bash 
# Server
python3 tunnel_server.py --target-ip google.com --target-port 443 --tunnel-ip 127.0.0.1 

# Client
curl -k https://127.0.0.1:8000/index.html -H 'Host: www.google.com'
```

```bash 
# Server
python3 tunnel_server.py  --target-ip test.rebex.net --target-port 21 --tunnel-ip 172.19.220.17

# Client
nc -C 127.0.0.1 8000
```