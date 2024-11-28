
# TCP Over ICMP
TODO

# Installation
TODO

## Examples
```bash 
python3 tunnel_server.py  --target-ip www.testingmcafeesites.com --target-port 80 --tunnel-ip 127.0.0.1

curl http://127.0.0.1:8000/ --header 'Host: www.testingmcafeesites.com'
```

```bash 
python3 tunnel_server.py --target-ip google.com --target-port 443 --tunnel-ip 127.0.0.1 

curl -k https://127.0.0.1:8000/index.html --header 'Host: www.google.com'
```

```bash 
python3 tunnel_server.py  --target-ip test.rebex.net --target-port 21 --tunnel-ip 172.19.220.17

nc -C 127.0.0.1 8000
```