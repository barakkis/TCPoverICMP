
# TCP Over ICMP
TODO

# Requirements
* You need linux and python3. 
* Run the scripts in root.
* Disable ping reply in the two machines. (using sysctl.conf)
* Enjoy :)

## Examples
```bash 
# Server
python3 tunnel_server.py  --target-ip www.testingmcafeesites.com --target-port 80 --tunnel-ip PROXY_HOST

# Client
curl http://127.0.0.1:8000/ -H 'Host: www.testingmcafeesites.com'
```

```bash 
# Server
python3 tunnel_server.py --target-ip google.com --target-port 443 --tunnel-ip PROXY_HOST 

# Client
curl -k https://127.0.0.1:8000/index.html -H 'Host: www.google.com'
```

```bash 
# Server
python3 tunnel_server.py  --target-ip test.rebex.net --target-port 21 --tunnel-ip PROXY_HOST

# Client
nc -C 127.0.0.1 8000
```