netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=22 connectaddress=172.25.197.237 connectport=22
netsh advfirewall firewall add rule name="Open Port 22 for WSL2" dir=in action=allow protocol=TCP localport=22