# SCS Packet Capturer

Capture inbound outbound tcp packet counts

```sh
wget https://github.com/scs-solution/scs-packet-capturer/releases/download/0/scs-packet-capturer
chmod +x scs-packet-capturer
sudo nohup ./scs-packet-capturer &

or

sudo docker rm $(sudo docker ps -a -q -f ancestor=rollrat/scs-packet-capturer)
sudo docker rmi rollrat/scs-packet-capturer
sudo docker run --net=host rollrat/scs-packet-capturer:latest
```

```json
# GET: http://127.0.0.1:5000/check
{
  "inbound": {
    "x.x.150.94": 162,
    "x.x.82.49": 1,
    "x.x.131.49": 12,
    "x.x.18.205": 1,
    "x.x.19.205": 1,
    "x.x.5.92": 2,
    "x.x.125.177": 1,
    "x.x.125.185": 1,
    "x.x.125.186": 1,
    "x.x.125.189": 2,
    "x.x.125.227": 1,
    "x.x.125.233": 1,
    "x.x.125.244": 1,
    "x.x.1.114": 1,
    "x.x.165.8": 1,
    "x.x.36.84": 9,
    "x.x.73.153": 6,
    "x.x.73.157": 4,
    "x.x.73.54": 4,
    "x.x.73.57": 8,
    "x.x.190.17": 8,
    "x.x.94.183": 2,
    "x.x.201.234": 1,
    "x.x.175.190": 1,
    "x.x.125.124": 1,
    "x.x.105.130": 1,
    "x.x.24.155": 1,
    "x.x.24.2": 2,
    "x.x.24.50": 1,
    "x.x.31.156": 1,
    "x.x.58.164": 2,
    "x.x.189.39": 1,
    "x.x.208.179": 12,
    "x.x.200.102": 4,
    "x.x.200.110": 2,
    "x.x.253.99": 14,
    "x.x.254.54": 4,
    "x.x.66.167": 1,
    "x.x.27.85": 4,
    "x.x.212.197": 14,
    "x.x.206.38": 2,
    "x.x.87.3": 6,
    "x.x.18.8": 2,
    "x.x.193.80": 60,
    "x.x.197.237": 1,
    "x.x.197.34": 1,
    "x.x.62.130": 2,
    "x.x.82.155": 1,
    "x.x.16.106": 4,
    "x.x.163.204": 1,
    "x.x.209.178": 2,
    "x.x.209.210": 2,
    "x.x.209.214": 2,
    "x.x.94.99": 12,
    "x.x.197.133": 4,
    "x.x.197.154": 6,
    "x.x.61.23": 1,
    ...
  },
  "outbound": {
    "x.x.150.94": 118,
    "x.x.82.49": 1,
    "x.x.131.49": 14,
    "x.x.18.205": 1,
    "x.x.19.205": 1,
    "x.x.5.92": 1,
    "x.x.125.177": 1,
    "x.x.125.185": 1,
    "x.x.125.186": 1,
    "x.x.125.189": 2,
    "x.x.125.227": 1,
    "x.x.125.233": 1,
    "x.x.125.244": 1,
    "x.x.1.114": 1,
    "x.x.165.8": 1,
    "x.x.36.84": 9,
    "x.x.73.153": 3,
    "x.x.73.157": 2,
    "x.x.73.54": 2,
    "x.x.73.57": 4,
    "x.x.190.17": 5,
    "x.x.94.183": 1,
    "x.x.201.234": 1,
    "x.x.175.190": 1,
    "x.x.125.124": 1,
    "x.x.105.130": 1,
    "x.x.24.155": 1,
    "x.x.24.2": 1,
    "x.x.24.50": 1,
    "x.x.31.156": 1,
    "x.x.58.164": 1,
    "x.x.189.39": 1,
    "x.x.208.179": 14,
    "x.x.200.102": 2,
    "x.x.200.110": 1,
    "x.x.253.99": 7,
    "x.x.254.54": 3,
    "x.x.66.167": 1,
    "x.x.27.85": 2,
    "x.x.212.197": 13,
    "x.x.206.38": 1,
    "x.x.87.3": 3,
    "x.x.18.8": 1,
    "x.x.193.80": 56,
    "x.x.197.237": 1,
    "x.x.197.34": 1,
    "x.x.62.130": 1,
    "x.x.82.155": 1,
    "x.x.16.106": 2,
    "x.x.163.204": 1,
    "x.x.209.178": 1,
    "x.x.209.210": 1,
    "x.x.209.214": 1,
    "x.x.94.99": 15,
    "x.x.197.133": 2,
    "x.x.197.154": 3,
    "x.x.61.23": 1,
    ...
  }
}
```
