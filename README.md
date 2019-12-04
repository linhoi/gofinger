# Goprinter
Goprinter is passive device fingerprint project written by go.  
It is under development.

## Introduce
The amid of device fingerprint is device identify.  There are many ways to get device fingerprint ,and my focus is to use the message spread in the 
network . Many delicious information are spread with the TCP/IP network, if you can 
find them, it may be great help to get a fingerprint. In my case, I will use the DHCP and HTTP packet to gain fingerprint.

# Install & Requirement
Build httpdump requires libpcap-dev and cgo enabled.
## libpcap
for ubuntu/debian:

```sh
sudo apt install libpcap-dev
```

for centos/redhat/fedora:

```sh
sudo yum install libpcap-devel
```

## Usage
Run command below , you can get the fundamental capacity of goprinter
```shell script
go run main/main.go
```
or run with argument
```shell script
go run main/main.go -i interfaceName -f filter
```

##