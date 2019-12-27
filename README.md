# Gofinger
Gofinger is passive device fingerprint project written by go.  
It is under development.

## Introduce
The amid of device fingerprint is device identify.  There are many ways to get device fingerprint ,and my focus is to use the message spread in the 
network . Many delicious information are spread with the TCP/IP network,if you can 
find them, it may be great help to get a fingerprint. In my case, I will use the DHCP and HTTP packet to gain fingerprint.

# Requirement
Build gofinger requires libpcap-dev and cgo enabled.
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

# OsScan
OsScan is a subproject of gofinger, the purpose of it is to guest the Operation System and Device Type of remote device.

## Requirement
To use OsScan , nmap should be installed first

for debiaan:
```shell script
rpm -vhU https://nmap.org/dist/nmap-7.80-1.x86_64.rpm
```

## Usage
```shell script
go run osScan/osscan.go -si [interfaceName] -h [host_name_of_mysql] -u [user_name_of_mysql] -p [password_of_user] -db [database_name]
```

## OutPut
The result of OsScan will be saved in mysql database. If you  set -db option when running osScan, data will be saved in database_name,with the table named "osscan".
 