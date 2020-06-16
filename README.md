
# NIST GoBGPsec 
GoBGPsec uses NIST SRxCrypto library to facilitate crypto calculations
which is able to sign and verify X.509 objects for BGPSec path validation. 


## Project Status

Active development




## Getting Started

You need a working Go Environment 

* go version > 1.13 
* protoc version == 3.7.1


### Prerequisites

Need to install SRxCryptoAPI library first. GoBGPsec requires to use this crypto library
for signing and validation when the BGPSec operation starts. <br>
Need SRxCryptoAPI library >= v3.0

Download NIST SRx software from the link below. 
```bash
git clone https://github.com/usnistgov/NIST-BGP-SRx.git
```

And then build with buildBGP-SRx.sh script.
It will install automatically all the packages.
```bash
./buildBGP-SRx.sh
```
or you might install individual modules, for example, only install SRxCryptoAPI library with
following command.
```
cd srx-crypto-api
./configure --prefix=<Dir/to/install> CFLAGS="-O0 -g"
```


### Build 
To import NIST SRxCryptoAPI library, need to specify the library location with a build or
install command. Otherwise LD_LIBRARY_PATH environment variable might be used.
```bash
LD_LIBRARY_PATH=/path/to/lib go build [source|./...]                    
go build ./...
```
Or 
```
go build -ldflags="-r /path/to/lib/go_srx_test" ./...
```


Avoiding the LD_LIBRARY_PATH for Shared Libs in Go (cgo) Applications   
```
export CGO_LDFLAGS="-L/path/to/lib -Wl,-rpath -Wl,/path/to/lib"
export CGO_CFLAGS="-I/path/to/include/"
go build ./...
```


### Install
Install binaries into $GOPATH/bin. Simply use 'install' instead of 'build' in commands
```
go install ./...
```
</br></br>


### BGPSec Configuration
 [GoBGPSec Configuration](docs/sources/bgpsec.md)
</br></br>

### Quick Functional Test / Demo
gobgpd server
```bash
# gobgpd -p -f /etc/gobgpd.conf --log-level=debug
INFO[0000] gobgpd started                               
INFO[0000] Finished reading the config file              Topic=Config
INFO[0000] key path set: /var/lib/bgpsec-keys/           Topic=bgpsec
DEBU[0000] + sca_SetKeyPath() return: 1                 
DEBU[0000] + Init call for srxcryptoapi ...             
DEBU[0000] + str: PUB:/var/lib/bgpsec-keys//ski-list.txt;PRIV:/var/lib/bgpsec-keys//priv-ski-list.txt 
+--------------------------------------------------------------+
| API: libBGPSec_OpenSSL.so                                    |
| WARNING: This API provides a reference implementation for    |
| BGPSec crypto processing. The key storage provided with this |
| API does not provide a 'secure' key storage which protects   |
| against malicious side attacks. Also it is not meant to be   |
| a FIBS certified key storage.                                |
| This API uses open source OpenSSL functions and checks, keys |
| for their correctness and once done, uses it repeatedly!     |
+--------------------------------------------------------------+
[SRxCryptoAPI - INFO] Extension for private key not set. Set 'der' as key-file extension!
[SRxCryptoAPI - INFO] Extension for public key (X509 cert) not set. Set 'cert' as cert-file extension!
[SRxCryptoAPI - INFO] The internal key initialized storage holds (11 private and 5 public keys)!
INFO[0000] Init() return: 1                             
INFO[0000] Peer 172.37.0.2 is added                     
INFO[0000] Add a peer configuration for:172.37.0.2       Topic=Peer
INFO[0000] Peer 172.37.0.4 is added                     
INFO[0000] Add a peer configuration for:172.37.0.4       Topic=Peer
DEBU[0000] IdleHoldTimer expired                         Duration=0 Key=172.37.0.2 Topic=Peer
DEBU[0000] IdleHoldTimer expired                         Duration=0 Key=172.37.0.4 Topic=Peer
DEBU[0000] state changed                                 Key=172.37.0.2 Topic=Peer new=BGP_FSM_ACTIVE old=BGP_FSM_IDLE reason=idle-hold-timer-expired
DEBU[0000] state changed                                 Key=172.37.0.4 Topic=Peer new=BGP_FSM_ACTIVE old=BGP_FSM_IDLE reason=idle-hold-timer-expired
DEBU[0005] try to connect                                Key=172.37.0.4 Topic=Peer
DEBU[0005] state changed                                 Key=172.37.0.4 Topic=Peer new=BGP_FSM_OPENSENT old=BGP_FSM_ACTIVE reason=new-connection
DEBU[0005] state changed                                 Key=172.37.0.4 Topic=Peer new=BGP_FSM_OPENCONFIRM old=BGP_FSM_OPENSENT reason=open-msg-received
INFO[0005] Peer Up                                       Key=172.37.0.4 State=BGP_FSM_OPENCONFIRM Topic=Peer
DEBU[0005] state changed                                 Key=172.37.0.4 Topic=Peer new=BGP_FSM_ESTABLISHED old=BGP_FSM_OPENCONFIRM reason=open-msg-negotiated
INFO[0006] newAsPaths from BGPSec update 60003          
INFO[0006] Validation called                             Topic=bgpsec
DEBU[0006] prefix:200.0.0.0/8  afi:1  safi:1             Topic=Bgpsec
DEBU[0006] received MP NLRI: true                       
DEBU[0006] bgpsec validation start
```

gobgp client
```bash
# gobgp global rib
Network              Next Hop             AS_PATH              Age        Attrs                                                    
N,V*>100.1.1.0/24    192.0.2.1            60001 60004          00:04:50   [{Origin: i} {Communities: 65001:666} {bgpsecs}]         
N,V*>200.0.0.0/8     172.37.0.4           60003                00:04:49   [{Origin: i} {Med: 0} {bgpsecs}]                         
N,V*>200.1.1.0/24    192.0.2.1            60001 60004          00:04:50   [{Origin: i} {Communities: 65002:667} {bgpsecs}]
```


</br></br>
</br></br>

## With Docker
**TBD**
</br></br>


## Authors & Main Contributors
Kyehwan Lee (kyehwanl@nist.gov)
</br></br>


## Contact
Kyehwan Lee (kyehwanl@nist.gov)
</br></br>



## Copyright

### DISCLAIMER
Gobgpsec was developed for applying BGPSec Routing software, NIST BGP-SRx
into GoBGP by employees of the Federal Government in the course of their 
official duties. NIST BGP-SRx is an open source BGPSec implementation for 
supporting RPKI and BGPSec protocol specification in RFC. 
Additional information can be found at [BGP Secure Routing Extension (BGP‑SRx) Prototype](https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype)


NIST assumes no responsibility whatsoever for its use by other parties,
and makes no guarantees, expressed or implied, about its quality,
reliability, or any other characteristic.

This software might use libraries that are under original license of
GoBGP or other licenses. Please refer to the licenses of all libraries 
required by this software.

