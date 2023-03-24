
# NIST GoBGPsec 
GoBGPsec uses NIST SRxCrypto library to facilitate crypto calculations
which is able to sign and verify X.509 objects for BGPSec path validation. 
This software is based on [Gobgp](https://github.com/osrg/gobgp) BGP implementation and added codes for 
implementing BGPSec protocol ([RFC 8205](https://tools.ietf.org/html/rfc8205)).

This work is part of the larger [NIST Robust Inter Domain Routing Project](https://www.nist.gov/programs-projects/robust-inter-domain-routing) that addresses a wide range of security and resilience issues in the Internet’s routing infrastructure. The software in this repository is a component of a larger [suite of software tools](https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-software-suite) developed within the project.


## Project Status

Active development




## Getting Started

You need a working Go Environment 

* go version > 1.13 
* protoc version == 3.7.1


### Prerequisites
GoBGPsec requires to use this crypto library for signing and validation 
when the BGPSec operation starts.
* Need to install SRxCryptoAPI library first
* Need SRxCryptoAPI library >= v3.0

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
For more information such as key generation for signing and etc,
please refer to [NIST SRxCryptoAPI](https://github.com/usnistgov/NIST-BGP-SRx/tree/master/srx-crypto-api) page.


### Build 
To import NIST SRxCryptoAPI library, need to specify the library location with a build command with CGO environment variables  
for shared libraries in Go (cgo) Applications   
```
export CGO_LDFLAGS="-L/path/to/lib -Wl,-rpath -Wl,/path/to/lib"
export CGO_CFLAGS="-I/path/to/include/"
go build ./...
```


### Install
Install binaries into $GOPATH/bin. Simply use 'install' instead of 'build' in commands (CGO env variable must be set)
```
go install ./...
```
</br></br>


### BGPSec Configuration
 [GoBGPsec Configuration](docs/sources/bgpsec.md)
</br></br>

### Quick Functional Test / Demo
#### gobgpd server
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
DEBU[0006] prefix : &server._Ctype_struct___2{afi:0x100, safi:0x1, length:0x8, addr:[16]uint8{0xc8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}} 
DEBU[0006] valData.nlri : server._Ctype_struct___2{afi:0x100, safi:0x1, length:0x8, addr:[16]uint8{0xc8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}} 
[SRxCryptoAPI - DEBUG]
Hash(validate):
00 00 ea 62 01 00 00 00 ea 63 01 00 01 01 08 c8                     
[SRxCryptoAPI - DEBUG]
Digest(validate):
6c 9e 19 e2 4f 17 51 ef d6 96 a0 39 14 0d ef ac
db 20 e3 b9 40 c3 76 46 54 3d 31 e0 02 36 34 da 
[SRxCryptoAPI - DEBUG] stack[1] VERIFY SUCCESS
INFO[0006] return: value: 1  and status:  0             
INFO[0006] Validation function SUCCESS 
DEBU[0006] received update                               Key=172.37.0.4 Topic=Peer attributes="[{Origin: i} {Med: 0} {MpReach(ipv4-unicast): {Nexthop: 172.37.0.4, NLRIs: [200.0.0.0/8]}} {bgpsecs}]" nlri="[]" withdrawals="[]"
DEBU[0035] UpdateBgpsecPathAttr processing BGPSec attribute  Topic=bgpsec  
INFO[0035] bgpsec sign: Generate Signature               Topic=bgpsec       
DEBU[0035] secure path value: bgp.SecurePathSegment{PCount:0x1, Flags:0x0, ASN:0xea62} 
DEBU[0035] net.IP: net.IP{0xc8, 0x0, 0x0, 0x0}, go prefix addr: [16]uint8{0xc8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0} 
DEBU[0035] type: []uint8,  SKI string : 45CAD0AC44F77EFAA94602E9984305215BF47DCD
DEBU[0035] peerAS :[]byte{0x0, 0x0, 0x0, 0x0, 0x61, 0xea, 0x0, 0x0}
DEBU[0035] peerAS BigEndian :0x61ea0000
INFO[0035] more than 2 hops verification                 Topic=bgpsec 
[SRxCryptoAPI - DEBUG]
Hash(sign):
00 00 ea 61 c3 04 33 fa 19 75 ff 19 31 81 45 8f     
b9 02 b5 01 ea 97 89 dc 00 47 30 45 02 20 72 f2
46 2e 18 9f 20 2e 8b b2 36 c4 c0 1a d5 d0 40 22
cb e9 e9 ef be 6d ee 51 ed 91 50 20 02 30 02 21
00 94 69 58 5f 89 7b 9c 68 c8 fc cd 61 f6 bc 13
f8 4c 1c c6 98 f5 8c 62 69 c0 76 1c 98 3a 47 d1
34 01 00 00 00 ea 62 01 00 00 00 ea 63 01 00 01
01 08 c8
[SRxCryptoAPI - DEBUG]
Digest(sign):
f1 03 c9 56 06 03 61 36 1f be bc c8 e7 10 85 60
3b d9 f0 76 2f 00 d4 9a 7d 21 3d 93 c2 ef f9 4a
INFO[0035] return value:1 and status: 0
INFO[0035] sign function SUCCESS 
DEBU[0035] siglen: 71 signature (SEND) 
DEBU[0035] sb Length: 96
DEBU[0035] prefix addr: net.IP{0xc8, 0x0, 0x0, 0x0}, length(8), nlri afi: 0x1, nlri safi: 0x1
DEBU[0035] sb_value: []bgp.SignatureBlockInterface{(*bgp.SignatureBlock)(0xc0003c5040)}
DEBU[0035] sent update                                   Key=172.37.0.2 State=BGP_FSM_ESTABLISHED Topic=Peer attributes="[{Origin: i} {bgpsecs} {MpReach(ipv4-unicast): {Nexthop: 172.37.0.3, NLRIs: [200.0.0.0/8]}}]" nlri="[]" withdrawals="[]"
```

#### gobgp client
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

