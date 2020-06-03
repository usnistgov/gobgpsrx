

# Configuration for using NIST SRxCryptoAPI library of BGPSec Protocol


1. To enable BGPSec validation and signing features on gobgp, There are three necessary 
    configuration parameters in gobgp's configuration file

    (1) key-path  <path/to/location>
        It needs to be configured to let NIST SRxCryptoAPI library
        to know where the keys could be found. The keys are used to validate the 
        received update with using crypto calculation which was signed from the 
        sender's private key. Key locattion includes the public key paired with the
        private key. With this key, gobgpd will be able to validate or make signing 
        BGPSec update message.

    (2) bgpsec-enable  <true | false>
        This indicate gobgpd will be able to deal with BGPSec message to validate and
        make signing the BGP update packet.

    (3) SKI <20 byte hexdecimal string> 
        Unique hexadecimal string of RPKI Router Certificate


2. Example Configuration

```toml
[global.config]
  as = <as number>
  router-id = <address string>
  key-path = /path/to/keys
  # (example) key-path = "/var/lib/bgpsec-keys/"

[[neighbors]]
  [neighbors.config]
    neighbor-address = <neighbor address>
    peer-as = <neighbor asn>
    bgpsec-enable = <true | false>
    SKI = <20 byte hexdecimal string> 
    # (example) SKI = "45CAD0AC44F77EFAA94602E9984305215BF47DCD"
```



