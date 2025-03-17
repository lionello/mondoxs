# mondoxs
[Pulumi](https://www.pulumi.com) stack that deploys a [WireGuard](https://www.wireguard.com) server on EC2 Spot.

See `Pulumi.canada.yaml` for an example on how to configure a particular instance.

## Local config
```
[Interface]
PrivateKey = generate private key for which you'll put the public key in stack config
Address = 192.168.9.2/32
DNS = 8.8.8.8

[Peer]
PublicKey = server's public key for which you'll put the private key in stack config
AllowedIPs = 0.0.0.0/0
Endpoint = stackx.donat.io:51820
PersistentKeepalive = 25
```
