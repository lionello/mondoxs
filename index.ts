import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";
import assert = require("assert");

const config = new pulumi.Config();
export const wgPort = config.getNumber("wgPort") || 51820; // TODO: randomize
export const sshCidr = config.require("sshCidr");

interface Peer {
  publicKey: string;
  allowedIPs: string; // TODO: make this an array
  presharedKey?: string;
}

const peers = config.requireObject<Peer[]>("peers") || [];
assert(peers.length > 0, "At least one peer is required");

// Find the latest Amazon Linux 2 AMI for x64, EBS-backed instances.
const ami = aws.ec2.getAmiOutput({
  filters: [
    {
      name: "name",
      values: ["amzn2-ami*"],
    },
    {
      name: "owner-alias",
      values: ["amazon"],
    },
    {
      name: "architecture",
      values: ["x86_64"],
    },
    {
      name: "virtualization-type",
      values: ["hvm"],
    },
    {
      name: "root-device-type",
      values: ["ebs"],
    },
  ],
  mostRecent: true,
  owners: ["amazon"],
});

export const imageId = ami.id;

const sg = new aws.ec2.SecurityGroup("secgroup", {
  ingress: [
    { protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: [sshCidr] }, // TODO: only when SSH is enabled
    {
      protocol: "udp",
      fromPort: wgPort,
      toPort: wgPort,
      cidrBlocks: ["0.0.0.0/0"],
    },
    // By default, security groups do not allow any inbound ICMP traffic.
    // If you don't explicitly configure an ICMP inbound rule for your security group, PMTUD is blocked.
    // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network_mtu.html
    // Allow ICMP Path MTU Discovery (RFC 1213) FIXME: narrow this down
    {
      protocol: "icmp",
      fromPort: -1,
      toPort: -1,
      cidrBlocks: ["0.0.0.0/0"],
    },
  ],
  egress: [
    { protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] },
  ],
});

// TODO: make this optional
const keyPair = new aws.ec2.KeyPair("keyPair", {
  publicKey: config.require("sshPublicKey"),
});

const ifAddress = config.require("ifAddress");

function peerConfig(peer: Peer): string {
  assert(peer.publicKey, "Peer must have a public key");
  assert(peer.allowedIPs, "Peer must have allowed IPs");
  return `[Peer]
PublicKey = ${peer.publicKey}
AllowedIPs = ${peer.allowedIPs}
${peer.presharedKey ? `PresharedKey = ${peer.presharedKey}` : ""}
`;
}

// Cloud-init script
// NOTE: this only runs once during first boot
// TODO: create AMI with WireGuard pre-installed to speed up boot time
const userData = `#cloud-config
package_update: false # Update apt or yum database on first boot (default: false)
package_upgrade: false # Upgrade existing packages on first boot (default: false)
repo_upgrade: security # Upgrade the instance on first boot (default: security)

write_files:
  - path: /etc/wireguard/wg0.conf
    permissions: "0600"
    owner: root
    content: |
      [Interface]
      ListenPort = ${wgPort}
      PrivateKey = PRIVATEKEY
      Address = ${ifAddress}
      PostUp = iptables -A FORWARD -i eth0 -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT ; iptables -A FORWARD -i %i -o eth0 -j ACCEPT ; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
      PostDown = iptables -D FORWARD -i eth0 -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT ; iptables -D FORWARD -i %i -o eth0 -j ACCEPT ; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
      ${peers.flatMap((peer) => peerConfig(peer).split('\n')).join("\n      ")}

runcmd:
  - amazon-linux-extras install -y epel
  - curl -o "/etc/yum.repos.d/wireguard.repo" "https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo"
  - yum install -y wireguard-dkms wireguard-tools
  - wg genkey | tee /root/privatekey | wg pubkey > publickey
  - sed -i "s:PRIVATEKEY:$(cat /root/privatekey):g" /etc/wireguard/wg0.conf
  - echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
  - sysctl -p
  - systemctl enable wg-quick@wg0
  - wg-quick up wg0
`;

const spotInstance = new aws.ec2.SpotInstanceRequest("spotInstance", {
  keyName: keyPair.keyName,
  ami: imageId,
  instanceType: "t3a.micro",
  waitForFulfillment: true,
  vpcSecurityGroupIds: [sg.id],
  userData,
});

export const publicDns = spotInstance.publicDns;
export const publicIp = spotInstance.publicIp;
export const endpoint = pulumi.interpolate`${publicIp}:${wgPort}`;
export const sshUser = pulumi.interpolate`ec2-user@${publicIp}`;
