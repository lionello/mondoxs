import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";

const config = new pulumi.Config();
export const wgPort = config.getNumber("wgPort") || 51820; // TODO: randomize
export const sshCidr = config.require("sshCidr");

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
    { protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: [sshCidr] },
    {
      protocol: "udp",
      fromPort: wgPort,
      toPort: wgPort,
      cidrBlocks: ["0.0.0.0/0"],
    },
  ],
  egress: [
    { protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] },
  ],
});

const keyPair = new aws.ec2.KeyPair("keyPair", {
  publicKey: config.require("publicKey"),
});

// const wgCidr = config.require("wgCidr");
const ifAddress = config.require("ifAddress"); // TODO: get from `wgCidr`
const peerPublicKey = config.require("peerPublicKey");
const peerAllowedIPs = config.require("peerAllowedIPs");
const peerPresharedKey = config.get("peerPresharedKey");

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
      SaveConfig = true
      PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
      PreDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
      [Peer]
      PublicKey = ${peerPublicKey}
      AllowedIPs = ${peerAllowedIPs}
      ${peerPresharedKey ? `PresharedKey = ${peerPresharedKey}` : ""}

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
