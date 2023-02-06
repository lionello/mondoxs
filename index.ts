import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import assert = require("assert");

interface Peer {
  publicKey: string;
  allowedIPs: string; // TODO: make this an array
  presharedKey?: string;
}

const config = new pulumi.Config();
export const region = aws.config.region;
assert(region);
export const wgPort = config.getNumber("wgPort") || 53; // TODO: randomize
export const sshCidr = config.require("sshCidr"); // TODO: make this optional
const ifAddress = config.require("ifAddress");
const privateKey = config.getSecret("privateKey");
const peers = config.requireObject<Peer[]>("peers") || [];
assert(peers.length > 0, "At least one peer is required");

// Find the latest Amazon Linux 2 AMI for x64, EBS-backed instances.
const ami = aws.ec2.getAmiOutput({
  filters: [
    {
      name: "name",
      values: ["amzn2-ami-kernel-5.10*"],
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

function peerConfig(peer: Peer): string {
  assert(peer.publicKey, "Peer must have a public key");
  assert(peer.allowedIPs, "Peer must have allowed IPs");
  return `[Peer]
PublicKey = ${peer.publicKey}
AllowedIPs = ${peer.allowedIPs}
${peer.presharedKey ? `PresharedKey = ${peer.presharedKey}` : ""}
`;
}

// Write private key to AWS secrets manager TODO: make this optional
const pkSecret = new aws.secretsmanager.Secret("privateKey", {});
const secretVersion = new aws.secretsmanager.SecretVersion(
  "secretVersion",
  {
    secretId: pkSecret.id,
    secretString: privateKey,
  },
  {
    parent: pkSecret,
    aliases: [{ parent: pulumi.rootStackResource }],
  }
);

export const secretId = pkSecret.name;

// Cloud-init script
// NOTE: this only runs once during first boot
// TODO: create AMI with WireGuard pre-installed to speed up boot time
const userData = pulumi.interpolate`#cloud-config
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
      PrivateKey = REPLACEME
      Address = ${ifAddress}
      PostUp = iptables -A FORWARD -i eth0 -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT ; iptables -A FORWARD -i %i -o eth0 -j ACCEPT ; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
      PostDown = iptables -D FORWARD -i eth0 -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT ; iptables -D FORWARD -i %i -o eth0 -j ACCEPT ; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
      ${peers.flatMap((peer) => peerConfig(peer).split("\n")).join("\n      ")}

runcmd:
  - amazon-linux-extras install -y epel
  - curl -o "/etc/yum.repos.d/wireguard.repo" "https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo"
  - yum install -y wireguard-dkms wireguard-tools
  - export PK=$(aws secretsmanager get-secret-value --region ${region} --secret-id ${
  pkSecret.id
} --query SecretString --output text || wg genkey)
  - echo $PK | wg pubkey > /publickey
  - sed -i "s:REPLACEME:$PK:g" /etc/wireguard/wg0.conf
  - echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
  - sysctl -p
  - systemctl enable wg-quick@wg0
  - wg-quick up wg0
`;

// Create a role that can be assumed by EC2 instances TODO: make this optional
const instanceRole = new aws.iam.Role("instance-role", {
  assumeRolePolicy: {
    Version: "2012-10-17",
    Statement: [
      {
        Action: "sts:AssumeRole",
        Effect: "Allow",
        Principal: {
          Service: "ec2.amazonaws.com",
        },
      },
    ],
  },
  inlinePolicies: [
    {
      name: "SecretReadAccess",
      policy: pulumi.jsonStringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: "secretsmanager:GetSecretValue",
            Resource: pkSecret.arn,
          },
        ],
      }),
    },
  ],
});

const instance_profile = new aws.iam.InstanceProfile("instance_profile", {
  role: instanceRole.name,
});

const spotInstance = new aws.ec2.SpotInstanceRequest("spotInstance", {
  ami: imageId,
  iamInstanceProfile: instance_profile.name,
  instanceType: "t3a.nano", // TODO: use Spot Fleet to get the cheapest instance type
  keyName: keyPair.keyName,
  userData,
  vpcSecurityGroupIds: [sg.id],
  waitForFulfillment: true,
});

export const publicIp = spotInstance.publicIp;
export const endpoint = pulumi.interpolate`${publicIp}:${wgPort}`;
export const sshUser = pulumi.interpolate`ec2-user@${publicIp}`;
