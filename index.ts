import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";

// Find the latest Amazon Linux 2 AMI for ARM, EBS-backed instances.
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
      values: ["arm64"],
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
        { protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: ["0.0.0.0/0"] },
    ],
    egress: [
        { protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] },
    ],
});

const config = new pulumi.Config();

const keyPair = new aws.ec2.KeyPair("keyPair", {
  publicKey: config.require("publicKey"),
});

const spotInstance = new aws.ec2.SpotInstanceRequest("spotInstance", {
  keyName: keyPair.keyName,
  ami: imageId,
  instanceType: "t4g.micro",
  waitForFulfillment: true,
  vpcSecurityGroupIds: [sg.id],
});

export const publicDns = spotInstance.publicDns;
export const publicIp = spotInstance.publicIp;
