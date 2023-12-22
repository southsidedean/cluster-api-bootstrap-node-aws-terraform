# -------------------------
# Bastion-only lab deployment for DKP CAPI deployments
# Ubuntu 20.04
# Tom Dean
# D2iQ
# Last updated 8/9/2022
# -------------------------

# -------------------------
# Bastion/Lab Variables
# Change these values here!!
# -------------------------

variable "bastion_instance_type" {
  type    = string
  default = "t3.large"
}

variable "bastion_ami" {
  type    = string
  default = "ami-00e8c38e4908d08ce"
}

variable "bastion_key" {
  type    = string
  default = "cs-key"
}

variable "aws_region" {
  type    = string
  default = "us-west-2"
}

variable "subnet_range" {
  type    = string
  default = "10.0.0.0/24"
}

variable "route_destination_cidr_block" {
  type    = string
  default = "0.0.0.0/0"
}

variable "class_name" {
  type    = string
  default = "dka200"
}

variable "owner" {
  type    = string
  default = "D2iQ Education"
}

# -------------------------
# Generate a random string for cluster name
# No two clusters shall be named the same!
# -------------------------

resource "random_pet" "pet" {
  length    = 2
  separator = "-"
}

locals {
  cluster_name = random_pet.pet.id
}

# -------------------------
# Keypair Resources: student_key
# This is the keypair for the student to use for labs
# -------------------------

resource "tls_private_key" "student_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "student_key" {
  key_name_prefix = "student_key_"
  public_key      = tls_private_key.student_key.public_key_openssh
}

output "student_key" {
  value = aws_key_pair.student_key.key_name
}

# -------------------------
# Keypair Resources: cs-key
# This is the keypair provided by CloudShare for console connections
# It is attached to the Bootstrap
# Let's pull some information on this key
# -------------------------

data "aws_key_pair" "cs-key-existing" {
  key_name = "cs-key"
}

output "cs-key-data" {
  value = data.aws_key_pair.cs-key-existing
}

# -------------------------
# Pull AWS Account ID for future use
# We'll need this!!
# -------------------------

data "aws_caller_identity" "current" {}

# -------------------------
# DKP IAM Roles/Policies/Instance Profiles for CAPI AWS Deployments
# Per https://docs.d2iq.com/dkp/konvoy/2.2/choose-infrastructure/aws/iam-policies/
# -------------------------
# Create instance-assume-role-policy
# We will need this to create the IAM Roles
# -------------------------

data "aws_iam_policy_document" "instance-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# -------------------------
# IAM Policies
# We put the contents of the policies into aws_iam_policy_documents, then consume those policy documents in their associated aws_iam_policy
# This gives us some flexibility in how we consume policies
# -------------------------
# AWSIAMManagedPolicyCloudProviderControlPlane: For the Kubernetes Cloud Provider AWS Control Plane
#   - enumerates the Actions required by the workload cluster control plane machines. It is attached to the AWSIAMRoleControlPlane Role
# AWSIAMManagedPolicyCloudProviderNodes: For the Kubernetes Cloud Provider AWS nodes
#   - enumerates the Actions required by the workload cluster worker machines. It is attached to the AWSIAMRoleNodes Role
# AWSIAMManagedPolicyControllers: For the Kubernetes Cluster API Provider AWS Controllers
#   - enumerates the Actions required by the workload cluster worker machines. It is attached to the AWSIAMRoleControlPlane Role
# -------------------------

data "aws_iam_policy_document" "AWSIAMManagedPolicyCloudProviderControlPlanePD" {
  statement {
    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeTags",
      "ec2:DescribeInstances",
      "ec2:DescribeImages",
      "ec2:DescribeRegions",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVolumes",
      "ec2:CreateSecurityGroup",
      "ec2:CreateTags",
      "ec2:CreateVolume",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyVolume",
      "ec2:AttachVolume",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateRoute",
      "ec2:DeleteRoute",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteVolume",
      "ec2:DetachVolume",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DescribeVpcs",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:AttachLoadBalancerToSubnets",
      "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateLoadBalancerPolicy",
      "elasticloadbalancing:CreateLoadBalancerListeners",
      "elasticloadbalancing:ConfigureHealthCheck",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteLoadBalancerListeners",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DetachLoadBalancerFromSubnets",
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
      "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancerPolicies",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
      "iam:CreateServiceLinkedRole",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "AWSIAMManagedPolicyCloudProviderNodesPD" {
  statement {
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeRegions",
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:BatchGetImage"
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "secretsmanager:DeleteSecret",
      "secretsmanager:GetSecretValue"
    ]
    resources = ["arn:*:secretsmanager:*:*:secret:aws.cluster.x-k8s.io/*"]
  }
  statement {
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
      "s3:GetEncryptionConfiguration"
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "AWSIAMManagedPolicyControllersPD" {
  statement {
    actions = [
      "ec2:AllocateAddress",
      "ec2:AssociateRouteTable",
      "ec2:AttachInternetGateway",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateInternetGateway",
      "ec2:CreateNatGateway",
      "ec2:CreateRoute",
      "ec2:CreateRouteTable",
      "ec2:CreateSecurityGroup",
      "ec2:CreateSubnet",
      "ec2:CreateTags",
      "ec2:CreateVpc",
      "ec2:ModifyVpcAttribute",
      "ec2:DeleteInternetGateway",
      "ec2:DeleteNatGateway",
      "ec2:DeleteRouteTable",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteSubnet",
      "ec2:DeleteTags",
      "ec2:DeleteVpc",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInstances",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeImages",
      "ec2:DescribeNatGateways",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeNetworkInterfaceAttribute",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
      "ec2:DescribeVpcAttribute",
      "ec2:DescribeVolumes",
      "ec2:DetachInternetGateway",
      "ec2:DisassociateRouteTable",
      "ec2:DisassociateAddress",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:ModifySubnetAttribute",
      "ec2:ReleaseAddress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RunInstances",
      "ec2:TerminateInstances",
      "tag:GetResources",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:ConfigureHealthCheck",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:RemoveTags",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeInstanceRefreshes",
      "ec2:CreateLaunchTemplate",
      "ec2:CreateLaunchTemplateVersion",
      "ec2:DescribeLaunchTemplates",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:DeleteLaunchTemplate",
      "ec2:DeleteLaunchTemplateVersions"
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "autoscaling:CreateAutoScalingGroup",
      "autoscaling:UpdateAutoScalingGroup",
      "autoscaling:CreateOrUpdateTags",
      "autoscaling:StartInstanceRefresh",
      "autoscaling:DeleteAutoScalingGroup",
      "autoscaling:DeleteTags"
    ]
    resources = ["arn:*:autoscaling:*:*:autoScalingGroup:*:autoScalingGroupName/*"]
  }
  statement {
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:*:iam::*:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["autoscaling.amazonaws.com"]
    }
  }
  statement {
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:*:iam::*:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing"]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["elasticloadbalancing.amazonaws.com"]
    }
  }
  statement {
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:*:iam::*:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot"]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"
      values   = ["spot.amazonaws.com"]
    }
  }
  statement {
    actions   = ["iam:PassRole"]
    resources = ["arn:*:iam::*:role/*.cluster-api-provider-aws.sigs.k8s.io"]
  }
  statement {
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:TagResource"
    ]
    resources = ["arn:*:secretsmanager:*:*:secret:aws.cluster.x-k8s.io/*"]
  }
}

# Deprecated as we are attaching the IAM Polcies directly to the Roles now
#data "aws_iam_policy_document" "AWSIAMManagedPolicyCloudProviderControlPlaneCAPIPD" {
#  source_policy_documents = [
#    data.aws_iam_policy_document.AWSIAMManagedPolicyCloudProviderControlPlanePD.json,
#    data.aws_iam_policy_document.AWSIAMManagedPolicyControllersPD.json
#  ]
#}

resource "aws_iam_policy" "AWSIAMManagedPolicyCloudProviderControlPlane" {
  name        = "control-plane.cluster-api-provider-aws.sigs.k8s.io"
  path        = "/"
  description = "For the Kubernetes Cloud Provider AWS Control Plane"
  policy      = data.aws_iam_policy_document.AWSIAMManagedPolicyCloudProviderControlPlanePD.json
}

resource "aws_iam_policy" "AWSIAMManagedPolicyCloudProviderNodes" {
  name        = "nodes.cluster-api-provider-aws.sigs.k8s.io"
  path        = "/"
  description = "For the Kubernetes Cloud Provider AWS nodes"
  policy      = data.aws_iam_policy_document.AWSIAMManagedPolicyCloudProviderNodesPD.json
}

resource "aws_iam_policy" "AWSIAMManagedPolicyControllers" {
  name        = "controllers.cluster-api-provider-aws.sigs.k8s.io"
  path        = "/"
  description = "For the Kubernetes Cluster API Provider AWS Controllers"
  policy      = data.aws_iam_policy_document.AWSIAMManagedPolicyControllersPD.json
}

# -------------------------
# IAM Roles for CAPI
# -------------------------
# AWSIAMRoleControlPlane is the Role associated with the AWSIAMInstanceProfileControlPlane Instance Profile
# AWSIAMRoleNodes is the Role associated with the AWSIAMInstanceProfileNodes Instance Profile
# -------------------------

resource "aws_iam_role" "AWSIAMRoleControlPlane" {
  name               = "control-plane.cluster-api-provider-aws.sigs.k8s.io"
  path               = "/system/"
  assume_role_policy = data.aws_iam_policy_document.instance-assume-role-policy.json
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/BoundaryForAdministratorAccess"
}

resource "aws_iam_role" "AWSIAMRoleNodes" {
  name               = "nodes.cluster-api-provider-aws.sigs.k8s.io"
  path               = "/system/"
  assume_role_policy = data.aws_iam_policy_document.instance-assume-role-policy.json
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/BoundaryForAdministratorAccess"
}

# -------------------------
# IAM Instance Profiles for CAPI
# This is where we attach our CAPI Roles to our CAPI Instance Profiles
# The CAPI Instance Profiles are consumed by the EC2 Instances
# -------------------------
# AWSIAMInstanceProfileControlPlane is assigned to workload cluster control plane machines
# AWSIAMInstanceProfileNodes is assigned to workload cluster worker machines
# -------------------------

resource "aws_iam_instance_profile" "AWSIAMInstanceProfileControlPlane" {
  name = "control-plane.cluster-api-provider-aws.sigs.k8s.io"
  role = aws_iam_role.AWSIAMRoleControlPlane.name
}

resource "aws_iam_instance_profile" "AWSIAMInstanceProfileNodes" {
  name = "nodes.cluster-api-provider-aws.sigs.k8s.io"
  role = aws_iam_role.AWSIAMRoleNodes.name
}

# -------------------------
# IAM Policy Attachments for CAPI
# This is where we attach our CAPI Policies to our CAPI Roles
# The CAPI Roles are consumed by the CAPI Instance Profiles
# -------------------------
# For the Control Planes:
# AWSIAMPolicyAttachmentControlPlane attaches the AWSIAMManagedPolicyCloudProviderControlPlane Managed Policy to the AWSIAMRoleControlPlane Role
# AWSIAMPolicyAttachmentCPNodes attaches the AWSIAMManagedPolicyCloudProviderNodes Managed Policy to the AWSIAMRoleControlPlane Role
# AWSIAMPolicyAttachmentControllers attaches the AWSIAMManagedPolicyControllers Managed Policy to the AWSIAMRoleControlPlane Role
#
# For the Worker Nodes:
# AWSIAMPolicyAttachmentNodes attaches the AWSIAMManagedPolicyCloudProviderNodes Managed Policy to the AWSIAMRoleNodes Role
# -------------------------

resource "aws_iam_role_policy_attachment" "AWSIAMPolicyAttachmentControlPlane" {
  role       = aws_iam_role.AWSIAMRoleControlPlane.name
  policy_arn = aws_iam_policy.AWSIAMManagedPolicyCloudProviderControlPlane.arn
}

resource "aws_iam_role_policy_attachment" "AWSIAMPolicyAttachmentCPNodes" {
  role       = aws_iam_role.AWSIAMRoleControlPlane.name
  policy_arn = aws_iam_policy.AWSIAMManagedPolicyCloudProviderNodes.arn
}

resource "aws_iam_role_policy_attachment" "AWSIAMPolicyAttachmentControllers" {
  role       = aws_iam_role.AWSIAMRoleControlPlane.name
  policy_arn = aws_iam_policy.AWSIAMManagedPolicyControllers.arn
}

resource "aws_iam_role_policy_attachment" "AWSIAMPolicyAttachmentNodes" {
  role       = aws_iam_role.AWSIAMRoleNodes.name
  policy_arn = aws_iam_policy.AWSIAMManagedPolicyCloudProviderNodes.arn
}

# -------------------------
# DKP Minimal Permissions and Role to Create Clusters For Bootstrap Nodes
# Per https://docs.d2iq.com/dkp/konvoy/2.2/choose-infrastructure/aws/advanced/permissions_role_create_cluster/
# -------------------------
# The following is a Terraform stack that creates:
#   - A policy named dkp-bootstrapper-policy that enumerates the minimal permissions for a user that can create dkp aws clusters.
#   - A role named dkp-bootstrapper-role that uses the dkp-bootstrapper-policy with a trust policy to allow IAM users and ec2 instances from MYAWSACCOUNTID to use the role via STS.
#   - An instance profile DKPBootstrapInstanceProfile that wraps the dkp-bootstrapper-role to be used by ec2 instances.
#
# We'll attach the DKPBootstrapInstanceProfile to our Bootstrap node
# -------------------------
# -------------------------
# Create bootstrap-assume-role aws_iam_policy_document
# -------------------------

data "aws_iam_policy_document" "bootstrap-assume-role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

# -------------------------
# IAM Managed Policy
# AWSIAMManagedPolicyDKPBootstrapper
# ManagedPolicyName: dkp-bootstrapper-policy
# Minimal policy to create dkp clusters in AWS
# The dkp-bootstrapper-policy enumerates the minimal permissions for a user that can create dkp aws clusters.
# -------------------------

resource "aws_iam_policy" "AWSIAMManagedPolicyDKPBootstrapper" {
  name        = "dkp-bootstrapper-policy"
  path        = "/"
  description = "Minimal policy to create dkp clusters in AWS"
  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:AllocateAddress",
          "ec2:AssociateRouteTable",
          "ec2:AttachInternetGateway",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateInternetGateway",
          "ec2:CreateNatGateway",
          "ec2:CreateRoute",
          "ec2:CreateRouteTable",
          "ec2:CreateSecurityGroup",
          "ec2:CreateSubnet",
          "ec2:CreateTags",
          "ec2:CreateVpc",
          "ec2:ModifyVpcAttribute",
          "ec2:DeleteInternetGateway",
          "ec2:DeleteNatGateway",
          "ec2:DeleteRouteTable",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteSubnet",
          "ec2:DeleteTags",
          "ec2:DeleteVpc",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInstances",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeImages",
          "ec2:DescribeNatGateways",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeNetworkInterfaceAttribute",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeVolumes",
          "ec2:DetachInternetGateway",
          "ec2:DisassociateRouteTable",
          "ec2:DisassociateAddress",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:ModifySubnetAttribute",
          "ec2:ReleaseAddress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "tag:GetResources",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:ConfigureHealthCheck",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
          "elasticloadbalancing:DescribeTags",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
          "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
          "elasticloadbalancing:RemoveTags",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeInstanceRefreshes",
          "ec2:CreateLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:DeleteLaunchTemplate",
          "ec2:DeleteLaunchTemplateVersions",
          "ec2:DescribeKeyPairs"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "autoscaling:CreateAutoScalingGroup",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:CreateOrUpdateTags",
          "autoscaling:StartInstanceRefresh",
          "autoscaling:DeleteAutoScalingGroup",
          "autoscaling:DeleteTags"
        ]
        Effect   = "Allow"
        Resource = "arn:*:autoscaling:*:*:autoScalingGroup:*:autoScalingGroupName/*"
      },
      {
        Action = ["iam:CreateServiceLinkedRole"]
        Condition = {
          "StringLike" = {
            "iam:AWSServiceName" = "autoscaling.amazonaws.com"
          }
        }
        Effect   = "Allow"
        Resource = "arn:*:iam::*:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
      },
      {
        Action = ["iam:CreateServiceLinkedRole"]
        Condition = {
          "StringLike" = {
            "iam:AWSServiceName" = "elasticloadbalancing.amazonaws.com"
          }
        }
        Effect   = "Allow"
        Resource = "arn:*:iam::*:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing"
      },
      {
        Action = ["iam:CreateServiceLinkedRole"]
        Condition = {
          "StringLike" = {
            "iam:AWSServiceName" = "spot.amazonaws.com"
          }
        }
        Effect   = "Allow"
        Resource = "arn:*:iam::*:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot"
      },
      {
        Action   = ["iam:PassRole"]
        Effect   = "Allow"
        Resource = "arn:*:iam::*:role/*.cluster-api-provider-aws.sigs.k8s.io"
      },
      {
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:DeleteSecret",
          "secretsmanager:TagResource"
        ]
        Effect   = "Allow"
        Resource = "arn:*:secretsmanager:*:*:secret:aws.cluster.x-k8s.io/*"
      }
    ]
  })
}

# -------------------------
# IAM Role for Bootstrap Nodes
# -------------------------
# A role named dkp-bootstrapper-role that uses the dkp-bootstrapper-policy with a trust policy to allow IAM users and ec2 instances from ${data.aws_caller_identity.current.account_id} to use the role via STS.
# -------------------------

resource "aws_iam_role" "DKPBootstrapRole" {
  name               = "dkp-bootstrapper-role"
  path               = "/system/"
  assume_role_policy = data.aws_iam_policy_document.bootstrap-assume-role.json
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/BoundaryForAdministratorAccess"
}

# -------------------------
# IAM Instance Profile for Bootstrap Nodes
# -------------------------
# The instance profile DKPBootstrapInstanceProfile wraps the dkp-bootstrapper-role to be used by ec2 instances.
# -------------------------

resource "aws_iam_instance_profile" "AWSIAMInstanceProfileDKPBootstrapper" {
  name = "DKPBootstrapInstanceProfile"
  role = aws_iam_role.DKPBootstrapRole.name
}

# -------------------------
# IAM Policy Attachments for Bootstrap Nodes
# -------------------------
# AWSIAMPolicyAttachmentBootstrap attaches DKPBootstrapRole to AWSIAMManagedPolicyDKPBootstrapper
# -------------------------

resource "aws_iam_role_policy_attachment" "AWSIAMPolicyAttachmentBootstrap" {
  role       = aws_iam_role.DKPBootstrapRole.name
  policy_arn = aws_iam_policy.AWSIAMManagedPolicyDKPBootstrapper.arn
}

# -------------------------
# VPC
# -------------------------

resource "aws_vpc" "course_vpc" {
  cidr_block = var.subnet_range

  tags = {
    Name = "${var.class_name}-vpc-${local.cluster_name}"
  }
  enable_dns_support   = true
  enable_dns_hostnames = true
}

# -------------------------
# Subnet + Routes
# -------------------------

resource "aws_subnet" "course_subnet" {
  vpc_id     = aws_vpc.course_vpc.id
  cidr_block = var.subnet_range

  map_public_ip_on_launch = true

  tags = {
    Name                                          = "${var.class_name}-${local.cluster_name}-subnet"
    "kubernetes.io/cluster"                       = local.cluster_name
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
  }
}

resource "aws_internet_gateway" "default" {
  vpc_id = aws_vpc.course_vpc.id
}

resource "aws_route_table" "course_public_rt" {
  vpc_id = aws_vpc.course_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.default.id
  }
  lifecycle {
    ignore_changes = [route, tags]
  }
  tags = {
    "Name" : "${var.class_name}-${local.cluster_name}-routetable",
    "kubernetes.io/cluster/${local.cluster_name}" : "owned",
    "kubernetes.io/cluster" : "${local.cluster_name}"
  }
}

resource "aws_route_table_association" "course_public_rta" {
  subnet_id      = aws_subnet.course_subnet.id
  route_table_id = aws_route_table.course_public_rt.id
}

# -------------------------
# Security Groups
# -------------------------

resource "aws_security_group" "common" {
  name        = "${var.class_name}-${local.cluster_name}-common-firewall"
  description = "Allow common ports (e.g. 22/tcp)"
  vpc_id      = aws_vpc.course_vpc.id

  ingress {
    description = "All Ingress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All Egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "course_ssh" {
  name        = "${var.class_name}-${local.cluster_name}-ssh"
  description = "Allow inbound SSH."
  vpc_id      = aws_vpc.course_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${var.class_name}-${local.cluster_name}-sg-ssh"
  }
}

resource "aws_security_group" "elb_control_plane" {
  name        = "${var.class_name}-${local.cluster_name}-cp"
  description = "Allow traffic to konvoy control plane"
  vpc_id      = aws_vpc.course_vpc.id

  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.class_name}-${local.cluster_name}-cp"
  }
}

resource "aws_security_group" "course_elb" {
  name        = "${var.class_name}-${local.cluster_name}-elb-sg"
  description = "Security Group used by elb"
  vpc_id      = aws_vpc.course_vpc.id

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 9000
    to_port   = 9000
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 5000
    to_port   = 5000
    protocol  = "tcp"
    self      = true
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  tags = {
    Name                                          = "${var.class_name}-${local.cluster_name}-elb-sg",
    "kubernetes.io/cluster/${local.cluster_name}" = "owned",
    "kubernetes.io/cluster"                       = "${local.cluster_name}"
  }
}

# -------------------------
# Bastion Instance
# -------------------------

resource "aws_instance" "bastion" {
  count         = 1
  ami           = var.bastion_ami
  instance_type = var.bastion_instance_type
  subnet_id     = aws_subnet.course_subnet.id
  key_name      = var.bastion_key
  vpc_security_group_ids = [
    aws_security_group.common.id,
    aws_security_group.course_ssh.id
  ]
  iam_instance_profile        = aws_iam_instance_profile.AWSIAMInstanceProfileDKPBootstrapper.name
  associate_public_ip_address = true
  root_block_device {
    volume_size           = 128 # 80 is fine but 120 for airgap considerations
    volume_type           = "gp2"
    delete_on_termination = true
  }

  tags = {
    Name            = "${var.class_name}-${local.cluster_name}-bastion",
    Cluster         = local.cluster_name,
    Class           = var.class_name,
    ci-key-username = "ubuntu"
  }

  lifecycle {
    ignore_changes = [user_data, ami]
  }

  user_data = <<EOF
#!/usr/bin/bash
echo "${tls_private_key.student_key.private_key_pem}" > /home/ubuntu/student_key.pem
echo "${tls_private_key.student_key.public_key_pem}" > /home/ubuntu/student_key.pub
chmod 600 /home/ubuntu/student_key.pem
chown ubuntu:ubuntu /home/ubuntu/student_key.*
docker pull d2iqeducation/dka200-workbook:latest
docker run --restart=always -d -p 8080:80 d2iqeducation/dka200-workbook:latest
EOF
}
