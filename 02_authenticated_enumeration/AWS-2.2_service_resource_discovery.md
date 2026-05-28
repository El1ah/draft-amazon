Repeatability: per_account
Prerequisites: Valid AWS credentials with read permissions (SecurityAudit, ViewOnlyAccess, or equivalent IAM policies granting Describe/List/Get on target services)
Description: Authenticated enumeration of all AWS service resources within an account. This methodology systematically discovers compute, storage, serverless, database, secrets, encryption, orchestration, container, and ML resources across all regions. The output feeds directly into attack surface mapping, privilege escalation analysis, and data exfiltration planning. Incomplete visibility of resources is itself a finding — defenders who cannot enumerate their own assets cannot protect them.
Tags: enumeration, resource-discovery, cloudfox, ec2, s3, lambda, rds, secrets-manager, ssm, kms, cloudformation, codebuild, ecs, eks, sagemaker
Potential Severity: medium

------------------------------------------
Procedure 0 — Enumerate All Resource Types Across Regions
Tools: aws cli, CloudFox, Prowler
Intrusiveness: passive
Description: Performs a broad sweep of all resource types across every enabled region using the Resource Groups Tagging API and CloudFox inventory module. This provides a high-level asset inventory before diving into service-specific enumeration. Resources that are untagged or in unexpected regions are especially interesting.

Step 1: Identify all enabled regions for the account:
  aws ec2 describe-regions --query "Regions[].RegionName" --output text

Step 2: Enumerate all tagged resources across all regions using the Resource Groups Tagging API:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== Region: $region ==="
    aws resourcegroupstaggingapi get-resources --region "$region" --output json >> all_tagged_resources.json
  done

Step 3: Summarize resource types discovered:
  cat all_tagged_resources.json | jq -r '.ResourceTagMappingList[].ResourceARN' | awk -F: '{print $3":"$5}' | sort | uniq -c | sort -rn

Step 4: Run CloudFox inventory module for a comprehensive cross-service sweep:
  cloudfox aws --profile <profile> inventory

Step 5: Run CloudFox all-checks to generate a broad enumeration baseline:
  cloudfox aws --profile <profile> all-checks

Step 6: Optionally run Prowler for a compliance-oriented inventory:
  prowler aws -p <profile> --checks-folder inventory

Step 7: Compare discovered resources against any provided asset inventory or CMDB export to identify shadow/orphan resources.

Flag: Resources discovered in unexpected regions, untagged resources, resource types not documented in the client's asset inventory, or any resources that appear to be orphaned or outside of known infrastructure-as-code management.

------------------------------------------
Procedure 1 — Enumerate EC2 Instances, Security Groups, VPCs, and Subnets
Tools: aws cli, CloudFox
Intrusiveness: passive
Description: Discovers all EC2 compute instances, their security group configurations, VPC topology, and subnet layout. Publicly exposed instances, overly permissive security groups, and instances with IAM roles attached are high-value targets.

Step 1: List all EC2 instances across all regions with key metadata:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws ec2 describe-instances --region "$region" \
      --query "Reservations[].Instances[].{ID:InstanceId,Type:InstanceType,State:State.Name,PublicIP:PublicIpAddress,PrivateIP:PrivateIpAddress,Profile:IamInstanceProfile.Arn,KeyName:KeyName,SubnetId:SubnetId,VpcId:VpcId,LaunchTime:LaunchTime}" \
      --output table
  done

Step 2: Enumerate all security groups and identify overly permissive rules (0.0.0.0/0 ingress):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws ec2 describe-security-groups --region "$region" \
      --query "SecurityGroups[?length(IpPermissions[?contains(IpRanges[].CidrIp, '0.0.0.0/0')]) > \`0\`].{GroupId:GroupId,GroupName:GroupName,VpcId:VpcId}" \
      --output table
  done

Step 3: List all VPCs and their CIDR blocks:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    aws ec2 describe-vpcs --region "$region" \
      --query "Vpcs[].{VpcId:VpcId,CidrBlock:CidrBlock,IsDefault:IsDefault,State:State}" \
      --output table
  done

Step 4: List all subnets with public/private classification:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    aws ec2 describe-subnets --region "$region" \
      --query "Subnets[].{SubnetId:SubnetId,VpcId:VpcId,CidrBlock:CidrBlock,AZ:AvailabilityZone,MapPublicIp:MapPublicIpOnLaunch,AvailableIPs:AvailableIpAddressCount}" \
      --output table
  done

Step 5: Identify EC2 instances with public IP addresses and IAM instance profiles (high-value pivot targets):
  aws ec2 describe-instances --query "Reservations[].Instances[?PublicIpAddress!=null && IamInstanceProfile!=null].{ID:InstanceId,PublicIP:PublicIpAddress,Profile:IamInstanceProfile.Arn}" --output table --region <region>

Step 6: Run CloudFox to identify instances with interesting roles:
  cloudfox aws --profile <profile> instances

Step 7: Check for EC2 user data scripts (may contain credentials):
  for id in $(aws ec2 describe-instances --query "Reservations[].Instances[].InstanceId" --output text --region <region>); do
    echo "=== $id ==="
    aws ec2 describe-instance-attribute --instance-id "$id" --attribute userData --region <region> --query "UserData.Value" --output text | base64 -d 2>/dev/null
  done

Flag: EC2 instances with public IPs and attached IAM roles, security groups allowing 0.0.0.0/0 ingress on sensitive ports (22, 3389, 3306, 5432, 27017), instances with credentials in user data, or instances in non-standard/unexpected regions.

------------------------------------------
Procedure 2 — Enumerate S3 Buckets and Bucket Policies
Tools: aws cli, CloudFox, Prowler
Intrusiveness: passive
Description: Discovers all S3 buckets, their ACLs, bucket policies, public access block settings, and encryption configuration. S3 buckets are a top target for data exfiltration and frequently misconfigured.

Step 1: List all S3 buckets in the account:
  aws s3api list-buckets --query "Buckets[].{Name:Name,Created:CreationDate}" --output table

Step 2: For each bucket, check the public access block configuration:
  for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
    echo "=== $bucket ==="
    aws s3api get-public-access-block --bucket "$bucket" 2>&1
  done

Step 3: Retrieve bucket policies and inspect for wildcard principals or public access:
  for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
    echo "=== $bucket ==="
    aws s3api get-bucket-policy --bucket "$bucket" --query "Policy" --output text 2>/dev/null | jq .
  done

Step 4: Check bucket ACLs for public grants:
  for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
    echo "=== $bucket ==="
    aws s3api get-bucket-acl --bucket "$bucket" --output json 2>/dev/null
  done

Step 5: Check encryption configuration:
  for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
    echo "=== $bucket ==="
    aws s3api get-bucket-encryption --bucket "$bucket" 2>&1
  done

Step 6: Check bucket versioning status (relevant for data recovery / ransomware scenarios):
  for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
    echo "=== $bucket ==="
    aws s3api get-bucket-versioning --bucket "$bucket" 2>&1
  done

Step 7: Identify bucket regions:
  for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
    echo "$bucket: $(aws s3api get-bucket-location --bucket "$bucket" --query "LocationConstraint" --output text)"
  done

Step 8: Attempt to list objects in each bucket (top-level sample):
  for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
    echo "=== $bucket ==="
    aws s3api list-objects-v2 --bucket "$bucket" --max-items 20 --query "Contents[].{Key:Key,Size:Size,Modified:LastModified}" --output table 2>/dev/null
  done

Step 9: Run CloudFox S3 enumeration:
  cloudfox aws --profile <profile> buckets

Flag: Buckets with public access (ACL grants to AllUsers or AuthenticatedUsers), bucket policies with Principal "*", disabled public access blocks, unencrypted buckets, buckets containing sensitive file types (.sql, .bak, .env, .pem, .key, .csv), or buckets with versioning disabled on critical data.

------------------------------------------
Procedure 3 — Enumerate Lambda Functions, Layers, and Event Sources
Tools: aws cli, CloudFox
Intrusiveness: passive
Description: Discovers all Lambda functions, their configurations, environment variables (which frequently contain secrets), IAM execution roles, layers, and event source mappings. Lambda functions are a common vector for credential harvesting and privilege escalation.

Step 1: List all Lambda functions across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws lambda list-functions --region "$region" \
      --query "Functions[].{Name:FunctionName,Runtime:Runtime,Role:Role,Handler:Handler,Timeout:Timeout,MemorySize:MemorySize,LastModified:LastModified}" \
      --output table
  done

Step 2: Retrieve environment variables for each function (high-value — often contains secrets):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for func in $(aws lambda list-functions --region "$region" --query "Functions[].FunctionName" --output text); do
      echo "=== $region / $func ==="
      aws lambda get-function-configuration --function-name "$func" --region "$region" \
        --query "Environment.Variables" --output json 2>/dev/null
    done
  done

Step 3: List Lambda layers (may contain shared libraries or credentials):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws lambda list-layers --region "$region" --output table
  done

Step 4: List event source mappings for each function:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws lambda list-event-source-mappings --region "$region" --output json
  done

Step 5: Retrieve function policies (resource-based policies — check for cross-account invocation):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for func in $(aws lambda list-functions --region "$region" --query "Functions[].FunctionName" --output text); do
      echo "=== $region / $func ==="
      aws lambda get-policy --function-name "$func" --region "$region" 2>/dev/null | jq '.Policy | fromjson'
    done
  done

Step 6: Download function code for offline analysis (if permitted):
  aws lambda get-function --function-name <function-name> --region <region> --query "Code.Location" --output text

Step 7: Run CloudFox Lambda enumeration:
  cloudfox aws --profile <profile> lambdas

Flag: Lambda functions with hardcoded secrets or API keys in environment variables, functions with overly permissive IAM execution roles (e.g., AdministratorAccess), functions invokable cross-account via resource policy, functions running deprecated runtimes, or functions in VPCs with access to sensitive subnets.

------------------------------------------
Procedure 4 — Enumerate RDS Instances, Snapshots, and Parameter Groups
Tools: aws cli
Intrusiveness: passive
Description: Discovers all RDS database instances, their accessibility settings, snapshots (which may be publicly shared), and parameter groups. Publicly accessible RDS instances and shared snapshots are critical findings.

Step 1: List all RDS instances across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws rds describe-db-instances --region "$region" \
      --query "DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,EngineVersion:EngineVersion,Class:DBInstanceClass,PublicAccess:PubliclyAccessible,Endpoint:Endpoint.Address,Port:Endpoint.Port,VpcId:DBSubnetGroup.VpcId,StorageEncrypted:StorageEncrypted,MultiAZ:MultiAZ}" \
      --output table
  done

Step 2: Identify publicly accessible RDS instances:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    aws rds describe-db-instances --region "$region" \
      --query "DBInstances[?PubliclyAccessible==\`true\`].{ID:DBInstanceIdentifier,Engine:Engine,Endpoint:Endpoint.Address,Port:Endpoint.Port}" \
      --output table
  done

Step 3: List all RDS snapshots and check for public sharing:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws rds describe-db-snapshots --region "$region" \
      --query "DBSnapshots[].{SnapshotId:DBSnapshotIdentifier,DBInstance:DBInstanceIdentifier,Engine:Engine,Status:Status,Encrypted:Encrypted,SnapshotCreateTime:SnapshotCreateTime}" \
      --output table
  done

Step 4: Check each snapshot for public sharing (critical finding):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for snap in $(aws rds describe-db-snapshots --region "$region" --query "DBSnapshots[].DBSnapshotIdentifier" --output text); do
      attrs=$(aws rds describe-db-snapshot-attributes --db-snapshot-identifier "$snap" --region "$region" \
        --query "DBSnapshotAttributesResult.DBSnapshotAttributes[?AttributeName=='restore'].AttributeValues[]" --output text 2>/dev/null)
      if [ "$attrs" = "all" ]; then
        echo "PUBLIC SNAPSHOT: $snap in $region"
      fi
    done
  done

Step 5: List RDS parameter groups (may reveal non-default security settings):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    aws rds describe-db-parameter-groups --region "$region" --output table
  done

Step 6: List RDS cluster instances (Aurora):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    aws rds describe-db-clusters --region "$region" \
      --query "DBClusters[].{ClusterID:DBClusterIdentifier,Engine:Engine,Endpoint:Endpoint,ReaderEndpoint:ReaderEndpoint,StorageEncrypted:StorageEncrypted}" \
      --output table 2>/dev/null
  done

Flag: Publicly accessible RDS instances, publicly shared RDS snapshots (restore attribute = "all"), unencrypted RDS instances or snapshots, RDS instances using default parameter groups, or instances with IAM authentication disabled.

------------------------------------------
Procedure 5 — Enumerate Secrets Manager Secrets (Names + Access Test)
Tools: aws cli, CloudFox
Intrusiveness: low
Description: Discovers all AWS Secrets Manager secrets and tests whether the current credentials can retrieve their values. Secrets Manager often stores database passwords, API keys, and other high-value credentials that enable lateral movement.

Step 1: List all Secrets Manager secrets across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws secretsmanager list-secrets --region "$region" \
      --query "SecretList[].{Name:Name,ARN:ARN,Description:Description,LastAccessed:LastAccessedDate,LastRotated:LastRotatedDate,RotationEnabled:RotationEnabled}" \
      --output table
  done

Step 2: Attempt to retrieve the value of each secret (access test):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for secret in $(aws secretsmanager list-secrets --region "$region" --query "SecretList[].Name" --output text); do
      echo "=== $region / $secret ==="
      aws secretsmanager get-secret-value --secret-id "$secret" --region "$region" 2>&1 | head -5
    done
  done

Step 3: Check the resource policy on each secret (look for cross-account or public access):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for secret_arn in $(aws secretsmanager list-secrets --region "$region" --query "SecretList[].ARN" --output text); do
      echo "=== $secret_arn ==="
      aws secretsmanager get-resource-policy --secret-id "$secret_arn" --region "$region" 2>/dev/null
    done
  done

Step 4: Identify secrets without rotation enabled:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    aws secretsmanager list-secrets --region "$region" \
      --query "SecretList[?RotationEnabled!=\`true\`].{Name:Name,LastRotated:LastRotatedDate}" \
      --output table
  done

Step 5: Run CloudFox secrets enumeration:
  cloudfox aws --profile <profile> secrets

Flag: Secrets whose values are retrievable with the current credentials, secrets with overly permissive resource policies (cross-account or wildcard principal), secrets without rotation enabled, or secrets with names suggesting high-value targets (e.g., containing "prod", "admin", "root", "master", "rds", "api-key").

------------------------------------------
Procedure 6 — Enumerate SSM Parameter Store Keys (Names + Access Test)
Tools: aws cli, CloudFox
Intrusiveness: low
Description: Discovers all SSM Parameter Store parameters and tests access to their values. Parameter Store is frequently used as a lightweight secrets store and often contains credentials, connection strings, and configuration data in plaintext (non-SecureString).

Step 1: List all SSM parameters across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws ssm describe-parameters --region "$region" \
      --query "Parameters[].{Name:Name,Type:Type,Tier:Tier,Version:Version,LastModified:LastModifiedDate}" \
      --output table
  done

Step 2: Identify parameters stored as plaintext String (not SecureString):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    aws ssm describe-parameters --region "$region" \
      --query "Parameters[?Type=='String'].{Name:Name,Type:Type}" \
      --output table
  done

Step 3: Attempt to retrieve parameter values (access test — includes decryption for SecureString):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for param in $(aws ssm describe-parameters --region "$region" --query "Parameters[].Name" --output text); do
      echo "=== $region / $param ==="
      aws ssm get-parameter --name "$param" --with-decryption --region "$region" 2>&1 | head -5
    done
  done

Step 4: Retrieve parameters by path (commonly organized hierarchically):
  aws ssm get-parameters-by-path --path "/" --recursive --with-decryption --region <region> --output json 2>&1

Step 5: Run CloudFox for parameter discovery:
  cloudfox aws --profile <profile> env-vars

Flag: Parameters retrievable by the current credentials (especially SecureString parameters successfully decrypted), parameters stored as plaintext String that contain credentials or connection strings, or parameters with names suggesting secrets (e.g., containing "password", "key", "token", "secret", "connection").

------------------------------------------
Procedure 7 — Enumerate KMS Keys and Grants
Tools: aws cli
Intrusiveness: passive
Description: Discovers all KMS customer-managed keys, their policies, grants, and rotation status. KMS keys control access to encrypted data across the account. Overly permissive key policies or grants can allow unauthorized decryption.

Step 1: List all KMS keys across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws kms list-keys --region "$region" --query "Keys[].KeyId" --output text
  done

Step 2: Describe each key to get metadata and identify customer-managed keys:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for key in $(aws kms list-keys --region "$region" --query "Keys[].KeyId" --output text); do
      aws kms describe-key --key-id "$key" --region "$region" \
        --query "KeyMetadata.{KeyId:KeyId,Description:Description,KeyManager:KeyManager,KeyState:KeyState,Origin:Origin,RotationStatus:KeyRotationStatus}" \
        --output table 2>/dev/null
    done
  done

Step 3: Retrieve key policies for customer-managed keys (check for overly permissive access):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for key in $(aws kms list-keys --region "$region" --query "Keys[].KeyId" --output text); do
      manager=$(aws kms describe-key --key-id "$key" --region "$region" --query "KeyMetadata.KeyManager" --output text 2>/dev/null)
      if [ "$manager" = "CUSTOMER" ]; then
        echo "=== $region / $key ==="
        aws kms get-key-policy --key-id "$key" --policy-name default --region "$region" --output text 2>/dev/null | jq .
      fi
    done
  done

Step 4: List grants on each key (grants can provide access beyond the key policy):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for key in $(aws kms list-keys --region "$region" --query "Keys[].KeyId" --output text); do
      grants=$(aws kms list-grants --key-id "$key" --region "$region" --query "Grants" --output json 2>/dev/null)
      if [ "$grants" != "[]" ] && [ -n "$grants" ]; then
        echo "=== $region / $key ==="
        echo "$grants" | jq .
      fi
    done
  done

Step 5: Check key rotation status for customer-managed keys:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for key in $(aws kms list-keys --region "$region" --query "Keys[].KeyId" --output text); do
      manager=$(aws kms describe-key --key-id "$key" --region "$region" --query "KeyMetadata.KeyManager" --output text 2>/dev/null)
      if [ "$manager" = "CUSTOMER" ]; then
        echo "=== $key ==="
        aws kms get-key-rotation-status --key-id "$key" --region "$region" 2>/dev/null
      fi
    done
  done

Step 6: List aliases to identify key purposes:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    aws kms list-aliases --region "$region" \
      --query "Aliases[].{AliasName:AliasName,TargetKeyId:TargetKeyId}" --output table
  done

Flag: Customer-managed KMS keys with overly permissive key policies (Principal "*" or cross-account access without conditions), keys with grants to unexpected principals, keys without rotation enabled, or disabled/scheduled-for-deletion keys that may indicate insufficient key lifecycle management.

------------------------------------------
Procedure 8 — Enumerate CloudFormation Stacks and Outputs
Tools: aws cli, CloudFox
Intrusiveness: passive
Description: Discovers all CloudFormation stacks, their parameters (which may contain secrets passed at deploy time), outputs (which often expose endpoints, ARNs, and credentials), and exported values. CloudFormation is a goldmine for understanding infrastructure architecture and finding hardcoded secrets.

Step 1: List all CloudFormation stacks across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws cloudformation list-stacks --region "$region" \
      --query "StackSummaries[?StackStatus!='DELETE_COMPLETE'].{Name:StackName,Status:StackStatus,Created:CreationTime,Updated:LastUpdatedTime}" \
      --output table
  done

Step 2: Describe each stack to retrieve parameters and outputs:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for stack in $(aws cloudformation list-stacks --region "$region" \
      --query "StackSummaries[?StackStatus!='DELETE_COMPLETE'].StackName" --output text); do
      echo "=== $region / $stack ==="
      aws cloudformation describe-stacks --stack-name "$stack" --region "$region" \
        --query "Stacks[0].{Parameters:Parameters,Outputs:Outputs}" --output json
    done
  done

Step 3: Check for parameters that were not marked NoEcho (potential secret leakage):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for stack in $(aws cloudformation list-stacks --region "$region" \
      --query "StackSummaries[?StackStatus!='DELETE_COMPLETE'].StackName" --output text); do
      aws cloudformation describe-stacks --stack-name "$stack" --region "$region" \
        --query "Stacks[0].Parameters[?ParameterValue!='****']" --output json 2>/dev/null
    done
  done

Step 4: List CloudFormation exports (cross-stack references that expose resource identifiers):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws cloudformation list-exports --region "$region" --output table
  done

Step 5: Retrieve the template body for interesting stacks (full infrastructure-as-code review):
  aws cloudformation get-template --stack-name <stack-name> --region <region> --output json

Step 6: Run CloudFox for stack output analysis:
  cloudfox aws --profile <profile> outputs

Flag: Stack parameters containing plaintext secrets (not marked NoEcho), stack outputs exposing credentials, API keys, or database connection strings, exported values revealing internal architecture, or templates with hardcoded secrets.

------------------------------------------
Procedure 9 — Enumerate CodeBuild Projects and CodePipeline Pipelines
Tools: aws cli
Intrusiveness: passive
Description: Discovers all CodeBuild projects and CodePipeline pipelines. CI/CD pipelines frequently contain credentials in environment variables, have overly permissive IAM service roles, and provide paths to source code repositories.

Step 1: List all CodeBuild projects across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws codebuild list-projects --region "$region" --output text
  done

Step 2: Describe each CodeBuild project to extract environment variables and service role:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for project in $(aws codebuild list-projects --region "$region" --output text); do
      echo "=== $region / $project ==="
      aws codebuild batch-get-projects --names "$project" --region "$region" \
        --query "projects[0].{Name:name,ServiceRole:serviceRole,Source:source,Environment:environment}" \
        --output json
    done
  done

Step 3: Check CodeBuild environment variables for plaintext secrets:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for project in $(aws codebuild list-projects --region "$region" --output text); do
      aws codebuild batch-get-projects --names "$project" --region "$region" \
        --query "projects[0].environment.environmentVariables[?type=='PLAINTEXT']" \
        --output json 2>/dev/null
    done
  done

Step 4: List all CodePipeline pipelines across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws codepipeline list-pipelines --region "$region" --output table
  done

Step 5: Describe each pipeline to understand stages and actions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for pipeline in $(aws codepipeline list-pipelines --region "$region" --query "pipelines[].name" --output text); do
      echo "=== $region / $pipeline ==="
      aws codepipeline get-pipeline --name "$pipeline" --region "$region" --output json
    done
  done

Step 6: Check CodeBuild build history for credential leakage in logs:
  aws codebuild list-builds-for-project --project-name <project> --region <region> --max-items 5 --output text
  aws codebuild batch-get-builds --ids <build-id> --region <region> --query "builds[0].logs" --output json

Flag: CodeBuild projects with plaintext credentials in environment variables, overly permissive service roles (e.g., AdministratorAccess), pipelines connected to source repositories containing secrets, or build logs accessible that may contain credentials.

------------------------------------------
Procedure 10 — Enumerate ECS Clusters and Task Definitions
Tools: aws cli, CloudFox
Intrusiveness: passive
Description: Discovers all ECS clusters, services, running tasks, and task definitions. Task definitions may contain environment variables with hardcoded secrets, IAM task roles for privilege escalation, and container images from private registries.

Step 1: List all ECS clusters across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws ecs list-clusters --region "$region" --query "clusterArns[]" --output text
  done

Step 2: Describe each cluster:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    clusters=$(aws ecs list-clusters --region "$region" --query "clusterArns[]" --output text)
    if [ -n "$clusters" ]; then
      aws ecs describe-clusters --clusters $clusters --region "$region" \
        --query "clusters[].{Name:clusterName,Status:status,RunningTasks:runningTasksCount,ActiveServices:activeServicesCount,ContainerInsights:settings}" \
        --output table
    fi
  done

Step 3: List services in each cluster:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for cluster in $(aws ecs list-clusters --region "$region" --query "clusterArns[]" --output text); do
      echo "=== $region / $cluster ==="
      aws ecs list-services --cluster "$cluster" --region "$region" --output text
    done
  done

Step 4: List all task definitions and retrieve their details (check for secrets in env vars):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for taskdef in $(aws ecs list-task-definitions --region "$region" --query "taskDefinitionArns[]" --output text); do
      echo "=== $taskdef ==="
      aws ecs describe-task-definition --task-definition "$taskdef" --region "$region" \
        --query "taskDefinition.{Family:family,TaskRoleArn:taskRoleArn,ExecutionRoleArn:executionRoleArn,Containers:containerDefinitions[].{Name:name,Image:image,Environment:environment,Secrets:secrets}}" \
        --output json
    done
  done

Step 5: List running tasks and identify their task roles:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for cluster in $(aws ecs list-clusters --region "$region" --query "clusterArns[]" --output text); do
      tasks=$(aws ecs list-tasks --cluster "$cluster" --region "$region" --query "taskArns[]" --output text)
      if [ -n "$tasks" ]; then
        aws ecs describe-tasks --cluster "$cluster" --tasks $tasks --region "$region" \
          --query "tasks[].{TaskArn:taskArn,TaskDefinition:taskDefinitionArn,LastStatus:lastStatus,Overrides:overrides}" \
          --output json
      fi
    done
  done

Step 6: Run CloudFox ECS enumeration:
  cloudfox aws --profile <profile> ecs-tasks

Flag: Task definitions with hardcoded credentials in environment variables (type PLAINTEXT instead of using Secrets Manager references), overly permissive task IAM roles, containers running as privileged, or task definitions referencing images from public registries in production.

------------------------------------------
Procedure 11 — Enumerate EKS Clusters
Tools: aws cli, CloudFox
Intrusiveness: passive
Description: Discovers all EKS (Elastic Kubernetes Service) clusters, their configurations, and access settings. EKS clusters may have publicly accessible API endpoints, overly permissive RBAC, or IRSA (IAM Roles for Service Accounts) misconfigurations.

Step 1: List all EKS clusters across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws eks list-clusters --region "$region" --query "clusters[]" --output text
  done

Step 2: Describe each cluster to get endpoint, access configuration, and logging:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for cluster in $(aws eks list-clusters --region "$region" --query "clusters[]" --output text); do
      echo "=== $region / $cluster ==="
      aws eks describe-cluster --name "$cluster" --region "$region" \
        --query "cluster.{Name:name,Endpoint:endpoint,Version:version,PlatformVersion:platformVersion,PublicAccess:resourcesVpcConfig.endpointPublicAccess,PrivateAccess:resourcesVpcConfig.endpointPrivateAccess,PublicCIDRs:resourcesVpcConfig.publicAccessCidrs,RoleArn:roleArn,Logging:logging,EncryptionConfig:encryptionConfig}" \
        --output json
    done
  done

Step 3: List node groups for each cluster:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for cluster in $(aws eks list-clusters --region "$region" --query "clusters[]" --output text); do
      echo "=== $region / $cluster ==="
      aws eks list-nodegroups --cluster-name "$cluster" --region "$region" --output text
    done
  done

Step 4: Describe node groups to identify instance types and IAM roles:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for cluster in $(aws eks list-clusters --region "$region" --query "clusters[]" --output text); do
      for ng in $(aws eks list-nodegroups --cluster-name "$cluster" --region "$region" --query "nodegroups[]" --output text); do
        aws eks describe-nodegroup --cluster-name "$cluster" --nodegroup-name "$ng" --region "$region" \
          --query "nodegroup.{NodegroupName:nodegroupName,InstanceTypes:instanceTypes,NodeRole:nodeRole,ScalingConfig:scalingConfig,AmiType:amiType}" \
          --output json
      done
    done
  done

Step 5: List Fargate profiles:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for cluster in $(aws eks list-clusters --region "$region" --query "clusters[]" --output text); do
      aws eks list-fargate-profiles --cluster-name "$cluster" --region "$region" --output text
    done
  done

Step 6: Check EKS access entries (newer access management):
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for cluster in $(aws eks list-clusters --region "$region" --query "clusters[]" --output text); do
      aws eks list-access-entries --cluster-name "$cluster" --region "$region" 2>/dev/null
    done
  done

Step 7: Attempt to update kubeconfig and access the cluster:
  aws eks update-kubeconfig --name <cluster-name> --region <region>
  kubectl get namespaces
  kubectl auth can-i --list

Step 8: Run CloudFox EKS enumeration:
  cloudfox aws --profile <profile> eks

Flag: EKS clusters with public API endpoint access enabled without CIDR restrictions (0.0.0.0/0), clusters without envelope encryption enabled, clusters with audit logging disabled, node group IAM roles with excessive permissions, or clusters where the current credentials can authenticate and have broad RBAC permissions.

------------------------------------------
Procedure 12 — Enumerate SageMaker Notebooks, Endpoints, and Models
Tools: aws cli
Intrusiveness: passive
Description: Discovers all SageMaker notebook instances, endpoints, training jobs, and models. SageMaker resources often have direct internet access, contain sensitive training data or model artifacts, and notebook instances may have IAM roles with broad permissions. Notebooks with root access and internet connectivity are high-value targets.

Step 1: List all SageMaker notebook instances across all regions:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws sagemaker list-notebook-instances --region "$region" \
      --query "NotebookInstances[].{Name:NotebookInstanceName,Status:NotebookInstanceStatus,InstanceType:InstanceType,DirectInternetAccess:DirectInternetAccess}" \
      --output table
  done

Step 2: Describe each notebook instance for detailed configuration:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for nb in $(aws sagemaker list-notebook-instances --region "$region" --query "NotebookInstances[].NotebookInstanceName" --output text); do
      echo "=== $region / $nb ==="
      aws sagemaker describe-notebook-instance --notebook-instance-name "$nb" --region "$region" \
        --query "{Name:NotebookInstanceName,Status:NotebookInstanceStatus,RoleArn:RoleArn,InstanceType:InstanceType,DirectInternetAccess:DirectInternetAccess,RootAccess:RootAccess,VolumeSize:VolumeSizeInGB,SubnetId:SubnetId,KmsKeyId:KmsKeyId}" \
        --output json
    done
  done

Step 3: List SageMaker endpoints:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws sagemaker list-endpoints --region "$region" \
      --query "Endpoints[].{Name:EndpointName,Status:EndpointStatus,Created:CreationTime}" \
      --output table
  done

Step 4: Describe each endpoint to identify the model and configuration:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    for ep in $(aws sagemaker list-endpoints --region "$region" --query "Endpoints[].EndpointName" --output text); do
      echo "=== $region / $ep ==="
      aws sagemaker describe-endpoint --endpoint-name "$ep" --region "$region" --output json
    done
  done

Step 5: List SageMaker models:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws sagemaker list-models --region "$region" \
      --query "Models[].{ModelName:ModelName,Created:CreationTime}" \
      --output table
  done

Step 6: List SageMaker training jobs:
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "=== $region ==="
    aws sagemaker list-training-jobs --region "$region" --max-results 20 \
      --query "TrainingJobSummaries[].{Name:TrainingJobName,Status:TrainingJobStatus,Created:CreationTime}" \
      --output table
  done

Step 7: Check for presigned notebook URLs (direct access to Jupyter):
  aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name <notebook-name> --region <region> 2>&1

Flag: Notebook instances with DirectInternetAccess enabled, notebooks with RootAccess enabled, notebook IAM roles with overly permissive policies, unencrypted notebook volumes (no KMS key), endpoints exposed without authentication, or the ability to generate presigned URLs to access Jupyter notebooks.

------------------------------------------
References:
- AWS CLI Command Reference: https://docs.aws.amazon.com/cli/latest/reference/
- AWS Resource Groups Tagging API: https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/
- CloudFox GitHub: https://github.com/BishopFox/cloudfox
- Prowler GitHub: https://github.com/prowler-cloud/prowler
- HackTricks Cloud — AWS Pentesting: https://cloud.hacktricks.xyz/pentesting-cloud/aws-pentesting
- Rhino Security Labs — AWS Pacu: https://github.com/RhinoSecurityLabs/pacu
- SANS Cloud Security — AWS Enumeration: https://www.sans.org/cloud-security/
- AWS Security Best Practices: https://docs.aws.amazon.com/security/
- AWS S3 Security: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html
- AWS EKS Security Best Practices: https://docs.aws.amazon.com/eks/latest/userguide/security.html
- AWS Lambda Security: https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html
- AWS KMS Key Policies: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- AWS Secrets Manager Best Practices: https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html
- AWS SageMaker Security: https://docs.aws.amazon.com/sagemaker/latest/dg/security.html
- CloudSplaining — AWS IAM Assessment: https://github.com/salesforce/cloudsplaining
