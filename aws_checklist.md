
## AWS-1 | Unauthenticated Testing

### AWS-1.1 | S3 Bucket Discovery
- [ ] 1.1.0 Enumerate S3 buckets via permutation wordlists (cloud_enum, s3recon, bucket_finder)
- [ ] 1.1.1 Test discovered buckets for public LIST access
- [ ] 1.1.2 Test discovered buckets for public GET access on objects
- [ ] 1.1.3 Test discovered buckets for public PUT / DELETE access
- [ ] 1.1.4 Search for sensitive files: `*.pem`, `*.key`, `credentials`, `backup`, `database`, `.env`
- [ ] 1.1.5 Check for public static website hosting with sensitive content
- [ ] 1.1.6 Identify misconfigured Access Points with public access

### AWS-1.2 | Public Endpoint Discovery
- [ ] 1.2.0 Identify AWS-hosted assets via DNS (CNAME to amazonaws.com, cloudfront.net, s3.amazonaws.com)
- [ ] 1.2.1 Enumerate public API Gateway endpoints (swagger / OpenAPI spec exposure)
- [ ] 1.2.2 Identify unauthenticated API Gateway routes (no authorizer, no auth header required)
- [ ] 1.2.3 Enumerate Lambda function URLs with AuthType=NONE
- [ ] 1.2.4 Enumerate public EC2 instances with open sensitive ports (22, 3389, 80, 443, 8080, 8443)
- [ ] 1.2.5 Identify internet-facing ELB / ALB / NLB without authentication
- [ ] 1.2.6 Test CloudFront distributions for direct S3 origin bypass (missing OAC/OAI)
- [ ] 1.2.7 Identify publicly accessible RDS / Redshift instances
- [ ] 1.2.8 Identify exposed ElastiCache / DocumentDB / OpenSearch endpoints
- [ ] 1.2.9 Identify dangling DNS records pointing to released resources (subdomain takeover)

### AWS-1.3 | Public Snapshot & Image Enumeration
- [ ] 1.3.0 Search for public EBS snapshots belonging to target account
- [ ] 1.3.1 Search for public AMIs owned by target account
- [ ] 1.3.2 Search for public RDS / Aurora snapshots
- [ ] 1.3.3 Search for public Redshift snapshots
- [ ] 1.3.4 Attempt to mount / launch discovered public snapshots in attacker account
- [ ] 1.3.5 Identify sensitive data within mounted snapshots (credentials, configs, DBs)

### AWS-1.4 | Exposed Credential Scanning
- [ ] 1.4.0 Search public code repositories (GitHub, GitLab, Bitbucket) for AWS keys, ARNs, account IDs
- [ ] 1.4.1 Run trufflehog / gitleaks against all discovered public repositories
- [ ] 1.4.2 Validate discovered AWS access keys via `aws sts get-caller-identity`
- [ ] 1.4.3 Enumerate permissions on validated keys (enumerate-iam)
- [ ] 1.4.4 Check for exposed Cognito app client IDs and secrets in JS bundles / source
- [ ] 1.4.5 Test Cognito user pools for self-registration and account enumeration
- [ ] 1.4.6 Check for exposed JWT tokens and test signing key attacks

---

## AWS-2 | Authenticated Enumeration

### AWS-2.1 | Credential Validation & Context
- [ ] 2.1.0 Validate credentials: `aws sts get-caller-identity`
- [ ] 2.1.1 Identify principal type: IAM user / role / federated / service account
- [ ] 2.1.2 Enumerate effective permissions (enumerate-iam, bf-aws-permissions, Pacu)
- [ ] 2.1.3 Determine execution context: EC2 instance profile / Lambda / ECS task / EKS pod
- [ ] 2.1.4 Check credential expiry (STS temporary credentials)
- [ ] 2.1.5 Identify SCPs or permission boundaries limiting current principal

### AWS-2.2 | Service & Resource Discovery
- [ ] 2.2.0 Enumerate all resource types across regions (CloudFox, `aws resourcegroupstaggingapi`)
- [ ] 2.2.1 Enumerate EC2 instances, security groups, VPCs, subnets
- [ ] 2.2.2 Enumerate S3 buckets and bucket policies
- [ ] 2.2.3 Enumerate Lambda functions, layers, event sources
- [ ] 2.2.4 Enumerate RDS instances, snapshots, parameter groups
- [ ] 2.2.5 Enumerate Secrets Manager secrets (names + access test)
- [ ] 2.2.6 Enumerate SSM Parameter Store keys (names + access test)
- [ ] 2.2.7 Enumerate KMS keys and grants
- [ ] 2.2.8 Enumerate CloudFormation stacks and outputs
- [ ] 2.2.9 Enumerate CodeBuild / CodePipeline
- [ ] 2.2.10 Enumerate ECS clusters and task definitions
- [ ] 2.2.11 Enumerate EKS clusters
- [ ] 2.2.12 Enumerate SageMaker notebooks, endpoints

### AWS-2.3 | Identity & Permission Mapping
- [ ] 2.3.0 Enumerate all IAM users, groups, roles
- [ ] 2.3.1 Enumerate attached policies (managed + inline) for current principal
- [ ] 2.3.2 Enumerate all assumable roles from current principal
- [ ] 2.3.3 Map Identity Center permission sets and account assignments
- [ ] 2.3.4 Enumerate SAML and OIDC identity providers
- [ ] 2.3.5 Enumerate Cognito user pools and identity pools
- [ ] 2.3.6 Generate PMapper graph for full escalation path visualization

---

## AWS-3 | IAM & Privilege Escalation

### AWS-3.1 | IAM Policy Analysis
- [ ] 3.1.0 Identify policies granting `Action:*` or `Resource:*`
- [ ] 3.1.1 Identify policies using `NotAction` or `NotResource`
- [ ] 3.1.2 Identify policies missing or with weak `Condition` blocks
- [ ] 3.1.3 Identify admin-equivalent custom managed policies
- [ ] 3.1.4 Identify policies allowing `iam:*` or `sts:*` broadly
- [ ] 3.1.5 Identify dormant users with active access keys
- [ ] 3.1.6 Identify unused high-privilege IAM roles
- [ ] 3.1.7 Identify roles with excessive `MaxSessionDuration`
- [ ] 3.1.8 Identify access keys older than rotation policy / multiple active keys per user
- [ ] 3.1.9 Run IAM Access Analyzer policy validation findings

### AWS-3.2 | Privilege Escalation — IAM Abuse
- [ ] 3.2.0 Attempt: `iam:CreateAccessKey` on other users to steal credentials
- [ ] 3.2.1 Attempt: `iam:CreateLoginProfile` / `UpdateLoginProfile` to gain console access
- [ ] 3.2.2 Attempt: `iam:AttachUserPolicy` / `AttachRolePolicy` / `AttachGroupPolicy` to attach AdministratorAccess
- [ ] 3.2.3 Attempt: `iam:PutUserPolicy` / `PutRolePolicy` for inline policy injection
- [ ] 3.2.4 Attempt: `iam:CreatePolicyVersion` / `SetDefaultPolicyVersion` to update policy to `*`
- [ ] 3.2.5 Attempt: `iam:AddUserToGroup` to add self to privileged group
- [ ] 3.2.6 Attempt: `iam:UpdateAssumeRolePolicy` to modify trust policy to allow self
- [ ] 3.2.7 Attempt: `iam:PassRole` + `ec2:RunInstances` to launch instance with privileged role
- [ ] 3.2.8 Attempt: `iam:PassRole` + `lambda:CreateFunction` + `InvokeFunction` for code execution as privileged role
- [ ] 3.2.9 Attempt: `iam:PassRole` + `cloudformation:CreateStack` for stack deployment as privileged role
- [ ] 3.2.10 Attempt: `iam:PassRole` + `glue:CreateDevEndpoint` via Glue endpoint as privileged role
- [ ] 3.2.11 Attempt: `iam:PassRole` + `sagemaker:CreateNotebookInstance` for SageMaker as privileged role
- [ ] 3.2.12 Attempt: `iam:PassRole` + `codebuild:CreateProject` + `StartBuild` to build as privileged role
- [ ] 3.2.13 Attempt: `iam:PassRole` + `ecs:RunTask` / `datapipeline` / `autoscaling`
- [ ] 3.2.14 Attempt: `lambda:UpdateFunctionCode` / `UpdateFunctionConfiguration` to modify existing Lambda
- [ ] 3.2.15 Attempt: `ssm:SendCommand` / `StartSession` for RCE on EC2 via privileged instance role
- [ ] 3.2.16 Attempt: resource policy modification (S3, KMS, Secrets Manager, Lambda) to grant self access

### AWS-3.3 | Role Trust & Federation Abuse
- [ ] 3.3.0 Identify roles with wildcard or `AWS:*` principals in trust policies
- [ ] 3.3.1 Identify roles with overly broad federated trust (`sub:*` / `aud:*` claims)
- [ ] 3.3.2 Attempt role assumption without `ExternalId` (confused deputy)
- [ ] 3.3.3 Test OIDC trust: forge claims via permissive `sub` conditions
- [ ] 3.3.4 Test GitHub Actions OIDC: overly broad `repo:*` trust conditions
- [ ] 3.3.5 Enumerate and attempt `sts:AssumeRole` on all discoverable roles
- [ ] 3.3.6 Identify cross-account role assumptions to pivot to other accounts
- [ ] 3.3.7 Map full role assumption chain depth (A to B to C to Admin)

### AWS-3.4 | SCP & Permission Boundary Analysis
- [ ] 3.4.0 Enumerate SCPs affecting in-scope accounts
- [ ] 3.4.1 Identify gaps: no root action deny, no region restriction, no CloudTrail protection
- [ ] 3.4.2 Identify accounts excluded from key organizational SCPs
- [ ] 3.4.3 Identify privileged principals lacking permission boundaries
- [ ] 3.4.4 Attempt actions missing from SCP deny list
- [ ] 3.4.5 Test permission boundary effectiveness via `NotAction` bypass attempts

---

## AWS-4 | Services Exploitation

### AWS-4.1 | IAM
- [ ] 4.1.0 Extract full policy documents for all attached policies
- [ ] 4.1.1 Identify admin-equivalent roles and users
- [ ] 4.1.2 Identify service-linked roles with unusual permissions
- [ ] 4.1.3 Map all principals capable of cross-account role assumption
- [ ] 4.1.4 Test `iam:SimulatePrincipalPolicy` for permission discovery

### AWS-4.2 | STS — Security Token Service
- [ ] 4.2.0 Enumerate all roles assumable by current principal
- [ ] 4.2.1 Attempt role assumption and credential capture
- [ ] 4.2.2 Test `sts:AssumeRoleWithWebIdentity` with controlled OIDC tokens
- [ ] 4.2.3 Test `sts:AssumeRoleWithSAML` with modified SAML assertions (if IdP accessible)
- [ ] 4.2.4 Identify roles with `sts:TagSession` allowing tag injection for bypass

### AWS-4.3 | KMS — Key Management Service
- [ ] 4.3.0 Enumerate CMKs and their key policies
- [ ] 4.3.1 Identify CMK policies allowing `kms:*` to broad or external principals
- [ ] 4.3.2 Attempt `kms:Decrypt` on accessible keys
- [ ] 4.3.3 Identify CMKs shared with external accounts via grants
- [ ] 4.3.4 Test ability to create new CMK grants to attacker-controlled principal
- [ ] 4.3.5 Test access to multi-region key replicas

### AWS-4.4 | Secrets Manager & SSM Parameter Store
- [ ] 4.4.0 Enumerate all accessible secrets (names + metadata)
- [ ] 4.4.1 Attempt `secretsmanager:GetSecretValue` on all enumerated secrets
- [ ] 4.4.2 Identify secrets with overly permissive resource policies
- [ ] 4.4.3 Attempt `ssm:GetParameter` / `GetParameters` on all enumerated parameters
- [ ] 4.4.4 Identify plaintext secrets in Lambda env vars, EC2 user-data, CloudFormation outputs
- [ ] 4.4.5 Identify plaintext secrets in CodeBuild / ECS task definitions

### AWS-4.5 | S3 — Simple Storage Service
- [ ] 4.5.0 Enumerate all accessible S3 buckets
- [ ] 4.5.1 Test bucket policies for Principal:* or cross-account access
- [ ] 4.5.2 Test for public ACLs (AllUsers / AuthenticatedUsers)
- [ ] 4.5.3 Attempt read access to identify sensitive files (PII, credentials, backups, configs)
- [ ] 4.5.4 Attempt write access (PUT object) on logging or deployment buckets
- [ ] 4.5.5 Test S3 Access Points for policy misconfigurations
- [ ] 4.5.6 Attempt to disable Block Public Access (if permissions allow)
- [ ] 4.5.7 Test cross-region replication targets for access

### AWS-4.6 | EC2 — Elastic Compute Cloud
- [ ] 4.6.0 Enumerate instances: state, instance profile, public IP, SG
- [ ] 4.6.1 Identify instances with overly permissive SGs (0.0.0.0/0 on 22, 3389, etc.)
- [ ] 4.6.2 Attempt SSH / RDP access on exposed instances (if credentials available)
- [ ] 4.6.3 Test IMDSv1 access on running instances (`curl http://169.254.169.254/latest/meta-data/`)
- [ ] 4.6.4 Enumerate IAM role credentials via IMDS
- [ ] 4.6.5 Review EC2 user-data for hardcoded secrets
- [ ] 4.6.6 Identify unencrypted EBS volumes and snapshots
- [ ] 4.6.7 Attempt to create snapshot of accessible EBS volumes for offline analysis
- [ ] 4.6.8 Identify instances with deprecated / EOL AMIs

### AWS-4.7 | Lambda
- [ ] 4.7.0 Enumerate Lambda functions: name, runtime, role, VPC, env vars
- [ ] 4.7.1 Attempt `lambda:GetFunction` to retrieve code package URL and download
- [ ] 4.7.2 Analyze Lambda code for hardcoded secrets and logic flaws
- [ ] 4.7.3 Identify plaintext secrets in Lambda environment variables
- [ ] 4.7.4 Attempt invocation of Lambda functions (direct + via function URL)
- [ ] 4.7.5 Test function URLs with AuthType=NONE
- [ ] 4.7.6 Identify functions with `Principal:*` in resource policies
- [ ] 4.7.7 Attempt `lambda:UpdateFunctionCode` to inject payload into existing function
- [ ] 4.7.8 Enumerate Lambda layers — check for supply chain risks
- [ ] 4.7.9 Assess execution role permissions for lateral movement

### AWS-4.8 | API Gateway
- [ ] 4.8.0 Enumerate REST, HTTP, WebSocket APIs
- [ ] 4.8.1 Map all routes — identify routes without authorizers
- [ ] 4.8.2 Test unauthenticated routes for sensitive functionality
- [ ] 4.8.3 Test for API key leakage (headers, source code, JS bundles)
- [ ] 4.8.4 Identify missing throttling / rate limiting
- [ ] 4.8.5 Identify public API stages without WAF
- [ ] 4.8.6 Review resource policies for cross-account or public access

### AWS-4.9 | RDS — Relational Database Service
- [ ] 4.9.0 Enumerate RDS / Aurora instances: accessibility, SG, encryption
- [ ] 4.9.1 Identify publicly accessible RDS instances
- [ ] 4.9.2 Attempt connection using credentials found in secrets / user-data
- [ ] 4.9.3 Enumerate and test RDS snapshots for public accessibility
- [ ] 4.9.4 Attempt to restore accessible snapshot in attacker-controlled account
- [ ] 4.9.5 Test IAM database authentication
- [ ] 4.9.6 Check master credentials in Secrets Manager and rotation status

### AWS-4.10 | DynamoDB
- [ ] 4.10.0 Enumerate DynamoDB tables
- [ ] 4.10.1 Attempt `dynamodb:Scan` / `GetItem` on accessible tables
- [ ] 4.10.2 Review resource-based policies for external principal access

### AWS-4.11 | ECS — Elastic Container Service
- [ ] 4.11.0 Enumerate ECS clusters, services, task definitions
- [ ] 4.11.1 Identify task definitions with `privileged=true`
- [ ] 4.11.2 Identify tasks using host network mode
- [ ] 4.11.3 Check for plaintext secrets in task definition environment variables
- [ ] 4.11.4 Assess task role permissions for lateral movement
- [ ] 4.11.5 Attempt ECS Exec into running containers
- [ ] 4.11.6 Check IMDS access from Fargate tasks (hop limit bypass attempt)

### AWS-4.12 | EKS — Elastic Kubernetes Service
- [ ] 4.12.0 Enumerate EKS clusters, node groups, add-ons
- [ ] 4.12.1 Test EKS API endpoint accessibility (public vs private, allowed CIDRs)
- [ ] 4.12.2 Enumerate `aws-auth` ConfigMap for overly permissive role bindings
- [ ] 4.12.3 Review IRSA / Pod Identity bindings for least privilege
- [ ] 4.12.4 Attempt `cluster-admin` escalation via RBAC misconfiguration
- [ ] 4.12.5 Test IMDS hop limit on worker nodes (pod to node role steal)
- [ ] 4.12.6 Test NetworkPolicy enforcement (pod-to-pod lateral movement)
- [ ] 4.12.7 Check for privileged pods, hostPath mounts, hostPID
- [ ] 4.12.8 Verify Pod Security Admission enforcement

### AWS-4.13 | ECR — Elastic Container Registry
- [ ] 4.13.0 Enumerate ECR repositories (public and private)
- [ ] 4.13.1 Pull images from accessible repositories — analyze for secrets and vulnerabilities
- [ ] 4.13.2 Review image scan results for critical CVEs
- [ ] 4.13.3 Test for ability to push modified image layers (supply chain attack)
- [ ] 4.13.4 Review cross-account repository policies

### AWS-4.14 | EFS / FSx
- [ ] 4.14.0 Enumerate EFS file systems and access points
- [ ] 4.14.1 Test EFS mount from accessible EC2 instances — review content
- [ ] 4.14.2 Review EFS file system policy for overly permissive access
- [ ] 4.14.3 Check EFS / FSx encryption at rest and in-transit enforcement

### AWS-4.15 | Elastic Beanstalk
- [ ] 4.15.0 Enumerate EB environments: platform version, instance profile, endpoint
- [ ] 4.15.1 Review instance profile permissions for lateral movement
- [ ] 4.15.2 Identify deprecated platform versions
- [ ] 4.15.3 Review environment variables for hardcoded secrets

### AWS-4.16 | CodeBuild / CodePipeline / CI-CD
- [ ] 4.16.0 Enumerate CodeBuild projects: service role, VPC, privilegedMode
- [ ] 4.16.1 Identify projects with `privilegedMode=true` (Docker socket access)
- [ ] 4.16.2 Enumerate environment variables for plaintext secrets
- [ ] 4.16.3 Assess CodeBuild service role — attempt escalation via triggered build
- [ ] 4.16.4 Enumerate CodeArtifact domain and repository policies
- [ ] 4.16.5 Review pipeline artifact S3 bucket access
- [ ] 4.16.6 Identify CI/CD using long-lived IAM user keys (vs OIDC)
- [ ] 4.16.7 Test OIDC trust conditions for overly broad `sub` claims

### AWS-4.17 | CloudFormation
- [ ] 4.17.0 Enumerate stacks and outputs
- [ ] 4.17.1 Identify outputs exposing sensitive data (passwords, keys, ARNs)
- [ ] 4.17.2 Review stack IAM capabilities (CAPABILITY_NAMED_IAM)
- [ ] 4.17.3 Identify StackSets with overly permissive administration roles
- [ ] 4.17.4 Check template S3 bucket for public access

### AWS-4.18 | SQS — Simple Queue Service
- [ ] 4.18.0 Enumerate SQS queues
- [ ] 4.18.1 Identify queues with public access in resource policy
- [ ] 4.18.2 Attempt to read messages from accessible queues
- [ ] 4.18.3 Attempt to inject messages into accessible queues (workflow manipulation)

### AWS-4.19 | SNS — Simple Notification Service
- [ ] 4.19.0 Enumerate SNS topics
- [ ] 4.19.1 Identify topics with public Subscribe / Publish access
- [ ] 4.19.2 Attempt to subscribe attacker endpoint to accessible topics
- [ ] 4.19.3 Attempt to publish messages to accessible topics

### AWS-4.20 | SSM — Systems Manager
- [ ] 4.20.0 Enumerate SSM managed instances
- [ ] 4.20.1 Attempt `ssm:SendCommand` on managed instances
- [ ] 4.20.2 Attempt `ssm:StartSession` for interactive shell
- [ ] 4.20.3 Enumerate SSM documents — identify shared / public documents with dangerous commands
- [ ] 4.20.4 Read SSM Parameter Store values

### AWS-4.21 | SageMaker / Bedrock / ML
- [ ] 4.21.0 Enumerate SageMaker notebooks, endpoints, training jobs
- [ ] 4.21.1 Identify notebooks with root access and internet access enabled
- [ ] 4.21.2 Review execution role permissions for lateral movement
- [ ] 4.21.3 Test IMDS access from SageMaker environments
- [ ] 4.21.4 Review Bedrock agent / knowledge base service role permissions
- [ ] 4.21.5 Test Glue dev endpoints for SSH key access and network exposure

### AWS-4.22 | Networking (VPC / SG / DNS)
- [ ] 4.22.0 Enumerate VPCs, subnets, route tables, internet gateways
- [ ] 4.22.1 Identify default VPCs in active use
- [ ] 4.22.2 Identify private subnets with default routes to IGW
- [ ] 4.22.3 Identify SGs with 0.0.0.0/0 on sensitive ports
- [ ] 4.22.4 Enumerate VPC peering connections — test lateral movement across peers
- [ ] 4.22.5 Enumerate Transit Gateway attachments — verify segmentation
- [ ] 4.22.6 Enumerate VPC endpoints — test endpoint policy restrictions
- [ ] 4.22.7 Identify services using public internet that should use VPC endpoints
- [ ] 4.22.8 Identify dangling DNS CNAME records (subdomain takeover)

### AWS-4.23 | Cognito
- [ ] 4.23.0 Enumerate user pools and identity pools
- [ ] 4.23.1 Test user pool for self-registration (open signup)
- [ ] 4.23.2 Test identity pool unauthenticated role permissions
- [ ] 4.23.3 Test identity pool authenticated role for over-privilege
- [ ] 4.23.4 Attempt JWT token forgery / algorithm confusion attacks
- [ ] 4.23.5 Test app client secret exposure and OAuth flow misconfigurations

### AWS-4.24 | Lightsail
- [ ] 4.24.0 Enumerate Lightsail instances and firewall rules
- [ ] 4.24.1 Identify publicly exposed instances with open sensitive ports
- [ ] 4.24.2 Enumerate Lightsail databases and snapshots for public access
- [ ] 4.24.3 Test IMDS access from Lightsail instances

---

## AWS-5 | Post-Exploitation

### AWS-5.1 | Persistence
- [ ] 5.1.0 [Document only unless approved] Create backdoor IAM user with access keys
- [ ] 5.1.1 [Document only unless approved] Modify role trust policy to add external account
- [ ] 5.1.2 [Document only unless approved] Add access key to existing high-privilege IAM user
- [ ] 5.1.3 [Document only unless approved] Deploy Lambda backdoor with persistent trigger (EventBridge)
- [ ] 5.1.4 [Document only unless approved] Inject malicious Lambda layer into existing functions
- [ ] 5.1.5 [Document only unless approved] Modify CloudFormation stack to recreate backdoor on drift
- [ ] 5.1.6 Identify GuardDuty trusted IP list — assess ability to add attacker IP

### AWS-5.2 | Lateral Movement
- [ ] 5.2.0 Pivot from EC2 instance role to enumerate and exploit permissions
- [ ] 5.2.1 Pivot from Lambda execution role to access other services
- [ ] 5.2.2 Pivot from ECS task role to secrets, S3, databases
- [ ] 5.2.3 Pivot from EKS pod via IRSA role to cloud resources
- [ ] 5.2.4 Pivot via `sts:AssumeRole` to other accounts in Organization
- [ ] 5.2.5 Pivot via cross-account resource policies (S3, KMS, Secrets Manager)
- [ ] 5.2.6 Pivot via VPC peering / Transit Gateway to other network segments
- [ ] 5.2.7 Pivot from management account via StackSet execution role to all member accounts
- [ ] 5.2.8 Pivot from CI/CD pipeline role to production accounts

### AWS-5.3 | Data Access & Exfiltration
- [ ] 5.3.0 Extract Secrets Manager credentials and attempt downstream access
- [ ] 5.3.1 Extract RDS / DynamoDB data using obtained credentials
- [ ] 5.3.2 Download sensitive S3 objects (PII, financial data, credentials, source code)
- [ ] 5.3.3 Extract KMS-encrypted data via `kms:Decrypt`
- [ ] 5.3.4 Download Lambda code packages (IP, business logic, embedded secrets)
- [ ] 5.3.5 Read CloudWatch Logs for secrets in application output / debug logs
- [ ] 5.3.6 Read EC2 user-data and IMDS for credentials
- [ ] 5.3.7 Extract data via RDS snapshot restoration to attacker account
- [ ] 5.3.8 Intercept SQS / SNS messages from accessible queues / topics

### AWS-5.4 | Defense Evasion
- [ ] 5.4.0 Verify CloudTrail coverage — identify blind spots (regions, data events)
- [ ] 5.4.1 [Document only unless approved] Test ability to disable / pause CloudTrail
- [ ] 5.4.2 [Document only unless approved] Test ability to modify CloudTrail S3 bucket policy
- [ ] 5.4.3 [Document only unless approved] Test ability to disable GuardDuty detectors
- [ ] 5.4.4 [Document only unless approved] Test ability to delete VPC Flow Logs
- [ ] 5.4.5 Identify CloudTrail data plane event logging gaps (S3, Lambda not enabled)
- [ ] 5.4.6 Identify console-only actions not captured by CloudTrail
- [ ] 5.4.7 Test use of legitimate AWS services as C2 channel (S3, SQS, SSM, DynamoDB)

### AWS-5.5 | Impact Scenarios (Document Only)
- [ ] 5.5.0 [Document blast radius — do NOT execute] Ability to delete S3 bucket contents
- [ ] 5.5.1 [Document blast radius — do NOT execute] Ability to terminate production EC2 instances
- [ ] 5.5.2 [Document blast radius — do NOT execute] Ability to delete RDS without backup
- [ ] 5.5.3 [Document blast radius — do NOT execute] Ability to delete / schedule deletion of KMS CMKs
- [ ] 5.5.4 [Document blast radius — do NOT execute] Ability to disable CloudTrail / GuardDuty / Security Hub
- [ ] 5.5.5 [Document blast radius — do NOT execute] Escalation to management account — blast radius is entire Organization
- [ ] 5.5.6 [Assess scenario — do NOT execute] Ransomware: re-encrypt S3 with attacker KMS key, delete originals
- [ ] 5.5.7 [Assess scenario — do NOT execute] Supply chain: push malicious code via CI/CD to production
- [ ] 5.5.8 [Assess scenario — do NOT execute] Crypto-mining: assess compute quota and deployment capability

---

## AWS-6 | Logging & Detection Gaps

### AWS-6.1 | CloudTrail
- [ ] 6.1.0 Verify multi-region trail exists per account
- [ ] 6.1.1 Verify log file integrity validation enabled
- [ ] 6.1.2 Verify CloudTrail S3 bucket has Block Public Access
- [ ] 6.1.3 Verify S3 / Lambda data events enabled where required
- [ ] 6.1.4 Verify CloudTrail-to-CloudWatch-Logs integration

### AWS-6.2 | GuardDuty & Security Hub
- [ ] 6.2.0 Verify GuardDuty enabled in all active regions
- [ ] 6.2.1 Verify organization-level auto-enroll
- [ ] 6.2.2 Verify EKS / S3 / Malware / RDS / Lambda protection plans
- [ ] 6.2.3 Verify Security Hub cross-region aggregation
- [ ] 6.2.4 Verify GuardDuty findings export to S3 / Security Hub

### AWS-6.3 | VPC Flow Logs & Monitoring
- [ ] 6.3.0 Verify VPC Flow Logs enabled on all VPCs
- [ ] 6.3.1 Verify Flow Logs cover ACCEPT and REJECT (or ALL)
- [ ] 6.3.2 Verify CloudWatch alarms: root usage, IAM changes, unauthorized API calls, console login without MFA


# APPENDIX A | Toolchain Reference

| Tool | Purpose | Phase |
|------|---------|-------|
| cloud_enum / s3recon | S3 bucket discovery | AWS-1 |
| trufflehog / gitleaks | Secret scanning in repos | AWS-1.4 |
| enumerate-iam | Permission enumeration from valid creds | AWS-2.1 |
| CloudFox | Attack surface mapping (secrets, endpoints, roles) | AWS-2.2 |
| PMapper | IAM privilege escalation graph | AWS-3 |
| CloudSplaining | IAM policy analysis report | AWS-3.1 |
| Pacu | AWS exploitation framework | AWS-3, AWS-4 |
| IAM Access Analyzer | External access findings | AWS-3.1 |
| Prowler | Config assessment + CIS/FSBP (optional) | OPT-2 |
| ScoutSuite | Multi-service config review (optional) | OPT-2 |
| Checkov / tfsec / cfn-nag | IaC static analysis | OPT |
