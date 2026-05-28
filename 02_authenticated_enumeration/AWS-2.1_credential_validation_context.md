Repeatability: per_account
Prerequisites: Valid AWS credentials (access key ID + secret access key, or STS temporary session token); AWS CLI v2 installed and configured; Python 3.8+ for tooling (enumerate-iam, Pacu, bf-aws-permissions)
Description: This methodology validates the authenticity and scope of AWS credentials obtained during an engagement. It determines the principal type (IAM user, assumed role, federated identity, or service-linked principal), enumerates effective permissions through brute-force API probing and policy analysis, identifies the execution context (EC2 instance profile, Lambda function, ECS task role, or EKS pod identity), checks credential expiry for STS temporary credentials, and maps Service Control Policies (SCPs) and IAM permission boundaries that constrain the current principal. Together these procedures establish the baseline understanding of what the credentials can do and where they are running — a prerequisite for all subsequent exploitation phases.
Tags: sts, credential-validation, permission-enumeration, execution-context, scp, permission-boundary, iam, enumeration, authenticated
Potential Severity: medium

------------------------------------------
Procedure 0 — Validate Credentials (STS GetCallerIdentity)
Tools: aws cli
Intrusiveness: passive
Description: Confirms that the configured AWS credentials are valid and retrieves the Account ID, ARN, and User ID of the calling principal. This is the first step in any authenticated engagement and cannot be blocked by IAM policies or SCPs, making it a reliable connectivity and validity check.

Step 1: Configure the credentials in the current shell session:
  export AWS_ACCESS_KEY_ID="AKIA..."
  export AWS_SECRET_ACCESS_KEY="..."
  export AWS_SESSION_TOKEN="..."   # only if STS temporary credentials

Step 2: Validate credentials by calling STS GetCallerIdentity:
  aws sts get-caller-identity

Step 3: Record the output fields:
  - Account: the 12-digit AWS account ID
  - Arn: the full ARN of the calling principal (e.g., arn:aws:iam::123456789012:user/pentest or arn:aws:sts::123456789012:assumed-role/RoleName/session)
  - UserId: the unique identifier (e.g., AIDA... for IAM users, AROA...:session for assumed roles)

Step 4: Verify the account ID matches the expected target scope. If a different account is returned, reassess engagement boundaries.

Step 5: (Optional) Confirm the AWS region defaults:
  aws configure get region
  aws ec2 describe-availability-zones --query "AvailabilityZones[0].RegionName" --output text

Flag: Credentials are VALID if get-caller-identity returns a 200 response with Account, Arn, and UserId. Flag as a finding if credentials belong to an unexpected account, or if the ARN reveals an overly privileged principal (e.g., root account, administrator role).

------------------------------------------
Procedure 1 — Identify Principal Type
Tools: aws cli
Intrusiveness: passive
Description: Determines whether the authenticated principal is an IAM user, an assumed IAM role, a federated identity (SAML/OIDC), or a service-linked role. The principal type dictates the enumeration path and available attack surface for privilege escalation.

Step 1: Parse the ARN returned by get-caller-identity to classify the principal type:
  CALLER_ARN=$(aws sts get-caller-identity --query "Arn" --output text)
  echo "$CALLER_ARN"

Step 2: Classify based on ARN pattern:
  - IAM User:           arn:aws:iam::<account>:user/<username>
  - IAM User (pathed):  arn:aws:iam::<account>:user/<path>/<username>
  - Assumed Role:       arn:aws:sts::<account>:assumed-role/<role-name>/<session-name>
  - Federated User:     arn:aws:sts::<account>:federated-user/<name>
  - Root Account:       arn:aws:iam::<account>:root
  - Service Role:       arn:aws:iam::<account>:role/aws-service-role/<service>/<role-name>

Step 3: If principal is an IAM User, retrieve user details:
  aws iam get-user
  aws iam list-user-tags --user-name <username>
  aws iam list-mfa-devices --user-name <username>

Step 4: If principal is an Assumed Role, extract the original role name and enumerate it:
  ROLE_NAME=$(echo "$CALLER_ARN" | cut -d'/' -f2)
  aws iam get-role --role-name "$ROLE_NAME"
  aws iam list-role-tags --role-name "$ROLE_NAME"

Step 5: If principal is a federated user, note the federation source (SAML provider, OIDC, or custom identity broker) from the session context.

Step 6: Check the UserId prefix for additional classification:
  - AIDA = IAM user
  - AROA = Role
  - ABIA = STS service bearer token
  - ASIA = STS temporary credentials (access key prefix)

Flag: Flag if the principal is the root account (critical misconfiguration). Flag if the principal is a service-linked role being used outside its intended service context. Note federated principals as they may indicate SSO/identity provider compromise vectors.

------------------------------------------
Procedure 2 — Enumerate Effective Permissions
Tools: enumerate-iam, bf-aws-permissions, Pacu, aws cli, CloudSplaining
Intrusiveness: medium
Description: Determines what API actions the current principal is authorized to perform by brute-force calling AWS APIs and analyzing attached IAM policies. This is a critical step that defines the attack surface available from the current credential set. Note that brute-force enumeration generates significant CloudTrail log volume.

Step 1: Run enumerate-iam to brute-force discover allowed API actions:
  git clone https://github.com/andresriancho/enumerate-iam.git
  cd enumerate-iam
  pip install -r requirements.txt
  python enumerate-iam.py --access-key "$AWS_ACCESS_KEY_ID" --secret-key "$AWS_SECRET_ACCESS_KEY" --session-token "$AWS_SESSION_TOKEN"

Step 2: Run bf-aws-permissions for a second-opinion brute-force enumeration:
  git clone https://github.com/carlospolop/bf-aws-permissions
  cd bf-aws-permissions
  python3 bf-aws-permissions.py --access-key "$AWS_ACCESS_KEY_ID" --secret-key "$AWS_SECRET_ACCESS_KEY" --session-token "$AWS_SESSION_TOKEN"

Step 3: Use Pacu to enumerate permissions through its built-in modules:
  pacu
  # Inside Pacu session:
  set_keys
  run iam__enum_permissions
  run iam__enum_users_roles_policies_groups
  whoami

Step 4: If iam:GetUserPolicy / iam:ListUserPolicies / iam:ListAttachedUserPolicies are allowed, enumerate inline and managed policies directly:
  # For IAM Users:
  aws iam list-user-policies --user-name <username>
  aws iam list-attached-user-policies --user-name <username>
  aws iam get-user-policy --user-name <username> --policy-name <policy>

  # For IAM Roles:
  aws iam list-role-policies --role-name <role-name>
  aws iam list-attached-role-policies --role-name <role-name>
  aws iam get-role-policy --role-name <role-name> --policy-name <policy>

Step 5: Retrieve and inspect managed policy documents:
  aws iam get-policy --policy-arn <policy-arn>
  aws iam get-policy-version --policy-arn <policy-arn> --version-id <version>

Step 6: If the principal belongs to IAM groups, enumerate group policies:
  aws iam list-groups-for-user --user-name <username>
  aws iam list-group-policies --group-name <group>
  aws iam list-attached-group-policies --group-name <group>
  aws iam get-group-policy --group-name <group> --policy-name <policy>

Step 7: Use the IAM Policy Simulator to test specific actions without actually calling them:
  aws iam simulate-principal-policy \
    --policy-source-arn <principal-arn> \
    --action-names s3:GetObject ec2:RunInstances iam:CreateUser sts:AssumeRole lambda:InvokeFunction \
    --output table

Step 8: Run CloudSplaining to identify overly permissive policies:
  cloudsplaining download --profile <profile>
  cloudsplaining scan --input-file <account-authorization-details.json> --output <output-dir>

Step 9: Save the full list of confirmed allowed actions for use in subsequent attack planning.

Flag: Flag if the principal has wildcard permissions (Action: "*"), administrative policies (AdministratorAccess, PowerUserAccess), or sensitive permissions such as iam:PassRole, iam:CreatePolicyVersion, iam:AttachUserPolicy, iam:PutUserPolicy, sts:AssumeRole on broad resources, lambda:CreateFunction + iam:PassRole, ec2:RunInstances + iam:PassRole, or any data exfiltration permissions (s3:GetObject on *, dynamodb:Scan, etc.).

------------------------------------------
Procedure 3 — Determine Execution Context
Tools: aws cli, curl, CloudFox
Intrusiveness: passive
Description: Identifies where the credentials are being executed from — whether they originate from an EC2 instance profile, a Lambda function execution role, an ECS task role, or an EKS pod identity. The execution context reveals lateral movement opportunities and additional metadata endpoints that may leak sensitive information.

Step 1: Check if running on an EC2 instance by querying the Instance Metadata Service (IMDSv1):
  curl -s --max-time 2 http://169.254.169.254/latest/meta-data/
  curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/
  curl -s --max-time 2 http://169.254.169.254/latest/meta-data/instance-id
  curl -s --max-time 2 http://169.254.169.254/latest/meta-data/local-ipv4

Step 2: Check IMDSv2 (token-based):
  TOKEN=$(curl -s --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data

Step 3: Check if running inside AWS Lambda by inspecting environment variables:
  echo "$AWS_LAMBDA_FUNCTION_NAME"
  echo "$AWS_LAMBDA_FUNCTION_VERSION"
  echo "$AWS_EXECUTION_ENV"
  echo "$_HANDLER"
  echo "$AWS_LAMBDA_RUNTIME_API"
  env | grep -i lambda
  env | grep -i AWS_

Step 4: Check if running as an ECS task by querying the ECS task metadata endpoint:
  curl -s --max-time 2 "${ECS_CONTAINER_METADATA_URI_V4}/task"
  curl -s --max-time 2 "${ECS_CONTAINER_METADATA_URI_V4}"
  curl -s --max-time 2 http://169.254.170.2/v2/credentials/<relative-uri>

Step 5: Check if running inside an EKS pod by inspecting Kubernetes service account tokens and IRSA:
  echo "$AWS_ROLE_ARN"
  echo "$AWS_WEB_IDENTITY_TOKEN_FILE"
  cat "$AWS_WEB_IDENTITY_TOKEN_FILE" 2>/dev/null
  cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
  echo "$KUBERNETES_SERVICE_HOST"

Step 6: Use CloudFox to enumerate instance profiles and execution contexts across the account:
  cloudfox aws --profile <profile> instance-profiles
  cloudfox aws --profile <profile> env-vars
  cloudfox aws --profile <profile> role-trusts

Step 7: If on EC2, retrieve the full instance identity document:
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document

Step 8: Check for user-data scripts that may contain secrets or bootstrap configuration:
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data

Flag: Flag if credentials originate from an EC2 instance with IMDSv1 enabled (SSRF risk). Flag if Lambda environment variables contain hardcoded secrets. Flag if ECS task role has excessive permissions. Flag if EKS pod has IRSA configured with overly broad role trust policy. Flag if user-data contains plaintext credentials, API keys, or bootstrap secrets.

------------------------------------------
Procedure 4 — Check Credential Expiry (STS Temporary Credentials)
Tools: aws cli, Python/bash scripting
Intrusiveness: passive
Description: Determines the remaining lifetime of STS temporary credentials. Temporary credentials from AssumeRole, GetSessionToken, or GetFederationToken have a finite TTL (typically 1–12 hours). Understanding expiry is critical for time-sensitive exploitation and for determining if credentials can be refreshed.

Step 1: Identify if credentials are temporary by checking the access key prefix:
  echo "$AWS_ACCESS_KEY_ID"
  # AKIA prefix = long-term IAM user credentials (no expiry)
  # ASIA prefix = STS temporary credentials (have expiry)

Step 2: If on an EC2 instance, retrieve the credential expiry from the metadata service:
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  ROLE_NAME=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME
  # Note the "Expiration" field in the response (e.g., "2026-05-28T22:00:00Z")

Step 3: Calculate remaining time from the expiration timestamp:
  EXPIRY="2026-05-28T22:00:00Z"  # Replace with actual value
  EXPIRY_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$EXPIRY" +%s 2>/dev/null || date -d "$EXPIRY" +%s)
  NOW_EPOCH=$(date +%s)
  REMAINING=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 60 ))
  echo "Remaining: ${REMAINING} minutes"

Step 4: If credentials are from ECS task role, check the expiration from the task metadata:
  curl -s "${ECS_CONTAINER_METADATA_URI_V4}/task" | python3 -m json.tool
  # ECS task role credentials are typically refreshed automatically

Step 5: If credentials are from Lambda, note that Lambda execution role credentials have a session duration tied to the function timeout and are refreshed per invocation.

Step 6: Test if the credentials can be used to generate new STS tokens (self-renewal):
  aws sts get-session-token --duration-seconds 3600
  # If this succeeds, the principal can extend its session beyond the original expiry

Step 7: Attempt to assume the same role to refresh credentials (if applicable):
  ROLE_ARN=$(aws sts get-caller-identity --query "Arn" --output text | sed 's/:sts:/:iam:/;s/assumed-role/role/;s/\/[^/]*$//')
  aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "refresh" --duration-seconds 3600

Flag: Flag if long-term IAM user credentials (AKIA*) are in use — these do not expire and represent a persistent access risk. Flag if STS temporary credentials have more than 6 hours remaining. Flag if the principal can self-renew or re-assume its own role, enabling indefinite access. Flag if credential auto-refresh mechanisms are available (instance profile, ECS task role).

------------------------------------------
Procedure 5 — Identify SCPs and Permission Boundaries
Tools: aws cli, Pacu, PMapper, CloudSplaining, Prowler
Intrusiveness: low
Description: Identifies Service Control Policies (SCPs) applied at the AWS Organization level and IAM Permission Boundaries attached to the current principal. SCPs and permission boundaries act as guardrails that restrict the effective permissions even when IAM policies explicitly allow actions. Understanding these constraints is essential to avoid wasted effort on blocked attack paths.

Step 1: Check if the account is part of an AWS Organization:
  aws organizations describe-organization 2>&1
  # AccessDeniedException is expected if permissions are limited — note this and proceed

Step 2: If Organizations access is available, list SCPs applied to the account:
  ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
  aws organizations list-policies-for-target --target-id "$ACCOUNT_ID" --filter SERVICE_CONTROL_POLICY
  aws organizations list-policies --filter SERVICE_CONTROL_POLICY

Step 3: Retrieve individual SCP policy documents:
  aws organizations describe-policy --policy-id <policy-id>
  # Examine the "Content" field for Deny statements that restrict actions

Step 4: List SCPs at the OU (Organizational Unit) level:
  aws organizations list-parents --child-id "$ACCOUNT_ID"
  aws organizations list-policies-for-target --target-id <ou-id> --filter SERVICE_CONTROL_POLICY

Step 5: Check for Permission Boundaries on the current principal:
  # For IAM Users:
  aws iam get-user --user-name <username> --query "User.PermissionsBoundary"

  # For IAM Roles:
  aws iam get-role --role-name <role-name> --query "Role.PermissionsBoundary"

Step 6: If a Permission Boundary is attached, retrieve and analyze the boundary policy:
  aws iam get-policy --policy-arn <boundary-policy-arn>
  BOUNDARY_VERSION=$(aws iam get-policy --policy-arn <boundary-policy-arn> --query "Policy.DefaultVersionId" --output text)
  aws iam get-policy-version --policy-arn <boundary-policy-arn> --version-id "$BOUNDARY_VERSION" --query "PolicyVersion.Document"

Step 7: Use Pacu to check for SCPs and boundaries:
  # Inside Pacu:
  run iam__enum_permissions
  run organizations__enum

Step 8: Use PMapper to build a permission graph and identify effective permissions considering boundaries:
  pmapper graph create --profile <profile>
  pmapper query "who can do iam:CreateUser"
  pmapper visualize --filetype png

Step 9: Run Prowler checks for SCP and boundary analysis:
  prowler aws -c iam_policy_no_full_access_to_star -c iam_no_custom_policy_permissive_role_assumption --profile <profile>

Step 10: Run CloudSplaining for a comprehensive policy risk assessment:
  cloudsplaining download --profile <profile>
  cloudsplaining scan --input-file <authorization-details.json> --exclusions-file <exclusions.yaml>

Step 11: Compare the IAM policy permissions (from Procedure 2) against identified SCPs and permission boundaries to determine the TRUE effective permission set. Document any actions that appear allowed by IAM policy but are denied by SCPs or boundaries.

Flag: Flag if no SCPs are applied to the account (the account operates without organization-level guardrails). Flag if SCPs use an allow-list model but have overly broad Allow statements. Flag if no Permission Boundary is attached to a principal with elevated privileges. Flag if the Permission Boundary allows sensitive actions (iam:*, sts:AssumeRole, s3:*, etc.). Flag if SCPs do not restrict common persistence mechanisms (iam:CreateUser, iam:CreateAccessKey, iam:AttachUserPolicy). Flag if the effective permission set (after SCP/boundary intersection) still includes privilege escalation paths.

------------------------------------------
References:
- https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html
- https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- https://github.com/andresriancho/enumerate-iam
- https://github.com/carlospolop/bf-aws-permissions
- https://github.com/RhinoSecurityLabs/pacu
- https://github.com/nccgroup/PMapper
- https://github.com/salesforce/cloudsplaining
- https://github.com/BishopFox/cloudfox
- https://github.com/prowler-cloud/prowler
- https://cloud.hacktricks.wiki/pentesting-cloud/aws-security/aws-services/aws-sts-enum.html
- https://cloud.hacktricks.wiki/pentesting-cloud/aws-security/aws-services/aws-iam-enum.html
- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
