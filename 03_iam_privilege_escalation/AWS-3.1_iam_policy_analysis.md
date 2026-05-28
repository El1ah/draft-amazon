Repeatability: per_account
Prerequisites: Valid AWS credentials with IAM read permissions (iam:Get*, iam:List*, iam:GenerateCredentialReport, iam:GetCredentialReport, access-analyzer:ListAnalyzers, access-analyzer:ValidatePolicy)
Description: Static analysis of IAM policies, roles, users, and access keys to identify overprivileged configurations, dangerous policy elements, stale credentials, and misconfigurations that could facilitate privilege escalation. This category covers wildcard permissions, NotAction/NotResource abuse, missing conditions, admin-equivalent policies, broad IAM/STS grants, dormant users with active keys, unused high-privilege roles, excessive session durations, key rotation violations, and automated policy validation via IAM Access Analyzer.
Tags: iam, policy-analysis, overprivilege, access-keys, cloudsplaining, access-analyzer, notaction, wildcard, privilege-escalation, static-analysis
Potential Severity: high

------------------------------------------
Procedure 0 — Identify policies granting Action:* or Resource:*
Tools: aws cli, CloudSplaining, Prowler, jq
Intrusiveness: passive
Description: Detects IAM policies that use wildcard (*) in the Action or Resource field. Policies with "Action": "*" or "Resource": "*" (especially combined as "Action": "*", "Resource": "*") grant unrestricted access and represent the most dangerous overprivilege pattern in AWS. Even a single statement with Action:* on Resource:* is equivalent to full administrator access.

Step 1: List all customer-managed policies and retrieve their default version documents:
```
aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn,DefaultVersionId]' --output text | while read name arn vid; do
  echo "=== $name ($arn) ==="
  aws iam get-policy-version --policy-arn "$arn" --version-id "$vid" --query 'PolicyVersion.Document' --output json
done
```

Step 2: Check AWS-managed policies attached to users, groups, and roles for wildcards:
```
for arn in $(aws iam list-policies --only-attached --query 'Policies[*].Arn' --output text); do
  vid=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text)
  doc=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$vid" --query 'PolicyVersion.Document' --output json)
  if echo "$doc" | grep -qE '"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"'; then
    echo "[!] WILDCARD FOUND: $arn"
    echo "$doc" | jq '.Statement[] | select(.Action == "*" or .Resource == "*")'
  fi
done
```

Step 3: Check inline policies on all users:
```
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  for pol in $(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text); do
    echo "=== Inline: $user / $pol ==="
    aws iam get-user-policy --user-name "$user" --policy-name "$pol" --query 'PolicyDocument' --output json | jq '.Statement[] | select(.Action == "*" or .Resource == "*")'
  done
done
```

Step 4: Check inline policies on all roles:
```
for role in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  for pol in $(aws iam list-role-policies --role-name "$role" --query 'PolicyNames' --output text); do
    echo "=== Inline: $role / $pol ==="
    aws iam get-role-policy --role-name "$role" --policy-name "$pol" --query 'PolicyDocument' --output json | jq '.Statement[] | select(.Action == "*" or .Resource == "*")'
  done
done
```

Step 5: Run CloudSplaining to generate a comprehensive report of wildcard policies:
```
aws iam get-account-authorization-details > account-auth-details.json
cloudsplaining scan --input-file account-auth-details.json --output cloudsplaining-results
```

Step 6: Run Prowler check for wildcard policies:
```
prowler aws -c iam_policy_no_statements_with_admin_access iam_policy_no_statements_with_full_access --output-modes json
```

Flag: Any policy statement containing "Action": "*" or "Resource": "*" in an Allow statement, especially when both are wildcards simultaneously, constitutes a finding. Pay special attention to customer-managed policies and inline policies, as these are directly controlled by the account owner.

------------------------------------------
Procedure 1 — Identify policies using NotAction or NotResource
Tools: aws cli, jq, CloudSplaining
Intrusiveness: passive
Description: Detects IAM policies that use NotAction or NotResource elements. These inverse logic elements are frequently misunderstood and can inadvertently grant far broader permissions than intended. A policy with "Effect": "Allow" and "NotAction": ["s3:*"] effectively grants every other AWS service action. Attackers specifically look for these patterns as privilege escalation vectors.

Step 1: Retrieve all customer-managed policy documents and search for NotAction/NotResource:
```
aws iam get-account-authorization-details --output json > account-auth-details.json
cat account-auth-details.json | jq -r '
  [.UserDetailList[].UserPolicyList[]?,
   .GroupDetailList[].GroupPolicyList[]?,
   .RoleDetailList[].RolePolicyList[]?] |
  .[] | select(.PolicyDocument.Statement[]? | has("NotAction") or has("NotResource")) |
  .PolicyName
' 2>/dev/null
```

Step 2: Search managed policies for NotAction/NotResource:
```
cat account-auth-details.json | jq -r '
  .Policies[] |
  select(.PolicyVersionList[].Document.Statement[]? | has("NotAction") or has("NotResource")) |
  "\(.PolicyName) (\(.Arn))"
' 2>/dev/null
```

Step 3: For each identified policy, extract and review the specific statements using NotAction/NotResource:
```
POLICY_ARN="<identified_arn>"
VID=$(aws iam get-policy --policy-arn "$POLICY_ARN" --query 'Policy.DefaultVersionId' --output text)
aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$VID" --query 'PolicyVersion.Document' --output json | \
  jq '.Statement[] | select(has("NotAction") or has("NotResource"))'
```

Step 4: Identify the effective permissions granted by NotAction Allow statements — determine what is NOT excluded:
```
# For a policy with NotAction: ["s3:*", "ec2:*"], the policy allows ALL actions EXCEPT s3 and ec2.
# Manually review excluded services and assess what remains accessible.
```

Step 5: Run CloudSplaining which flags NotAction/NotResource misuse:
```
cloudsplaining scan --input-file account-auth-details.json --output cloudsplaining-results
cat cloudsplaining-results/*.json | jq '.[] | select(.NotAction or .NotResource)'
```

Flag: Any Allow statement using NotAction or NotResource is a finding. This is especially critical when NotAction is paired with "Resource": "*" and "Effect": "Allow", as it grants permissions to all services not explicitly excluded. Deny statements with NotAction are acceptable if properly scoped but should still be reviewed.

------------------------------------------
Procedure 2 — Identify policies missing or with weak Condition blocks
Tools: aws cli, jq, Prowler, Parliament
Intrusiveness: passive
Description: Detects IAM policies that lack Condition blocks or use weak/ineffective conditions. Conditions are the primary mechanism for restricting when a policy applies (e.g., source IP, MFA, time-of-day, source VPC). Policies granting sensitive permissions without conditions can be exploited from any context, including compromised credentials used from attacker infrastructure.

Step 1: Extract all Allow statements from managed policies that have no Condition block:
```
aws iam get-account-authorization-details --output json > account-auth-details.json
cat account-auth-details.json | jq '
  .Policies[] |
  {PolicyName: .PolicyName, Arn: .Arn,
   UnconditionedStatements: [.PolicyVersionList[0].Document.Statement[] |
     select(.Effect == "Allow" and (has("Condition") | not))]} |
  select(.UnconditionedStatements | length > 0)
'
```

Step 2: Identify high-risk unconditioned statements (actions that should always require conditions):
```
SENSITIVE_PATTERNS='iam:|sts:AssumeRole|s3:DeleteBucket|ec2:RunInstances|lambda:CreateFunction|organizations:'
cat account-auth-details.json | jq -r '
  .Policies[] |
  .PolicyVersionList[0].Document.Statement[] |
  select(.Effect == "Allow" and (has("Condition") | not)) |
  select(.Action | tostring | test("iam:|sts:|s3:Delete|ec2:Run|lambda:Create|organizations:")) |
  {Action, Resource}
'
```

Step 3: Check for weak conditions that can be bypassed — e.g., aws:SourceIp with overly broad CIDR:
```
cat account-auth-details.json | jq '
  [.. | .Condition? // empty] | flatten |
  map(select(.. | strings | test("0\\.0\\.0\\.0/0|::/0|10\\.0\\.0\\.0/8|172\\.16\\.0\\.0/12|192\\.168\\.0\\.0/16")))
'
```

Step 4: Verify MFA enforcement on sensitive operations:
```
cat account-auth-details.json | jq '
  .Policies[] |
  select(.PolicyVersionList[0].Document.Statement[] |
    select(.Effect == "Allow") |
    select(.Action | tostring | test("iam:Create|iam:Delete|iam:Put|iam:Attach")) |
    select((.Condition.Bool["aws:MultiFactorAuthPresent"] // "false") != "true"))
  | .PolicyName
'
```

Step 5: Use Parliament for automated policy linting:
```
pip install parliament
cat account-auth-details.json | jq -r '.Policies[].PolicyVersionList[0].Document' | while read -r doc; do
  echo "$doc" | parliament --string
done
```

Step 6: Run Prowler checks for MFA and condition enforcement:
```
prowler aws -c iam_root_mfa_enabled iam_user_mfa_enabled_console_access --output-modes json
```

Flag: Any Allow statement granting sensitive permissions (IAM write, STS assume, S3 delete, EC2 run, Lambda create, etc.) without a Condition block is a finding. Also flag conditions using overly broad CIDR ranges (0.0.0.0/0) or missing MFA requirements on destructive/administrative operations.

------------------------------------------
Procedure 3 — Identify admin-equivalent custom managed policies
Tools: aws cli, jq, CloudSplaining, PMapper, Prowler
Intrusiveness: passive
Description: Detects customer-managed policies that are functionally equivalent to AdministratorAccess even if they do not literally use "Action": "*". Combinations of high-privilege actions across services (e.g., iam:CreateUser + iam:AttachUserPolicy + sts:AssumeRole) can compose into full administrative access. These "shadow admin" policies are harder to detect than simple wildcards.

Step 1: Identify customer-managed policies with full admin ("*:*") access:
```
aws iam get-account-authorization-details --filter LocalManagedPolicy --output json | jq '
  .Policies[] |
  select(.PolicyVersionList[0].Document.Statement[] |
    select(.Effect == "Allow" and .Action == "*" and .Resource == "*")) |
  {PolicyName, Arn}
'
```

Step 2: Identify policies granting a high-privilege action set that composes into admin:
```
ADMIN_ACTIONS='iam:Create|iam:Attach|iam:Put|iam:AddUserToGroup|iam:UpdateAssumeRolePolicy|iam:SetDefaultPolicyVersion|iam:PassRole|lambda:CreateFunction|lambda:InvokeFunction|sts:AssumeRole|cloudformation:CreateStack|ec2:RunInstances|glue:CreateDevEndpoint|datapipeline:CreatePipeline|sagemaker:CreateNotebookInstance'
aws iam get-account-authorization-details --filter LocalManagedPolicy --output json | jq --arg pat "$ADMIN_ACTIONS" '
  .Policies[] |
  {PolicyName: .PolicyName, Arn: .Arn,
   HighPrivActions: [.PolicyVersionList[0].Document.Statement[] |
     select(.Effect == "Allow") |
     .Action | if type == "array" then .[] else . end |
     select(test($pat))]} |
  select(.HighPrivActions | length >= 3)
'
```

Step 3: Run CloudSplaining for a comprehensive privilege escalation analysis:
```
cloudsplaining scan --input-file account-auth-details.json --output cloudsplaining-results
cat cloudsplaining-results/iam-results-account.json | jq '.[] | select(.PrivilegeEscalation | length > 0)'
```

Step 4: Run PMapper to graph and identify admin-equivalent principals:
```
pmapper graph create
pmapper query "who can do Action:'*' with Resource:'*'"
pmapper visualize --filetype png
```

Step 5: List which users, groups, and roles have these admin-equivalent policies attached:
```
for arn in $(jq -r '.Arn' admin-equiv-policies.json); do
  echo "=== $arn ==="
  aws iam list-entities-for-policy --policy-arn "$arn" --query '{Users:PolicyUsers,Groups:PolicyGroups,Roles:PolicyRoles}' --output json
done
```

Step 6: Run Prowler check:
```
prowler aws -c iam_policy_no_statements_with_admin_access iam_no_custom_policy_permissive_role_assumption --output-modes json
```

Flag: Any customer-managed policy granting effective administrative access — either through literal wildcards or through a combination of privilege-escalation-capable actions (3 or more high-privilege actions from the list above) — is a finding. Flag any non-administrator user/role with such a policy attached.

------------------------------------------
Procedure 4 — Identify policies allowing iam:* or sts:* broadly
Tools: aws cli, jq, CloudSplaining, Prowler
Intrusiveness: passive
Description: Detects policies granting blanket iam:* or sts:* permissions. iam:* grants full control over the IAM service including creating users, attaching policies, and modifying trust relationships — effectively admin access. sts:* grants the ability to assume any role, get federation tokens, and impersonate any principal. Both represent critical overprivilege.

Step 1: Search all policies for iam:* or sts:* grants:
```
aws iam get-account-authorization-details --output json > account-auth-details.json
cat account-auth-details.json | jq '
  .Policies[] |
  select(.PolicyVersionList[0].Document.Statement[] |
    select(.Effect == "Allow") |
    (.Action // []) | if type == "string" then [.] else . end |
    any(. == "iam:*" or . == "sts:*")) |
  {PolicyName, Arn}
'
```

Step 2: Search inline policies across users, groups, and roles:
```
cat account-auth-details.json | jq '
  (.UserDetailList[] | {Type: "User", Name: .UserName,
    Policies: [.UserPolicyList[]? | select(.PolicyDocument.Statement[] |
      select(.Effect == "Allow") | .Action | tostring | test("\"iam:\\*\"|\"sts:\\*\""))]}) |
  select(.Policies | length > 0),
  (.RoleDetailList[] | {Type: "Role", Name: .RoleName,
    Policies: [.RolePolicyList[]? | select(.PolicyDocument.Statement[] |
      select(.Effect == "Allow") | .Action | tostring | test("\"iam:\\*\"|\"sts:\\*\""))]}) |
  select(.Policies | length > 0)
'
```

Step 3: Identify broad sts:AssumeRole grants without resource restriction:
```
cat account-auth-details.json | jq '
  .. | objects |
  select(.Effect? == "Allow") |
  select((.Action // []) | if type == "string" then [.] else . end |
    any(test("sts:AssumeRole|sts:\\*"))) |
  select((.Resource // []) | if type == "string" then [.] else . end |
    any(. == "*" or test("arn:aws:iam::\\*")))
'
```

Step 4: Determine which principals have these policies attached:
```
cat account-auth-details.json | jq -r '
  .UserDetailList[] |
  select(.AttachedManagedPolicies[]?.PolicyArn | tostring |
    test("")) |
  .UserName
' # Combine with Step 1 results for targeted queries

# Or enumerate directly:
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  policies=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[*].PolicyArn' --output text)
  echo "$user: $policies"
done
```

Step 5: Run Prowler:
```
prowler aws -c iam_policy_no_statements_with_full_access --output-modes json
```

Flag: Any policy granting "iam:*" or "sts:*" as an action with "Effect": "Allow" is a finding, particularly when the Resource is "*" or when no restrictive Condition block limits the scope. This grants full IAM or STS control and should be restricted to break-glass roles only.

------------------------------------------
Procedure 5 — Identify dormant users with active access keys
Tools: aws cli, jq, Prowler, credential report
Intrusiveness: passive
Description: Detects IAM users who have not performed any activity (console login or API call) within a defined dormancy period (typically 90 days) but still have active access keys. These orphaned credentials represent a significant risk — if compromised, they provide persistent access to an account that is unlikely to be noticed since the legitimate user is not actively monitoring.

Step 1: Generate and download the IAM credential report:
```
aws iam generate-credential-report
# Wait for completion (may take a few seconds)
sleep 5
aws iam get-credential-report --query 'Content' --output text | base64 -d > credential-report.csv
```

Step 2: Identify users with active access keys who have not used them in 90+ days:
```
# Parse the credential report
awk -F',' 'NR>1 {
  user=$1
  access_key1_active=$9
  access_key1_last_used=$11
  access_key2_active=$14
  access_key2_last_used=$16
  password_last_used=$5

  if ((access_key1_active == "true" && (access_key1_last_used == "N/A" || access_key1_last_used == "no_information")) ||
      (access_key2_active == "true" && (access_key2_last_used == "N/A" || access_key2_last_used == "no_information"))) {
    print "[!] NEVER USED KEY: " user
  }
}' credential-report.csv
```

Step 3: Cross-reference with last activity using access advisor:
```
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  last_used=$(aws iam get-user --user-name "$user" --query 'User.PasswordLastUsed' --output text 2>/dev/null)
  key1_last=$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[0].CreateDate' --output text 2>/dev/null)
  echo "User: $user | PasswordLastUsed: $last_used | Key Created: $key1_last"
done
```

Step 4: Identify users with no console login AND active keys:
```
awk -F',' 'NR>1 {
  user=$1; pwd_enabled=$4; pwd_last_used=$5;
  key1_active=$9; key2_active=$14;
  if (pwd_enabled == "false" && (key1_active == "true" || key2_active == "true")) {
    if (pwd_last_used == "no_information" || pwd_last_used == "N/A") {
      print "[!] DORMANT (no console, active keys): " user
    }
  }
}' credential-report.csv
```

Step 5: Use AWS CLI to get access key last-used details for flagged users:
```
USER="<flagged_username>"
for key_id in $(aws iam list-access-keys --user-name "$USER" --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
  echo "=== $key_id ==="
  aws iam get-access-key-last-used --access-key-id "$key_id"
done
```

Step 6: Run Prowler checks for inactive users:
```
prowler aws -c iam_user_accesskey_unused iam_user_console_access_unused --output-modes json
```

Flag: Any IAM user who has not logged in or used their access key in 90+ days (or per organizational policy) while still having active access keys is a finding. Users with active keys that have NEVER been used are critical findings. Users with no console access and active keys that show no API usage are also findings.

------------------------------------------
Procedure 6 — Identify unused high-privilege IAM roles
Tools: aws cli, jq, PMapper, Prowler
Intrusiveness: passive
Description: Detects IAM roles with high privileges (admin-equivalent, iam:*, sts:*, or other sensitive permissions) that have not been assumed recently. Unused high-privilege roles increase the attack surface — if their trust policies are misconfigured or overly permissive, an attacker can assume these roles to escalate privileges without detection.

Step 1: Get the last-used information for all roles:
```
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output text | while read name arn; do
  last_used=$(aws iam get-role --role-name "$name" --query 'Role.RoleLastUsed.LastUsedDate' --output text 2>/dev/null)
  echo "$name | $arn | LastUsed: $last_used"
done
```

Step 2: Filter for roles not used in 90+ days:
```
THRESHOLD=$(date -v-90d +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -d '90 days ago' --iso-8601=seconds)
aws iam get-account-authorization-details --filter Role --output json | jq --arg threshold "$THRESHOLD" '
  .RoleDetailList[] |
  select((.RoleLastUsed.LastUsedDate // "1970-01-01") < $threshold) |
  {RoleName, Arn, LastUsed: (.RoleLastUsed.LastUsedDate // "NEVER")}
'
```

Step 3: Cross-reference unused roles with their attached policies to find high-privilege ones:
```
aws iam get-account-authorization-details --filter Role --output json | jq --arg threshold "$THRESHOLD" '
  .RoleDetailList[] |
  select((.RoleLastUsed.LastUsedDate // "1970-01-01") < $threshold) |
  select(
    (.AttachedManagedPolicies[]?.PolicyArn | test("AdministratorAccess|PowerUserAccess|IAMFullAccess")) or
    (.RolePolicyList[]?.PolicyDocument.Statement[]? |
      select(.Effect == "Allow") | .Action | tostring | test("\\*|iam:\\*|sts:\\*"))
  ) |
  {RoleName, Arn, LastUsed: (.RoleLastUsed.LastUsedDate // "NEVER"),
   AttachedPolicies: [.AttachedManagedPolicies[]?.PolicyName]}
'
```

Step 4: Review trust policies of unused high-privilege roles for overly permissive assume conditions:
```
for role in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  trust=$(aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output json)
  if echo "$trust" | grep -qE '"Principal"\s*:\s*"\*"|"AWS"\s*:\s*"\*"'; then
    echo "[CRITICAL] Role $role has wildcard trust policy!"
    echo "$trust" | jq .
  fi
done
```

Step 5: Run PMapper to identify roles reachable by other principals:
```
pmapper graph create
pmapper query "who can do sts:AssumeRole with Resource:'arn:aws:iam::*:role/<unused_role_name>'"
```

Step 6: Run Prowler check:
```
prowler aws -c iam_role_administratoraccess_policy iam_role_cross_account_readonlyaccess_policy --output-modes json
```

Flag: Any IAM role with high privileges (admin-equivalent policies or iam:*/sts:* actions) that has not been assumed in 90+ days (or never) is a finding. Roles with overly permissive trust policies (Principal: "*") combined with inactivity are critical findings.

------------------------------------------
Procedure 7 — Identify roles with excessive MaxSessionDuration
Tools: aws cli, jq
Intrusiveness: passive
Description: Detects IAM roles configured with a MaxSessionDuration exceeding organizational policy (default is 1 hour / 3600 seconds; maximum is 12 hours / 43200 seconds). Extended session durations allow assumed roles to maintain access for longer periods. An attacker who successfully assumes a role with a 12-hour session duration has a much larger operational window before needing to re-authenticate or re-assume.

Step 1: List all roles and their MaxSessionDuration settings:
```
aws iam list-roles --query 'Roles[*].[RoleName,MaxSessionDuration]' --output table
```

Step 2: Identify roles with MaxSessionDuration exceeding a threshold (e.g., 4 hours / 14400 seconds):
```
aws iam list-roles --output json | jq '
  .Roles[] |
  select(.MaxSessionDuration > 14400) |
  {RoleName, MaxSessionDuration, Arn, TrustPolicy: .AssumeRolePolicyDocument}
'
```

Step 3: Identify high-privilege roles with excessive session duration (compound risk):
```
aws iam get-account-authorization-details --filter Role --output json | jq '
  .RoleDetailList[] |
  select(.MaxSessionDuration > 14400) |
  select(
    (.AttachedManagedPolicies[]?.PolicyArn | test("AdministratorAccess|PowerUserAccess|IAMFullAccess")) or
    (.RolePolicyList[]?.PolicyDocument.Statement[]? |
      select(.Effect == "Allow") | .Action | tostring | test("\\*|iam:\\*|sts:\\*"))
  ) |
  {RoleName, MaxSessionDuration, Arn,
   AttachedPolicies: [.AttachedManagedPolicies[]?.PolicyName]}
'
```

Step 4: Check for roles at the absolute maximum (43200 seconds / 12 hours):
```
aws iam list-roles --output json | jq '
  .Roles[] |
  select(.MaxSessionDuration == 43200) |
  {RoleName, MaxSessionDuration: "12 hours (MAXIMUM)", Arn}
'
```

Step 5: Review the trust policies of roles with extended sessions to assess cross-account or external access risk:
```
aws iam list-roles --output json | jq '
  .Roles[] |
  select(.MaxSessionDuration > 14400) |
  {RoleName, MaxSessionDuration,
   ExternalTrust: (.AssumeRolePolicyDocument.Statement[] |
     select(.Principal.AWS // .Principal.Federated // "" | tostring | test("^(?!arn:aws:iam::CURRENT_ACCOUNT_ID)")))}
'
```

Flag: Any role with MaxSessionDuration exceeding the organizational threshold (recommended: 4 hours / 14400 seconds) is a finding. Roles with the maximum value of 43200 seconds (12 hours) are high findings. High-privilege roles with extended sessions that also allow cross-account or external assumption are critical findings.

------------------------------------------
Procedure 8 — Identify access keys older than rotation policy / multiple active keys per user
Tools: aws cli, jq, Prowler, credential report
Intrusiveness: passive
Description: Detects access keys that have exceeded the organization's rotation policy (typically 90 days) and users with multiple active access keys. Long-lived access keys increase the window of opportunity for credential theft and use. Multiple active keys per user often indicate poor key management hygiene and may include forgotten or unused keys.

Step 1: Generate and retrieve the credential report:
```
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query 'Content' --output text | base64 -d > credential-report.csv
```

Step 2: Identify access keys older than 90 days:
```
THRESHOLD=$(date -v-90d +%Y-%m-%d 2>/dev/null || date -d '90 days ago' +%Y-%m-%d)
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[?Status=='Active'].[AccessKeyId,CreateDate]" --output text | while read key_id created; do
    key_date=$(echo "$created" | cut -dT -f1)
    if [[ "$key_date" < "$THRESHOLD" ]]; then
      age=$(( ( $(date +%s) - $(date -jf "%Y-%m-%d" "$key_date" +%s 2>/dev/null || date -d "$key_date" +%s) ) / 86400 ))
      echo "[!] OLD KEY: User=$user KeyId=$key_id Created=$created Age=${age}days"
    fi
  done
done
```

Step 3: Identify users with multiple active access keys:
```
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  count=$(aws iam list-access-keys --user-name "$user" --query 'length(AccessKeyMetadata[?Status==`Active`])' --output text)
  if [ "$count" -gt 1 ]; then
    echo "[!] MULTIPLE ACTIVE KEYS: User=$user Count=$count"
    aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[?Status==`Active`].[AccessKeyId,CreateDate]' --output table
  fi
done
```

Step 4: Parse the credential report for a consolidated view:
```
awk -F',' 'NR>1 {
  user=$1
  key1_active=$9; key1_rotated=$10; key1_last_used=$11
  key2_active=$14; key2_rotated=$15; key2_last_used=$16
  if (key1_active == "true" && key2_active == "true") {
    print "[!] MULTI-KEY: " user " (key1_rotated: " key1_rotated ", key2_rotated: " key2_rotated ")"
  }
}' credential-report.csv
```

Step 5: Check access keys older than 365 days (critical finding):
```
CRITICAL_THRESHOLD=$(date -v-365d +%Y-%m-%d 2>/dev/null || date -d '365 days ago' +%Y-%m-%d)
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[?Status=='Active'].[AccessKeyId,CreateDate]" --output text | while read key_id created; do
    key_date=$(echo "$created" | cut -dT -f1)
    if [[ "$key_date" < "$CRITICAL_THRESHOLD" ]]; then
      echo "[CRITICAL] Key $key_id for $user is over 365 days old (created: $created)"
    fi
  done
done
```

Step 6: Run Prowler checks:
```
prowler aws -c iam_access_key_rotation_90_days iam_user_two_active_access_keys --output-modes json
```

Flag: Any active access key older than the rotation policy (typically 90 days) is a finding. Keys older than 365 days are critical findings. Any user with more than one active access key is a finding. Root account access keys (if present) are always a critical finding regardless of age.

------------------------------------------
Procedure 9 — Run IAM Access Analyzer policy validation findings
Tools: aws cli (access-analyzer), jq, Prowler
Intrusiveness: passive
Description: Leverages AWS IAM Access Analyzer's ValidatePolicy API to perform automated policy validation. Access Analyzer checks policies against AWS best practices and reports findings in categories including SECURITY_WARNING, ERROR, WARNING, and SUGGESTION. This provides AWS-native automated analysis that catches issues like missing version statements, invalid principals, overly permissive resources, and syntax errors.

Step 1: Check if an IAM Access Analyzer is enabled in the account:
```
aws accessanalyzer list-analyzers --query 'analyzers[*].[name,type,status]' --output table
```

Step 2: If no analyzer exists, note this as a finding and optionally create one:
```
# [DOCUMENT ONLY] Create an analyzer if authorized:
# aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT
```

Step 3: Validate all customer-managed policies using the Access Analyzer ValidatePolicy API:
```
aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn,DefaultVersionId]' --output text | while read name arn vid; do
  echo "=== Validating: $name ==="
  doc=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$vid" --query 'PolicyVersion.Document' --output json)
  echo "$doc" | aws accessanalyzer validate-policy \
    --policy-document file:///dev/stdin \
    --policy-type IDENTITY_POLICY \
    --query 'findings[?findingType==`SECURITY_WARNING` || findingType==`ERROR`]' \
    --output json
done
```

Step 4: Alternative approach — validate each policy from the authorization details export:
```
aws iam get-account-authorization-details --output json > account-auth-details.json
cat account-auth-details.json | jq -r '.Policies[] | "\(.PolicyName)|\(.Arn)|\(.PolicyVersionList[0].Document | @json)"' | while IFS='|' read name arn doc; do
  echo "=== $name ($arn) ==="
  echo "$doc" | jq '.' > /tmp/policy_doc.json
  aws accessanalyzer validate-policy \
    --policy-document "file:///tmp/policy_doc.json" \
    --policy-type IDENTITY_POLICY \
    --output json | jq '.findings[] | select(.findingType == "SECURITY_WARNING" or .findingType == "ERROR")'
done
```

Step 5: Validate resource-based policies (S3 bucket policies, SQS policies, etc.):
```
# Example for S3 bucket policies:
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null) || continue
  echo "=== S3: $bucket ==="
  echo "$policy" > /tmp/bucket_policy.json
  aws accessanalyzer validate-policy \
    --policy-document "file:///tmp/bucket_policy.json" \
    --policy-type RESOURCE_POLICY \
    --output json | jq '.findings[] | select(.findingType == "SECURITY_WARNING" or .findingType == "ERROR")'
done
```

Step 6: Validate trust policies on roles:
```
for role in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  echo "=== Trust: $role ==="
  aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output json > /tmp/trust_policy.json
  aws accessanalyzer validate-policy \
    --policy-document "file:///tmp/trust_policy.json" \
    --policy-type RESOURCE_POLICY \
    --output json | jq '.findings[] | select(.findingType == "SECURITY_WARNING" or .findingType == "ERROR")'
done
```

Step 7: List existing Access Analyzer findings for external access:
```
ANALYZER_ARN=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text)
aws accessanalyzer list-findings --analyzer-arn "$ANALYZER_ARN" \
  --filter '{"status": {"eq": ["ACTIVE"]}}' \
  --query 'findings[*].{Resource:resource,Type:resourceType,Principal:principal,Condition:condition}' \
  --output table
```

Step 8: Run Prowler checks for Access Analyzer:
```
prowler aws -c accessanalyzer_enabled iam_policy_allows_privilege_escalation --output-modes json
```

Flag: Any policy returning SECURITY_WARNING or ERROR findings from the ValidatePolicy API is a finding. The absence of an IAM Access Analyzer in the account is itself a finding. Active findings from Access Analyzer indicating external access to resources are findings. Pay special attention to SECURITY_WARNING findings related to overly permissive principals, missing conditions, or wildcard usage.

------------------------------------------
References:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html
- https://docs.aws.amazon.com/access-analyzer/latest/userguide/what-is-access-analyzer.html
- https://github.com/salesforce/cloudsplaining
- https://github.com/nccgroup/PMapper
- https://github.com/prowler-cloud/prowler
- https://github.com/duo-labs/parliament
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation
- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- https://bishopfox.com/blog/privilege-escalation-in-aws
- https://www.youtube.com/watch?v=YGRRAMz8PqY (AWS re:Invent — IAM Policy Best Practices)
