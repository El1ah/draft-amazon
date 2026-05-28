Repeatability: per_account
Prerequisites: Valid AWS credentials with IAM read permissions (iam:List*, iam:Get*, sso:List*, sso:Describe*, cognito-idp:List*, cognito-idp:Describe*, cognito-identity:List*, cognito-identity:Describe*, sts:GetCallerIdentity)
Description: Identity & Permission Mapping — Comprehensive enumeration of all IAM principals (users, groups, roles), their attached and inline policies, assumable role trust relationships, AWS Identity Center (SSO) permission sets and account assignments, federated identity providers (SAML/OIDC), Cognito user and identity pools, and full privilege escalation path analysis via PMapper. This category establishes a complete map of who can do what within an AWS account or organization, which is foundational for identifying over-permissioned principals, lateral movement paths, and privilege escalation vectors.
Tags: iam, identity, permission-mapping, pmapper, cognito, saml, oidc, sso, identity-center
Potential Severity: medium

------------------------------------------
Procedure 0 — Enumerate All IAM Users, Groups, and Roles
Tools: aws cli, Prowler, ScoutSuite, CloudFox
Intrusiveness: passive
Description: Enumerates all IAM users, groups, and roles in the target AWS account. This establishes the full inventory of IAM principals, which is the foundation for all subsequent permission mapping and privilege escalation analysis. Stale or unexpected principals may indicate compromise, misconfiguration, or shadow admin accounts.

Step 1: Confirm current identity and account context.
  aws sts get-caller-identity

Step 2: List all IAM users in the account.
  aws iam list-users --output table

Step 3: For each user, retrieve detailed metadata including creation date, password last used, and path.
  aws iam get-user --user-name <USERNAME>

Step 4: List all IAM groups in the account.
  aws iam list-groups --output table

Step 5: For each group, list its members to understand group-to-user relationships.
  aws iam get-group --group-name <GROUP_NAME>

Step 6: List all IAM roles in the account.
  aws iam list-roles --output table

Step 7: For each role, inspect the trust policy (AssumeRolePolicyDocument) to understand who or what can assume it.
  aws iam get-role --role-name <ROLE_NAME> --query 'Role.AssumeRolePolicyDocument'

Step 8: List all instance profiles to identify roles attached to EC2 instances.
  aws iam list-instance-profiles --output table

Step 9: Use CloudFox to perform automated IAM principal enumeration with enriched context.
  cloudfox aws -p <PROFILE> principals

Step 10: Optionally run Prowler for a broader IAM inventory check.
  prowler -p <PROFILE> -c iam_no_custom_policy_permissive_role_assumption

Step 11: Generate a credential report for a holistic view of all users, MFA status, key ages, and last activity.
  aws iam generate-credential-report
  aws iam get-credential-report --query 'Content' --output text | base64 --decode > credential_report.csv

Flag: Any IAM users, groups, or roles that are unexpected, stale (no recent activity), have no MFA enabled, or possess overly broad trust policies should be flagged for further investigation.

------------------------------------------
Procedure 1 — Enumerate Attached Policies (Managed + Inline) for Current Principal
Tools: aws cli, CloudSplaining, Prowler
Intrusiveness: passive
Description: Retrieves all managed and inline policies attached to the current principal (user, group memberships, or role). Understanding effective permissions is critical for determining the blast radius of the current set of credentials and identifying over-permissioned principals or policies granting administrative access.

Step 1: Identify the current principal type and name.
  aws sts get-caller-identity

Step 2: If the principal is a user, list all managed policies directly attached to the user.
  aws iam list-attached-user-policies --user-name <USERNAME>

Step 3: List all inline policies for the user.
  aws iam list-user-policies --user-name <USERNAME>

Step 4: Retrieve each inline policy document.
  aws iam get-user-policy --user-name <USERNAME> --policy-name <POLICY_NAME>

Step 5: List the groups the user belongs to.
  aws iam list-groups-for-user --user-name <USERNAME>

Step 6: For each group, list managed policies attached to the group.
  aws iam list-attached-group-policies --group-name <GROUP_NAME>

Step 7: For each group, list and retrieve inline policies.
  aws iam list-group-policies --group-name <GROUP_NAME>
  aws iam get-group-policy --group-name <GROUP_NAME> --policy-name <POLICY_NAME>

Step 8: If the principal is a role, list managed policies attached to the role.
  aws iam list-attached-role-policies --role-name <ROLE_NAME>

Step 9: List and retrieve inline policies for the role.
  aws iam list-role-policies --role-name <ROLE_NAME>
  aws iam get-role-policy --role-name <ROLE_NAME> --policy-name <POLICY_NAME>

Step 10: For any managed policy, retrieve the actual policy document to review permissions.
  aws iam get-policy --policy-arn <POLICY_ARN>
  aws iam get-policy-version --policy-arn <POLICY_ARN> --version-id <VERSION_ID>

Step 11: Use CloudSplaining to automatically analyze all policies for privilege escalation, resource exposure, and data exfiltration risks.
  cloudsplaining download --profile <PROFILE>
  cloudsplaining scan --input-file default.json --output cloudsplaining-results

Step 12: Simulate permissions for the current principal using the IAM policy simulator to confirm effective access.
  aws iam simulate-principal-policy --policy-source-arn <PRINCIPAL_ARN> --action-names s3:GetObject ec2:RunInstances iam:CreateUser

Flag: Any principal with AdministratorAccess, overly permissive wildcard policies (Action: *, Resource: *), inline policies granting sensitive permissions (iam:PassRole, sts:AssumeRole, lambda:InvokeFunction, etc.), or policies that CloudSplaining identifies as allowing privilege escalation or data exfiltration.

------------------------------------------
Procedure 2 — Enumerate All Assumable Roles from Current Principal
Tools: aws cli, CloudFox, Pacu
Intrusiveness: passive
Description: Identifies all IAM roles the current principal can assume, either within the same account or cross-account. Assumable roles are a primary vector for lateral movement and privilege escalation — a low-privilege user who can assume a high-privilege role effectively has those elevated permissions.

Step 1: Identify the current principal's ARN.
  aws sts get-caller-identity

Step 2: List all roles and examine their trust policies to find those that trust the current principal.
  aws iam list-roles --query 'Roles[*].[RoleName,Arn,AssumeRolePolicyDocument]' --output json

Step 3: Filter roles whose trust policy Principal field includes the current user/role ARN, the account root, or a wildcard.
  aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument), '$(aws sts get-caller-identity --query Account --output text)')].[RoleName,Arn]" --output table

Step 4: Attempt to assume each candidate role to confirm access.
  aws sts assume-role --role-arn <ROLE_ARN> --role-session-name test-session

Step 5: For each successfully assumed role, note the returned credentials and check the effective permissions of the assumed role (repeat Procedure 1 steps as the assumed role).

Step 6: Use CloudFox to automatically enumerate assumable roles and role trust relationships.
  cloudfox aws -p <PROFILE> role-trusts

Step 7: Use Pacu's iam__enum_roles module to enumerate roles that can be assumed.
  pacu
  > use iam__enum_roles
  > run

Step 8: Check for cross-account role assumptions by inspecting trust policies that reference external account IDs.
  aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument), 'arn:aws:iam::')]" --output json

Step 9: Look for roles assumable by AWS services (lambda.amazonaws.com, ec2.amazonaws.com, etc.) which can be abused via service-based privilege escalation.
  aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument), '.amazonaws.com')].[RoleName,AssumeRolePolicyDocument]" --output json

Flag: Any role that the current principal can assume which grants higher privileges than the current session, roles with overly permissive trust policies (Principal: "*" or broad account-level trust without conditions), cross-account roles without ExternalId conditions, or service roles that can be leveraged for privilege escalation.

------------------------------------------
Procedure 3 — Map Identity Center Permission Sets and Account Assignments
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Enumerates AWS IAM Identity Center (formerly AWS SSO) configuration including permission sets, account assignments, and user/group mappings. Identity Center is the recommended centralized access management for AWS Organizations and misconfigured permission sets can grant broad cross-account access. Understanding these mappings reveals which federated identities have access to which accounts and at what privilege level.

Step 1: List all Identity Center instances in the organization.
  aws sso-admin list-instances

Step 2: Note the InstanceArn and IdentityStoreId from the output. List all permission sets.
  aws sso-admin list-permission-sets --instance-arn <INSTANCE_ARN>

Step 3: For each permission set, describe it to see the name, description, session duration, and relay state.
  aws sso-admin describe-permission-set --instance-arn <INSTANCE_ARN> --permission-set-arn <PERMISSION_SET_ARN>

Step 4: Retrieve the inline policy attached to each permission set.
  aws sso-admin get-inline-policy-for-permission-set --instance-arn <INSTANCE_ARN> --permission-set-arn <PERMISSION_SET_ARN>

Step 5: List managed policies attached to each permission set.
  aws sso-admin list-managed-policies-in-permission-set --instance-arn <INSTANCE_ARN> --permission-set-arn <PERMISSION_SET_ARN>

Step 6: List the AWS managed policies attached to the permission set.
  aws sso-admin list-customer-managed-policy-references-in-permission-set --instance-arn <INSTANCE_ARN> --permission-set-arn <PERMISSION_SET_ARN>

Step 7: List all account assignments for each permission set to see which users/groups have access to which accounts.
  aws sso-admin list-account-assignments --instance-arn <INSTANCE_ARN> --account-id <ACCOUNT_ID> --permission-set-arn <PERMISSION_SET_ARN>

Step 8: Enumerate all accounts the permission set is provisioned to.
  aws sso-admin list-accounts-for-provisioned-permission-set --instance-arn <INSTANCE_ARN> --permission-set-arn <PERMISSION_SET_ARN>

Step 9: List all users and groups in the Identity Store.
  aws identitystore list-users --identity-store-id <IDENTITY_STORE_ID>
  aws identitystore list-groups --identity-store-id <IDENTITY_STORE_ID>

Step 10: For each group, list its members.
  aws identitystore list-group-memberships --identity-store-id <IDENTITY_STORE_ID> --group-id <GROUP_ID>

Step 11: Run Prowler checks specific to Identity Center configuration.
  prowler -p <PROFILE> -s sso

Flag: Permission sets with AdministratorAccess or overly broad policies, permission sets provisioned to all accounts in the organization, users or groups with access to production or sensitive accounts without justification, or permission sets with excessively long session durations (>4 hours).

------------------------------------------
Procedure 4 — Enumerate SAML and OIDC Identity Providers
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Identifies all configured SAML and OIDC identity providers in the AWS account. Federated identity providers allow external identities to assume IAM roles. Misconfigured providers can allow unauthorized external parties to assume roles within the account, and stale providers pointing to decommissioned IdPs can be hijacked.

Step 1: List all SAML providers in the account.
  aws iam list-saml-providers

Step 2: For each SAML provider, retrieve the full metadata document and configuration.
  aws iam get-saml-provider --saml-provider-arn <SAML_PROVIDER_ARN>

Step 3: Inspect the SAML metadata XML for the IdP entity ID, signing certificate, and SSO endpoint. Check if the certificate is expired.
  # Parse the SAMLMetadataDocument field from the output
  # Look for X509Certificate, entityID, SingleSignOnService elements

Step 4: List all OpenID Connect (OIDC) providers.
  aws iam list-open-id-connect-providers

Step 5: For each OIDC provider, retrieve its configuration details.
  aws iam get-open-id-connect-provider --open-id-connect-provider-arn <OIDC_PROVIDER_ARN>

Step 6: Review the OIDC provider URL, client ID list, and thumbprint list. Verify the provider URL is still valid and owned by the expected organization.
  # Check the Url, ClientIDList, and ThumbprintList fields
  curl -s <OIDC_PROVIDER_URL>/.well-known/openid-configuration | jq .

Step 7: Identify all IAM roles that trust each SAML or OIDC provider by searching role trust policies.
  aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument), 'saml-provider') || contains(to_string(AssumeRolePolicyDocument), 'oidc-provider')].[RoleName,AssumeRolePolicyDocument]" --output json

Step 8: For roles trusting OIDC providers (e.g., GitHub Actions, GitLab CI), check if the trust policy has proper conditions restricting the sub or aud claims.
  # Look for Condition blocks with StringEquals or StringLike on
  # token.actions.githubusercontent.com:sub, :aud, etc.

Step 9: Run Prowler checks for identity provider misconfiguration.
  prowler -p <PROFILE> -c iam_saml_provider_arn_is_valid

Flag: SAML providers with expired certificates, OIDC providers pointing to URLs no longer controlled by the organization, OIDC trust policies lacking Condition constraints (especially for CI/CD providers like GitHub Actions), roles trusting federated providers with overly permissive permissions, or stale/unused identity providers that should be decommissioned.

------------------------------------------
Procedure 5 — Enumerate Cognito User Pools and Identity Pools
Tools: aws cli, Pacu
Intrusiveness: passive
Description: Enumerates Amazon Cognito User Pools (authentication) and Identity Pools (federated identity/authorization). Misconfigured Cognito pools can allow unauthenticated access to AWS resources, self-registration leading to unauthorized authenticated access, or overly permissive IAM roles for authenticated/unauthenticated identities.

Step 1: List all Cognito User Pools in the current region.
  aws cognito-idp list-user-pools --max-results 60

Step 2: For each User Pool, describe the full configuration.
  aws cognito-idp describe-user-pool --user-pool-id <USER_POOL_ID>

Step 3: Check User Pool settings for risky configurations:
  - AdminCreateUserConfig.AllowAdminCreateUserOnly: if false, self-registration is enabled
  - MfaConfiguration: should be ON or OPTIONAL, not OFF
  - Policies.PasswordPolicy: check minimum length and complexity requirements
  # Review the output from describe-user-pool for these fields

Step 4: List User Pool clients (app clients) and their configurations.
  aws cognito-idp list-user-pool-clients --user-pool-id <USER_POOL_ID>
  aws cognito-idp describe-user-pool-client --user-pool-id <USER_POOL_ID> --client-id <CLIENT_ID>

Step 5: Check if any app client has ExplicitAuthFlows allowing ALLOW_USER_PASSWORD_AUTH (insecure) or if client secrets are missing where expected.

Step 6: List all Cognito Identity Pools (Federated Identities) in the current region.
  aws cognito-identity list-identity-pools --max-results 60

Step 7: For each Identity Pool, describe the configuration.
  aws cognito-identity describe-identity-pool --identity-pool-id <IDENTITY_POOL_ID>

Step 8: Check if the Identity Pool allows unauthenticated identities.
  # Look for AllowUnauthenticatedIdentities: true in the output

Step 9: Retrieve the IAM roles assigned to the Identity Pool for both authenticated and unauthenticated access.
  aws cognito-identity get-identity-pool-roles --identity-pool-id <IDENTITY_POOL_ID>

Step 10: Review the IAM policies attached to the unauthenticated and authenticated roles to assess what resources unauthenticated users can access.
  aws iam get-role-policy --role-name <UNAUTH_ROLE_NAME> --policy-name <POLICY_NAME>
  aws iam list-attached-role-policies --role-name <UNAUTH_ROLE_NAME>

Step 11: If unauthenticated access is enabled, attempt to obtain temporary credentials.
  aws cognito-identity get-id --identity-pool-id <IDENTITY_POOL_ID>
  aws cognito-identity get-credentials-for-identity --identity-id <IDENTITY_ID>

Step 12: Use Pacu to automate Cognito enumeration.
  pacu
  > use cognito__enum
  > run

Step 13: Repeat Steps 1-12 for all active regions if the assessment scope is multi-region.
  for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
    echo "=== $region ==="
    aws cognito-idp list-user-pools --max-results 60 --region $region
    aws cognito-identity list-identity-pools --max-results 60 --region $region
  done

Flag: Identity Pools with AllowUnauthenticatedIdentities set to true, unauthenticated roles with access to sensitive AWS services (S3, DynamoDB, Lambda, etc.), User Pools with self-registration enabled (AllowAdminCreateUserOnly: false), User Pools with MFA disabled, app clients using insecure auth flows, or weak password policies.

------------------------------------------
Procedure 6 — Generate PMapper Graph for Full Escalation Path Visualization
Tools: PMapper (Principal Mapper), aws cli
Intrusiveness: passive
Description: Uses PMapper (Principal Mapper) to build a directed graph of all IAM principals and their effective permissions, then queries the graph for privilege escalation paths. PMapper identifies non-obvious chains of permissions that allow a lower-privileged principal to escalate to admin-level access through actions like iam:PassRole, sts:AssumeRole, lambda:CreateFunction, or ec2:RunInstances combined with instance profiles.

Step 1: Ensure PMapper is installed and the current credentials have sufficient read permissions.
  pip install principalmapper
  pmapper --version

Step 2: Build the PMapper graph for the current AWS account. This pulls IAM data and simulates permission relationships.
  pmapper graph create --profile <PROFILE>

Step 3: Verify the graph was created successfully and view basic statistics.
  pmapper graph list

Step 4: Query the graph to identify all principals that can escalate to admin.
  pmapper query "who can do iam:CreateUser with *"

Step 5: Query for principals that can escalate via common privilege escalation vectors.
  pmapper query "who can do iam:PutUserPolicy with *"
  pmapper query "who can do iam:AttachUserPolicy with *"
  pmapper query "who can do iam:PutRolePolicy with *"
  pmapper query "who can do iam:AttachRolePolicy with *"
  pmapper query "who can do sts:AssumeRole with *"
  pmapper query "who can do iam:PassRole with *"
  pmapper query "who can do lambda:CreateFunction with *"
  pmapper query "who can do lambda:InvokeFunction with *"

Step 6: Run the full privilege escalation analysis to find all paths to admin.
  pmapper analysis --output-type text

Step 7: Identify specific escalation paths from a particular principal.
  pmapper argquery --principal <PRINCIPAL_ARN> --action "*" --resource "*"

Step 8: Check if a specific principal can reach admin-level access through any chain of actions.
  pmapper query "can <PRINCIPAL_ARN> do iam:CreateUser with *"

Step 9: Visualize the graph (requires graphviz). Export to SVG or PNG for inclusion in reports.
  pmapper visualize --filetype svg

Step 10: Look for cross-principal escalation chains where principal A can assume role B, and role B can modify permissions of role C, etc.
  pmapper analysis --output-type text | grep -i "admin"

Step 11: Export the raw graph data for offline analysis or integration with other tools.
  pmapper graph display

Step 12: After analysis, clean up the local graph data if no longer needed.
  pmapper graph delete --account <ACCOUNT_ID>

Flag: Any non-admin principal that has a path to admin-level access (direct or through a chain of role assumptions and permission modifications), principals that can create or modify IAM policies, principals that can pass roles to services (iam:PassRole) combined with service invocation permissions, or any unexpected privilege escalation paths that violate the principle of least privilege.

------------------------------------------
References:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html
- https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html
- https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html
- https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html
- https://github.com/nccgroup/PMapper
- https://github.com/salesforce/cloudsplaining
- https://github.com/BishopFox/cloudfox
- https://github.com/prowler-cloud/prowler
- https://github.com/RhinoSecurityLabs/pacu
- https://cloud.hacktricks.wiki/pentesting-cloud/aws-security/aws-services/aws-iam-enum.html
- https://cloud.hacktricks.wiki/pentesting-cloud/aws-security/aws-services/aws-cognito-enum.html
- https://cloud.hacktricks.wiki/pentesting-cloud/aws-security/aws-services/aws-sso-and-identitystore-enum.html
- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- https://bishopfox.com/blog/privilege-escalation-in-aws
