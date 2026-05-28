Repeatability: per_account
Prerequisites: Valid AWS credentials with Organizations read access (organizations:ListPolicies, organizations:ListTargetsForPolicy, organizations:DescribePolicy, organizations:ListAccounts, organizations:ListAccountsForParent, organizations:ListOrganizationalUnitsForParent, organizations:DescribeOrganization, iam:ListUsers, iam:ListRoles, iam:GetUser, iam:GetRole, iam:ListPolicies, iam:SimulatePrincipalPolicy); for active testing procedures, permissions to invoke target API actions in the member account
Description: Service Control Policies (SCPs) and IAM Permission Boundaries are two critical guardrail mechanisms in AWS. SCPs restrict what actions member accounts in an AWS Organization can perform, while Permission Boundaries cap the maximum privileges an IAM principal can assume regardless of its identity-based policies. Weaknesses in either layer—missing deny rules for destructive root actions, absent region restrictions, unprotected CloudTrail configurations, accounts excluded from organizational SCPs, privileged principals without Permission Boundaries, gaps in SCP deny lists, or exploitable NotAction constructs—can allow an attacker to escalate privileges, disable logging, operate in unrestricted regions, or bypass intended security controls. This methodology systematically enumerates, analyzes, and tests both SCP and Permission Boundary configurations to identify exploitable gaps.
Tags: scp, permission-boundary, organizations, guardrails, bypass, notaction
Potential Severity: high

------------------------------------------
Procedure 0 — Enumerate SCPs Affecting In-Scope Accounts
Tools: aws cli, Prowler, ScoutSuite
Intrusiveness: passive
Description: Enumerates all Service Control Policies (SCPs) attached to the AWS Organization root, organizational units (OUs), and individual member accounts. This produces a complete inventory of SCPs and their attachment points, which is essential for all subsequent analysis procedures. Without a full map of SCP coverage, gaps and misconfigurations cannot be reliably identified.

Step 1: Verify Organizations access and retrieve the organization structure.
  aws organizations describe-organization --query 'Organization.{Id:Id, MasterAccountId:MasterAccountId, FeatureSet:FeatureSet}'

Step 2: List all roots in the organization.
  aws organizations list-roots --query 'Roots[*].{Id:Id, Name:Name, PolicyTypes:PolicyTypes}'

Step 3: List all SCPs in the organization.
  aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[*].{Id:Id, Name:Name, Description:Description, AwsManaged:AwsManaged}'

Step 4: For each SCP identified, retrieve the full policy document.
  aws organizations describe-policy --policy-id <policy-id> --query 'Policy.{Name:PolicySummary.Name, Content:Content}'

Step 5: For each SCP, list its attachment targets (roots, OUs, accounts).
  aws organizations list-targets-for-policy --policy-id <policy-id> --query 'Targets[*].{TargetId:TargetId, Type:Type, Name:Name}'

Step 6: List all OUs under each root recursively to build the OU tree.
  aws organizations list-organizational-units-for-parent --parent-id <root-id> --query 'OrganizationalUnits[*].{Id:Id, Name:Name}'
  Repeat recursively for each discovered OU as parent-id.

Step 7: List all accounts in the organization and map them to their parent OUs.
  aws organizations list-accounts --query 'Accounts[*].{Id:Id, Name:Name, Status:Status}'
  aws organizations list-accounts-for-parent --parent-id <ou-id> --query 'Accounts[*].{Id:Id, Name:Name}'

Step 8: Cross-reference the SCP-to-target mappings against the full OU/account tree to produce a matrix showing which SCPs apply (directly or inherited) to each in-scope account.

Step 9: Run Prowler to corroborate SCP enumeration results.
  prowler aws -c organizations_scp_check_deny_regions_enabled organizations_scp_attached --profile <profile>

Step 10: Optionally, run ScoutSuite for a broader view of organization-level controls.
  scout --provider aws --profile <profile> --services organizations

Flag: Any in-scope account that has only the default FullAWSAccess SCP (p-FullAWSAccess) and no restrictive SCPs attached, or any account whose effective SCP chain is unclear, is a finding.

------------------------------------------
Procedure 1 — Identify SCP Gaps: No Root Action Deny, No Region Restriction, No CloudTrail Protection
Tools: aws cli, Prowler, CloudSplaining
Intrusiveness: passive
Description: Analyzes the content of all collected SCPs to identify three critical classes of missing guardrails: (1) no explicit Deny for dangerous root-level or destructive actions (e.g., organizations:LeaveOrganization, account:CloseAccount, iam:CreateUser on root), (2) no region restriction that limits workloads to approved AWS regions, and (3) no protection preventing disabling or tampering with CloudTrail logging. These are baseline guardrails recommended by AWS and their absence significantly increases risk.

Step 1: Retrieve all SCP policy documents collected in Procedure 0. For each policy, parse the JSON and inspect all Statement blocks.

Step 2: Check for root/destructive action deny rules. Search all SCP statements for Deny effects covering at minimum the following critical actions:
  - organizations:LeaveOrganization
  - account:CloseAccount
  - iam:CreateOpenIDConnectProvider
  - iam:CreateSAMLProvider
  - sts:AssumeRole (when restricting cross-account to known roles)
  - ec2:StopInstances, ec2:TerminateInstances (in production OUs)
  Record any of these actions NOT covered by a Deny statement in any SCP across the effective policy chain.

Step 3: Check for region restriction SCPs. Search for Deny statements that use an aws:RequestedRegion condition key to block API calls outside approved regions. Typical pattern:
  {
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:RequestedRegion": ["us-east-1", "eu-west-1"]
      }
    }
  }
  Verify that global services (IAM, STS, CloudFront, Route53, etc.) are excluded from the region deny to avoid breaking legitimate operations.

Step 4: Check for CloudTrail protection SCPs. Search for Deny statements that block:
  - cloudtrail:StopLogging
  - cloudtrail:DeleteTrail
  - cloudtrail:UpdateTrail
  - cloudtrail:PutEventSelectors (to prevent narrowing event scope)
  Verify these Deny rules cannot be bypassed by excepted principals.

Step 5: Run Prowler checks for SCP gap analysis.
  prowler aws -c organizations_scp_check_deny_regions_enabled --profile <profile>

Step 6: Use CloudSplaining to analyze downloaded SCP JSON documents for overly permissive patterns.
  cloudsplaining download --profile <profile>
  cloudsplaining scan-policy-file --input-policy-file <scp-policy.json>

Step 7: Document the complete list of missing guardrails per OU and per account, noting which critical deny rules are absent.

Flag: Any effective SCP chain for an in-scope account that is missing one or more of the following: (a) Deny for organizations:LeaveOrganization and account:CloseAccount, (b) Deny for API calls outside approved regions using aws:RequestedRegion, or (c) Deny for cloudtrail:StopLogging/DeleteTrail/UpdateTrail is a finding.

------------------------------------------
Procedure 2 — Identify Accounts Excluded from Key Organizational SCPs
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Determines whether any member accounts in the organization are excluded from key restrictive SCPs—either because they sit in OUs where SCPs are not attached, because they have been individually detached from inherited SCPs, or because SCP Condition blocks use principal-based exceptions that exempt specific accounts. Accounts carved out from organizational guardrails represent a significant escalation path; an attacker who compromises such an account operates without the restrictions applied to the rest of the organization.

Step 1: Using the SCP-to-target mapping from Procedure 0, list all accounts that are NOT covered by each restrictive (non-FullAWSAccess) SCP.

Step 2: For each restrictive SCP, verify attachment at the root level vs. individual OU level.
  aws organizations list-targets-for-policy --policy-id <restrictive-scp-id>
  If the SCP is attached only to specific OUs (not the root), enumerate which OUs and accounts are outside its scope.

Step 3: Inspect SCP Condition blocks for account-level or principal-level exceptions.
  Look for patterns such as:
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalAccount": ["111111111111", "222222222222"]
    }
  }
  or:
  "Condition": {
    "ArnNotLike": {
      "aws:PrincipalARN": ["arn:aws:iam::*:role/AdminBypassRole"]
    }
  }
  Document all excepted accounts and principals.

Step 4: Cross-reference excepted accounts with the in-scope account list. For each excepted account, determine whether the exception is justified (e.g., management account, break-glass account with compensating controls).

Step 5: Check if the management account itself has any SCPs applied. Note: SCPs do NOT apply to the management account by design—document this as an inherent limitation and assess risk accordingly.

Step 6: List all accounts directly under the organization root (not in any OU), as these only inherit root-level SCPs.
  aws organizations list-accounts-for-parent --parent-id <root-id>

Step 7: Run Prowler to validate SCP attachment.
  prowler aws -c organizations_scp_attached --profile <profile>

Flag: Any in-scope member account that is not covered by one or more key restrictive SCPs (region lockdown, CloudTrail protection, destructive action deny) due to OU placement, explicit detachment, or Condition-based exclusion is a finding. The management account lacking SCP coverage should be documented as an inherent risk if no compensating controls exist.

------------------------------------------
Procedure 3 — Identify Privileged Principals Lacking Permission Boundaries
Tools: aws cli, PMapper, Prowler
Intrusiveness: passive
Description: Identifies IAM users and roles with elevated privileges (e.g., AdministratorAccess, PowerUserAccess, IAMFullAccess, or broad wildcard policies) that do not have a Permission Boundary attached. Permission Boundaries provide a secondary authorization layer that limits the effective permissions of a principal, even if its identity-based policies grant broader access. Privileged principals without Permission Boundaries can exercise the full scope of their attached policies, which may exceed the intended authorization model and enable privilege escalation.

Step 1: List all IAM users in the target account and check for Permission Boundaries.
  aws iam list-users --query 'Users[*].{UserName:UserName, PermissionsBoundary:PermissionsBoundary}'
  Identify users where PermissionsBoundary is null or absent.

Step 2: List all IAM roles in the target account and check for Permission Boundaries.
  aws iam list-roles --query 'Roles[*].{RoleName:RoleName, PermissionsBoundary:PermissionsBoundary}'
  Identify roles where PermissionsBoundary is null or absent.

Step 3: For each principal lacking a Permission Boundary, enumerate its attached policies to assess privilege level.
  aws iam list-attached-user-policies --user-name <username>
  aws iam list-user-policies --user-name <username>
  aws iam list-attached-role-policies --role-name <rolename>
  aws iam list-role-policies --role-name <rolename>

Step 4: Identify principals with high-privilege policies. Flag any principal lacking a Permission Boundary that has any of:
  - AWS managed policies: AdministratorAccess, PowerUserAccess, IAMFullAccess, SecurityAudit
  - Custom policies containing "Action": "*" or "Action": "iam:*"
  - Policies granting iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion, iam:AttachUserPolicy, iam:AttachRolePolicy, iam:PutUserPolicy, iam:PutRolePolicy, iam:CreateUser, iam:CreateRole, iam:CreateLoginProfile, iam:UpdateLoginProfile, sts:AssumeRole on broad resources

Step 5: Use PMapper to map privilege escalation paths involving principals without boundaries.
  pmapper graph create --profile <profile>
  pmapper query "who can do iam:PutRolePolicy with * on *"
  pmapper query "who can do iam:AttachRolePolicy with * on *"
  Cross-reference results with the set of principals lacking Permission Boundaries.

Step 6: Run Prowler for Permission Boundary checks.
  prowler aws -c iam_no_custom_policy_permissive_role_assumption iam_policy_no_administrative_privileges --profile <profile>

Step 7: For service-linked roles and AWS-managed roles (e.g., AWSServiceRoleFor*), note that Permission Boundaries cannot be applied—document these separately as accepted exceptions.

Flag: Any IAM user or role with elevated privileges (AdministratorAccess, wildcard action grants, or IAM modification capabilities) that does not have a Permission Boundary attached is a finding.

------------------------------------------
Procedure 4 — Attempt Actions Missing from SCP Deny List
Tools: aws cli, Pacu
Intrusiveness: medium
Description: Actively tests whether actions that were identified as missing from SCP deny lists (Procedure 1) can actually be executed from a member account. This validates whether the SCP gaps are theoretically exploitable or if other controls (Permission Boundaries, identity policies, resource policies) compensate. Testing is performed using credentials within the in-scope member account. Actions are chosen to be non-destructive where possible, but some tests may involve creating or modifying resources.

Step 1: From the gap analysis in Procedure 1, compile a list of high-impact actions NOT denied by any SCP in the effective chain for the target account.

Step 2: Use aws iam simulate-principal-policy to predict whether actions will succeed before attempting them live.
  aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::<account-id>:user/<username> \
    --action-names organizations:LeaveOrganization \
    --query 'EvaluationResults[*].{Action:EvalActionName, Decision:EvalDecision}'

Step 3: [DOCUMENT ONLY] If organizations:LeaveOrganization is not denied by SCP, document the risk. DO NOT execute this action—it is destructive and irreversible.
  aws organizations leave-organization
  (Record command for documentation; do not execute without explicit authorization.)

Step 4: Test region restriction bypass. If no region-lock SCP exists, attempt to create resources in an unexpected region.
  aws ec2 describe-instances --region ap-southeast-1
  aws s3api create-bucket --bucket pentest-region-test-$(date +%s) --region ap-southeast-1 --create-bucket-configuration LocationConstraint=ap-southeast-1
  If successful, clean up immediately:
  aws s3 rb s3://pentest-region-test-<timestamp> --region ap-southeast-1

Step 5: Test CloudTrail protection bypass. If cloudtrail:StopLogging is not denied by SCP, test with simulation first:
  aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::<account-id>:role/<rolename> \
    --action-names cloudtrail:StopLogging cloudtrail:DeleteTrail cloudtrail:UpdateTrail \
    --query 'EvaluationResults[*].{Action:EvalActionName, Decision:EvalDecision}'
  [DOCUMENT ONLY] If simulation returns "allowed," document the finding. Do NOT stop or delete production trails without explicit written authorization.

Step 6: Use Pacu to automate SCP bypass testing where available.
  pacu
  > import_keys <access_key_id> <secret_key>
  > run iam__enum_permissions
  > run iam__privesc_scan
  Review Pacu output for identified escalation paths that align with SCP gaps.

Step 7: For each tested action, record the result: Denied (SCP effective), Denied (identity policy), Allowed (SCP gap confirmed), or Error (insufficient permissions unrelated to SCP).

Flag: Any action identified as missing from the SCP deny list in Procedure 1 that succeeds (or returns an identity-policy denial rather than an SCP-explicit denial) when tested from the member account is a finding, confirming the SCP gap is exploitable.

------------------------------------------
Procedure 5 — Test Permission Boundary Effectiveness via NotAction Bypass Attempts
Tools: aws cli, Pacu, PMapper
Intrusiveness: medium
Description: Tests whether Permission Boundaries that use NotAction constructs can be bypassed. The NotAction element in an IAM policy inverts the action match—it applies to all actions EXCEPT those listed. If a Permission Boundary uses NotAction in an Allow statement, it effectively permits everything not explicitly listed, which can inadvertently grant access to new services or actions added by AWS after the boundary was written. Similarly, if a Permission Boundary uses NotAction in a Deny statement, it denies everything except the listed actions, but may fail to account for newly introduced IAM actions. This procedure tests these boundary configurations for bypass opportunities.

Step 1: Identify all Permission Boundaries in the account that use NotAction.
  aws iam list-policies --scope Local --query 'Policies[*].{Arn:Arn, PolicyName:PolicyName}'
  For each policy, retrieve the document and search for NotAction:
  aws iam get-policy-version --policy-arn <arn> --version-id <version> --query 'PolicyVersion.Document'
  grep -l "NotAction" across all retrieved policy documents.

Step 2: For each Permission Boundary using NotAction in an Allow statement, list all actions NOT covered by the NotAction list. These are implicitly allowed and represent the bypass surface.
  Example: If NotAction lists ["iam:*", "organizations:*"], then all other services (ec2:*, s3:*, lambda:*, etc.) are allowed by this boundary.

Step 3: Identify recently launched AWS services and actions that may not have been included in the NotAction list at time of creation. Cross-reference with the AWS service changelog or IAM Actions reference.
  Check for services like: bedrock:*, q:*, codecatalyst:*, cleanrooms:*, entityresolution:*, tnb:*, vpc-lattice:*, etc.

Step 4: Test whether a principal with this Permission Boundary can invoke actions in services omitted from the NotAction list.
  aws bedrock list-foundation-models --region us-east-1
  aws cleanrooms list-collaborations --region us-east-1
  aws vpc-lattice list-services --region us-east-1
  If any of these succeed, the Permission Boundary's NotAction construct has a coverage gap.

Step 5: For Permission Boundaries using NotAction in a Deny statement, verify whether the listed (allowed) actions are sufficient. Attempt to invoke actions outside the allowed set to confirm they are properly denied.
  aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::<account-id>:role/<rolename> \
    --action-names <action-outside-notaction-list> \
    --query 'EvaluationResults[*].{Action:EvalActionName, Decision:EvalDecision}'

Step 6: Use PMapper to identify principals whose effective permissions exceed their Permission Boundary's intended scope.
  pmapper graph create --profile <profile>
  pmapper visualize --filetype png
  pmapper query "who can do s3:GetObject with * on *"
  Compare results against Permission Boundary intent.

Step 7: Use Pacu to attempt privilege escalation from a principal with a Permission Boundary.
  pacu
  > run iam__enum_permissions
  > run iam__privesc_scan
  Check whether Pacu identifies escalation paths that circumvent the boundary.

Step 8: Test if the principal can modify its own Permission Boundary (self-mutation).
  aws iam put-role-permissions-boundary --role-name <rolename> --permissions-boundary arn:aws:iam::aws:policy/AdministratorAccess
  If successful, the Permission Boundary can be replaced and is ineffective as a guardrail.
  (Revert immediately if successful):
  aws iam put-role-permissions-boundary --role-name <rolename> --permissions-boundary <original-boundary-arn>

Step 9: Test if the principal can delete its own Permission Boundary.
  aws iam delete-role-permissions-boundary --role-name <rolename>
  If successful, the boundary was removable and the principal operates with full identity-policy permissions.
  (Revert immediately if successful):
  aws iam put-role-permissions-boundary --role-name <rolename> --permissions-boundary <original-boundary-arn>

Flag: Any Permission Boundary using NotAction that allows access to services or actions not intended by the boundary design is a finding. Any principal that can modify or remove its own Permission Boundary is a critical finding. Any privilege escalation path identified by PMapper or Pacu that bypasses the Permission Boundary is a finding.

------------------------------------------
References:
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_strategies.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-organizations-enum
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-iam-privesc
- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- https://github.com/RhinoSecurityLabs/pacu
- https://github.com/nccgroup/PMapper
- https://github.com/prowler-cloud/prowler
- https://github.com/salesforce/cloudsplaining
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html
- https://summitroute.com/blog/2020/03/25/aws_scp_best_practices/
- https://www.wellarchitectedlabs.com/security/100_labs/100_create_a_data_bunker/
