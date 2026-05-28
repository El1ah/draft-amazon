Repeatability: per_asset
Prerequisites: Unauthenticated — DNS enumeration, port scanning, HTTP probing. No valid AWS credentials required for the majority of procedures. Authenticated AWS CLI access with read-only permissions is noted where it provides supplementary validation.
Description: This methodology covers the discovery and enumeration of publicly exposed AWS-hosted endpoints and services. It identifies assets reachable without authentication, including DNS-resolved AWS infrastructure, open API Gateways, unauthenticated Lambda function URLs, publicly accessible compute and database instances, misconfigured load balancers, CloudFront origin bypass conditions, and dangling DNS records susceptible to subdomain takeover. Collectively these checks map the external attack surface of an AWS environment from an unauthenticated perspective.
Tags: endpoint-discovery, dns, api-gateway, lambda-url, elb, cloudfront, subdomain-takeover, unauthenticated, ec2, rds, redshift, elasticache, documentdb, opensearch, attack-surface
Potential Severity: high

------------------------------------------
Procedure 0 — Identify AWS-Hosted Assets via DNS
Tools: dig, host, amass, subfinder, cloud_enum, dnsrecon, httpx
Intrusiveness: passive
Description: Enumerate DNS records (A, AAAA, CNAME, NS, MX, TXT) for the target domain and its subdomains to identify assets hosted on AWS infrastructure. CNAME records pointing to amazonaws.com, cloudfront.net, s3.amazonaws.com, elasticbeanstalk.com, elb.amazonaws.com, and similar suffixes confirm AWS-hosted resources.

Step 1: Perform passive subdomain enumeration against the target domain.
```
subfinder -d example.com -o subdomains.txt
amass enum -passive -d example.com -o amass_subs.txt
cat subdomains.txt amass_subs.txt | sort -u > all_subs.txt
```

Step 2: Resolve each discovered subdomain and inspect CNAME chains for AWS indicators.
```
cat all_subs.txt | while read sub; do
  echo "--- $sub ---"
  dig +short CNAME "$sub"
  dig +short A "$sub"
done | tee dns_resolution.txt
```

Step 3: Filter results for known AWS-hosted suffixes.
```
grep -iE '(amazonaws\.com|cloudfront\.net|s3\.amazonaws\.com|elasticbeanstalk\.com|elb\.amazonaws\.com|awsglobalaccelerator\.com|execute-api\.|s3-website)' dns_resolution.txt | sort -u > aws_assets.txt
```

Step 4: Use cloud_enum to discover cloud resources associated with the target keyword or domain.
```
cloud_enum -k example -k example.com -l cloud_enum_results.txt
```

Step 5: Use s3recon or similar tools to brute-force S3 bucket names derived from the target.
```
s3recon example example-dev example-prod example-backup --thread 10 -o s3_buckets.txt
```

Step 6: Probe all discovered AWS endpoints for HTTP(S) availability and response codes.
```
cat aws_assets.txt | httpx -status-code -title -tech-detect -follow-redirects -o aws_http_probe.txt
```

Flag: Any subdomain or DNS record that resolves via CNAME (or A record) to an AWS-managed service endpoint confirms the target uses AWS-hosted infrastructure and should be subjected to further service-specific testing.

------------------------------------------
Procedure 1 — Enumerate Public API Gateway Endpoints and Spec Exposure
Tools: httpx, ffuf, nuclei, curl, aws cli
Intrusiveness: low
Description: Identify publicly reachable AWS API Gateway endpoints and test for exposed Swagger / OpenAPI specification files. API Gateway REST APIs follow predictable URL patterns (https://{api-id}.execute-api.{region}.amazonaws.com/{stage}). Exposed specification files disclose all routes, parameters, and authorization requirements, enabling targeted attacks.

Step 1: From the DNS discovery results, isolate all execute-api endpoints.
```
grep -i 'execute-api' aws_assets.txt > apigw_endpoints.txt
```

Step 2: For each API Gateway endpoint, probe common specification paths.
```
cat apigw_endpoints.txt | while read endpoint; do
  for path in /swagger.json /openapi.json /swagger.yaml /openapi.yaml /api-docs /v1/swagger.json /v2/swagger.json /v1/api-docs /v2/api-docs /export /restapis; do
    url="https://${endpoint}${path}"
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    echo "$url -> $code"
  done
done | tee apigw_spec_probe.txt
```

Step 3: Use ffuf to fuzz for stage names on discovered API IDs.
```
ffuf -u "https://APIID.execute-api.REGION.amazonaws.com/FUZZ/" -w /usr/share/wordlists/api-stages.txt -mc 200,301,302,403 -o apigw_stages.txt
```

Step 4: Run Nuclei templates targeting API Gateway misconfigurations.
```
nuclei -l apigw_endpoints.txt -t http/misconfiguration/ -t http/exposures/ -o nuclei_apigw.txt
```

Step 5: If authenticated access is available, export the API specification directly.
```
aws apigateway get-rest-apis --region us-east-1
aws apigateway get-export --rest-api-id <api-id> --stage-name <stage> --export-type swagger /tmp/swagger.json
```

Flag: Any API Gateway endpoint returning a valid Swagger/OpenAPI specification file (HTTP 200 with JSON/YAML content) or any endpoint reachable without authentication constitutes a finding.

------------------------------------------
Procedure 2 — Identify Unauthenticated API Gateway Routes
Tools: curl, httpx, Burp Suite, ffuf, aws cli
Intrusiveness: low
Description: Test discovered API Gateway endpoints for routes that do not enforce authentication. API Gateway routes without an authorizer (IAM, Cognito, Lambda authorizer) or API key requirement can be invoked by anyone, potentially exposing sensitive functionality or backend data.

Step 1: For each discovered API Gateway endpoint and stage, enumerate routes using a wordlist.
```
ffuf -u "https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/FUZZ" \
  -w /usr/share/wordlists/api-routes.txt \
  -mc 200,201,204,301,302,400,405 \
  -fc 403 \
  -o apigw_routes.txt
```

Step 2: For each discovered route, send requests without any authorization headers and observe the response.
```
curl -s -D- "https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<route>"
```

Step 3: Verify that removing Authorization, x-api-key, or token headers still returns data.
```
curl -s -D- -H "Authorization: " "https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<route>"
curl -s -D- "https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<route>" | head -50
```

Step 4: Test common HTTP methods on each route for unintended functionality.
```
for method in GET POST PUT DELETE PATCH OPTIONS; do
  echo "--- $method ---"
  curl -s -o /dev/null -w "%{http_code}" -X "$method" "https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<route>"
done
```

Step 5: If authenticated AWS access is available, verify authorizer configuration.
```
aws apigateway get-resources --rest-api-id <api-id> --region <region>
aws apigateway get-method --rest-api-id <api-id> --resource-id <resource-id> --http-method GET --region <region>
```
Look for `"authorizationType": "NONE"` in the output.

Flag: Any API Gateway route that returns a successful response (HTTP 2xx with meaningful body) without providing any authorization header, API key, or session token is a finding. Confirmed when `authorizationType` is `NONE` and no API key is required.

------------------------------------------
Procedure 3 — Enumerate Lambda Function URLs with AuthType=NONE
Tools: curl, httpx, aws cli, nuclei
Intrusiveness: low
Description: AWS Lambda function URLs provide direct HTTPS endpoints to invoke Lambda functions. When configured with AuthType=NONE, these endpoints are publicly accessible without any authentication, potentially exposing sensitive functionality or data processing pipelines to the internet.

Step 1: From DNS or cloud_enum results, identify Lambda function URL patterns.
```
grep -iE '\.lambda-url\.[a-z0-9-]+\.on\.aws' all_subs.txt aws_assets.txt > lambda_urls.txt
```

Step 2: Probe each discovered Lambda function URL for unauthenticated access.
```
cat lambda_urls.txt | while read url; do
  echo "--- $url ---"
  curl -s -D- "https://${url}/"
  echo ""
done | tee lambda_url_responses.txt
```

Step 3: Test with various HTTP methods and payloads.
```
curl -s -D- -X POST "https://<function-url>.lambda-url.<region>.on.aws/" \
  -H "Content-Type: application/json" \
  -d '{"test": "probe"}'
```

Step 4: If authenticated AWS access is available, enumerate all Lambda function URLs and their auth types.
```
aws lambda list-functions --region <region> --query 'Functions[].FunctionName' --output text | tr '\t' '\n' | while read fn; do
  echo "--- $fn ---"
  aws lambda get-function-url-config --function-name "$fn" --region <region> 2>/dev/null
done | tee lambda_url_configs.txt
```

Step 5: Filter for functions with AuthType NONE.
```
grep -B5 '"AuthType": "NONE"' lambda_url_configs.txt
```

Flag: Any Lambda function URL that responds to unauthenticated requests (HTTP 2xx) or is confirmed to have `AuthType: NONE` via API enumeration is a finding.

------------------------------------------
Procedure 4 — Enumerate Public EC2 Instances with Open Sensitive Ports
Tools: nmap, masscan, shodan, censys, aws cli
Intrusiveness: low
Description: Identify EC2 instances with public IP addresses that expose sensitive management or service ports to the internet. Open ports such as SSH (22), RDP (3389), HTTP (80/443/8080/8443), and database ports indicate a larger attack surface and potential entry points.

Step 1: Collect public IPs from DNS resolution and cloud enumeration results.
```
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' dns_resolution.txt | sort -u > public_ips.txt
```

Step 2: Query Shodan for AWS IP ranges associated with the target.
```
shodan search "org:example hostname:amazonaws.com" --fields ip_str,port,org --separator , > shodan_ec2.csv
```

Step 3: Query Censys for exposed services.
```
censys search "services.tls.certificates.leaf.subject.common_name: example.com AND autonomous_system.name: AMAZON" --index-type hosts
```

Step 4: Perform targeted port scanning against collected IPs for sensitive ports.
```
nmap -Pn -sS -p 22,3389,80,443,8080,8443,3306,5432,1433,27017,6379,9200,9300,5601 \
  -iL public_ips.txt -oA ec2_sensitive_ports --open
```

Step 5: Use masscan for rapid large-scale scanning if the IP list is extensive.
```
masscan -iL public_ips.txt -p 22,3389,80,443,8080,8443 --rate 1000 -oL masscan_results.txt
```

Step 6: If authenticated AWS access is available, enumerate public EC2 instances and their security groups.
```
aws ec2 describe-instances --region <region> \
  --filters "Name=ip-address,Values=*" \
  --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,SecurityGroups[].GroupId]' \
  --output table
```

Step 7: Check security group rules for overly permissive inbound access (0.0.0.0/0).
```
aws ec2 describe-security-groups --region <region> \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName,IpPermissions[].{Port:FromPort,Proto:IpProtocol,CIDR:IpRanges[].CidrIp}]' \
  --output json
```

Flag: Any EC2 instance with a public IP exposing ports 22, 3389, 80, 443, 8080, or 8443 to 0.0.0.0/0 is a finding. Findings are critical if management ports (22, 3389) are open to the internet.

------------------------------------------
Procedure 5 — Identify Internet-Facing ELB / ALB / NLB Without Authentication
Tools: curl, httpx, nmap, aws cli, nuclei
Intrusiveness: low
Description: Discover internet-facing Elastic Load Balancers (Classic ELB, Application ALB, Network NLB) that serve backend content without enforcing authentication. Load balancers without authentication at the listener or target group level expose backend applications directly to the internet.

Step 1: From DNS results, isolate load balancer endpoints.
```
grep -iE '(elb\.amazonaws\.com|\.us-east-1\.elb\.amazonaws\.com|\.eu-west-1\.elb\.amazonaws\.com)' aws_assets.txt > elb_endpoints.txt
```

Step 2: Probe each ELB/ALB/NLB endpoint for unauthenticated HTTP(S) access.
```
cat elb_endpoints.txt | httpx -status-code -title -tech-detect -content-length -follow-redirects -o elb_http_probe.txt
```

Step 3: Check for common unauthenticated paths returning sensitive data.
```
cat elb_endpoints.txt | while read elb; do
  for path in / /health /status /api /admin /login /graphql /metrics /actuator; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${elb}${path}")
    echo "$elb$path -> $code"
  done
done | tee elb_path_probe.txt
```

Step 4: Run Nuclei against ELB endpoints for known misconfigurations.
```
nuclei -l elb_endpoints.txt -t http/misconfiguration/ -t http/exposures/ -o nuclei_elb.txt
```

Step 5: If authenticated AWS access is available, enumerate all internet-facing load balancers.
```
aws elbv2 describe-load-balancers --region <region> \
  --query 'LoadBalancers[?Scheme==`internet-facing`].[LoadBalancerName,DNSName,Type,Scheme]' \
  --output table
```

Step 6: Check ALB listener rules for authentication actions (Cognito or OIDC).
```
aws elbv2 describe-listeners --load-balancer-arn <lb-arn> --region <region>
aws elbv2 describe-rules --listener-arn <listener-arn> --region <region> \
  --query 'Rules[].[Priority,Actions[].Type]' --output table
```
Look for missing `authenticate-cognito` or `authenticate-oidc` action types.

Flag: Any internet-facing ELB/ALB/NLB that serves application content (HTTP 2xx) without requiring authentication, or whose listener rules lack authenticate-cognito or authenticate-oidc actions, is a finding.

------------------------------------------
Procedure 6 — Test CloudFront Distributions for Direct S3 Origin Bypass (Missing OAC/OAI)
Tools: curl, aws cli, dig, httpx
Intrusiveness: low
Description: CloudFront distributions backed by S3 origins should use Origin Access Control (OAC) or the legacy Origin Access Identity (OAI) to restrict direct access to the S3 bucket. If neither is configured, the S3 bucket may be directly accessible, bypassing CloudFront caching, WAF rules, and access controls.

Step 1: From DNS results, identify CloudFront distribution domains.
```
grep -iE 'cloudfront\.net' aws_assets.txt > cloudfront_endpoints.txt
```

Step 2: For each CloudFront distribution, attempt to identify the S3 origin bucket.
```
cat cloudfront_endpoints.txt | while read cf; do
  echo "--- $cf ---"
  curl -sI "https://${cf}/" | grep -i 'x-amz-\|server\|x-cache'
done | tee cf_headers.txt
```

Step 3: Attempt direct S3 access using common bucket naming patterns derived from the target domain.
```
for bucket in example.com www.example.com assets.example.com static.example.com cdn.example.com; do
  echo "--- $bucket ---"
  curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com/"
  curl -s -o /dev/null -w "%{http_code}" "http://${bucket}.s3.amazonaws.com/"
done
```

Step 4: If the S3 origin bucket is identified, test for unauthenticated listing and object access.
```
aws s3 ls s3://<bucket-name> --no-sign-request
curl -s "https://<bucket-name>.s3.amazonaws.com/" | head -100
```

Step 5: If authenticated AWS access is available, verify OAC/OAI configuration.
```
aws cloudfront list-distributions --query 'DistributionList.Items[].[Id,DomainName,Origins.Items[].{DomainName:DomainName,OAI:S3OriginConfig.OriginAccessIdentity,OAC:OriginAccessControlId}]' --output json
```

Step 6: Check if the S3 bucket policy restricts access to CloudFront only.
```
aws s3api get-bucket-policy --bucket <bucket-name> --output json 2>/dev/null | python3 -m json.tool
```
Look for conditions requiring `aws:SourceArn` matching the CloudFront distribution ARN or `aws:Referer` headers — neither of which is a strong restriction without OAC/OAI.

Flag: A finding exists if an S3 origin bucket behind CloudFront is directly accessible (listing or object retrieval) without going through CloudFront, indicating missing or misconfigured OAC/OAI. Confirmed when `OriginAccessIdentity` is empty and `OriginAccessControlId` is null.

------------------------------------------
Procedure 7 — Identify Publicly Accessible RDS / Redshift Instances
Tools: nmap, aws cli, psql, mysql, Shodan
Intrusiveness: low
Description: Amazon RDS and Redshift instances configured with public accessibility and permissive security groups can be reached from the internet. This exposes database services to brute-force attacks, credential stuffing, and exploitation of database engine vulnerabilities.

Step 1: From DNS results, identify RDS and Redshift endpoints.
```
grep -iE '(rds\.amazonaws\.com|redshift\.amazonaws\.com)' dns_resolution.txt aws_assets.txt > db_endpoints.txt
```

Step 2: Resolve and port-scan each database endpoint for default ports.
```
cat db_endpoints.txt | while read db; do
  ip=$(dig +short "$db" | tail -1)
  echo "$db -> $ip"
done > db_ips.txt

nmap -Pn -sS -p 3306,5432,1433,1521,5439 -iL db_endpoints.txt -oA rds_scan --open
```

Step 3: Attempt connection to identified open ports (observe only, do not authenticate with guessed credentials).
```
# PostgreSQL (RDS/Aurora)
psql -h <rds-endpoint> -p 5432 -U postgres -c "\conninfo" 2>&1 | head -5

# MySQL (RDS/Aurora)
mysql -h <rds-endpoint> -P 3306 -u root --connect-timeout=5 -e "SELECT 1;" 2>&1 | head -5

# Redshift
psql -h <redshift-endpoint> -p 5439 -U awsuser -d dev -c "\conninfo" 2>&1 | head -5
```

Step 4: Query Shodan for publicly exposed RDS/Redshift instances.
```
shodan search "port:5432 org:Amazon" --fields ip_str,port,hostnames
shodan search "port:5439 product:Redshift" --fields ip_str,port,hostnames
```

Step 5: If authenticated AWS access is available, enumerate publicly accessible instances.
```
aws rds describe-db-instances --region <region> \
  --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Endpoint.Address,Endpoint.Port,PubliclyAccessible,Engine]' \
  --output table

aws redshift describe-clusters --region <region> \
  --query 'Clusters[?PubliclyAccessible==`true`].[ClusterIdentifier,Endpoint.Address,Endpoint.Port,PubliclyAccessible]' \
  --output table
```

Step 6: Inspect associated security groups for 0.0.0.0/0 inbound rules on database ports.
```
aws ec2 describe-security-groups --group-ids <sg-id> --region <region> \
  --query 'SecurityGroups[].IpPermissions[?FromPort==`5432` || FromPort==`3306` || FromPort==`5439`]'
```

Flag: Any RDS or Redshift instance that is publicly accessible (PubliclyAccessible=true) and has security group rules permitting inbound connections from 0.0.0.0/0 on its database port is a finding. Confirmed if a TCP connection to the database port can be established from the internet.

------------------------------------------
Procedure 8 — Identify Exposed ElastiCache / DocumentDB / OpenSearch Endpoints
Tools: nmap, curl, aws cli, redis-cli, mongosh, Shodan
Intrusiveness: low
Description: AWS managed data stores such as ElastiCache (Redis, Memcached), DocumentDB (MongoDB-compatible), and OpenSearch (Elasticsearch-compatible) are typically designed for VPC-internal access. Misconfigured networking, public subnets, or transit gateway routes can inadvertently expose these services to the internet, allowing unauthenticated data access.

Step 1: From DNS and cloud enumeration, identify potential data store endpoints.
```
grep -iE '(cache\.amazonaws\.com|docdb\.amazonaws\.com|es\.amazonaws\.com|aoss\.amazonaws\.com)' dns_resolution.txt aws_assets.txt > datastore_endpoints.txt
```

Step 2: Port-scan discovered endpoints for data store default ports.
```
nmap -Pn -sS -p 6379,11211,27017,9200,9300,443 -iL datastore_endpoints.txt -oA datastore_scan --open
```

Step 3: Test for unauthenticated Redis access.
```
redis-cli -h <elasticache-endpoint> -p 6379 PING
redis-cli -h <elasticache-endpoint> -p 6379 INFO server
```

Step 4: Test for unauthenticated OpenSearch / Elasticsearch access.
```
curl -s "https://<opensearch-endpoint>:443/"
curl -s "https://<opensearch-endpoint>:443/_cluster/health"
curl -s "https://<opensearch-endpoint>:443/_cat/indices?v"
curl -s "https://<opensearch-endpoint>:443/_search?q=*&size=5"
```

Step 5: Test for unauthenticated DocumentDB / MongoDB access.
```
mongosh --host <docdb-endpoint> --port 27017 --eval "db.adminCommand('listDatabases')" 2>&1 | head -20
```

Step 6: If authenticated AWS access is available, check for publicly reachable configurations.
```
# ElastiCache
aws elasticache describe-cache-clusters --region <region> \
  --query 'CacheClusters[].[CacheClusterId,Engine,ConfigurationEndpoint,CacheNodes[].Endpoint]' --output json

# OpenSearch
aws opensearch describe-domains --region <region>
aws opensearch describe-domain --domain-name <domain> --region <region> \
  --query 'DomainStatus.{Endpoint:Endpoint,VPC:VPCOptions,AccessPolicies:AccessPolicies}'

# DocumentDB
aws docdb describe-db-clusters --region <region> \
  --query 'DBClusters[].[DBClusterIdentifier,Endpoint,Port]' --output table
```

Step 7: Review OpenSearch access policies for wildcard principal or open IP-based policies.
```
aws opensearch describe-domain --domain-name <domain> --region <region> \
  --query 'DomainStatus.AccessPolicies' --output text | python3 -m json.tool
```
Look for `"Principal": "*"` or `"Condition"` blocks with broad IP ranges.

Flag: Any ElastiCache, DocumentDB, or OpenSearch endpoint that responds to unauthenticated queries from the internet is a finding. For OpenSearch, an access policy with `Principal: *` and no IP/VPC restriction is also a finding.

------------------------------------------
Procedure 9 — Identify Dangling DNS Records Pointing to Released Resources (Subdomain Takeover)
Tools: subjack, nuclei, can-i-take-over-xyz, dig, httpx, aws cli
Intrusiveness: passive
Description: DNS records (typically CNAMEs) that point to AWS resources which have been deprovisioned — such as deleted S3 buckets, deregistered Elastic Beanstalk environments, released Elastic IPs, or removed CloudFront distributions — can be claimed by an attacker. This enables subdomain takeover, allowing the attacker to serve arbitrary content under the victim's domain, potentially leading to credential theft, phishing, or cookie hijacking.

Step 1: Collect all CNAME records pointing to AWS services.
```
cat all_subs.txt | while read sub; do
  cname=$(dig +short CNAME "$sub")
  if echo "$cname" | grep -qiE '(amazonaws\.com|cloudfront\.net|elasticbeanstalk\.com|s3\.amazonaws\.com|awsglobalaccelerator\.com)'; then
    echo "$sub -> $cname"
  fi
done | tee aws_cnames.txt
```

Step 2: Check each CNAME target for signs of unclaimed resources.
```
cat aws_cnames.txt | while read line; do
  sub=$(echo "$line" | awk '{print $1}')
  echo "--- $sub ---"
  curl -s -o /dev/null -w "%{http_code}" "http://${sub}"
  curl -s "http://${sub}" 2>&1 | head -20
done | tee dangling_check.txt
```

Step 3: Look for known takeover signatures in responses.
```
# S3 bucket takeover indicator
grep -i "NoSuchBucket" dangling_check.txt

# Elastic Beanstalk takeover indicator
grep -i "NXDOMAIN" dangling_check.txt

# CloudFront takeover indicator (distribution removed but CNAME remains)
grep -i "Bad Request\|The request could not be satisfied\|ERROR: The request could not be satisfied" dangling_check.txt
```

Step 4: Run subjack for automated subdomain takeover detection.
```
subjack -w all_subs.txt -t 50 -timeout 30 -ssl -c /path/to/fingerprints.json -o subjack_results.txt -v
```

Step 5: Run Nuclei with takeover templates.
```
nuclei -l all_subs.txt -t http/takeovers/ -o nuclei_takeover.txt
```

Step 6: Cross-reference with the can-i-take-over-xyz project for up-to-date takeover fingerprints.
```
# Reference: https://github.com/EdOverflow/can-i-take-over-xyz
# Check each identified dangling record against the fingerprint database
```

Step 7: [DOCUMENT ONLY] For confirmed dangling S3 CNAMEs, an attacker could register the bucket name.
```
# DOCUMENT ONLY — DO NOT EXECUTE without explicit authorization
# aws s3 mb s3://<dangling-bucket-name> --region <region>
# This would allow serving arbitrary content under the victim's subdomain
```

Step 8: If authenticated AWS access is available, identify orphaned Route 53 records.
```
aws route53 list-hosted-zones --query 'HostedZones[].[Id,Name]' --output table
aws route53 list-resource-record-sets --hosted-zone-id <zone-id> \
  --query 'ResourceRecordSets[?Type==`CNAME`].[Name,ResourceRecords[].Value]' --output table
```
Cross-reference CNAME targets with active resources in the account.

Flag: Any DNS CNAME record pointing to an AWS resource that returns a known takeover signature (NoSuchBucket, NXDOMAIN for Elastic Beanstalk, CloudFront error for removed distributions) is a finding. Severity is critical if the resource can be claimed by a third party.

------------------------------------------
References:
- AWS API Gateway Developer Guide: https://docs.aws.amazon.com/apigateway/latest/developerguide/
- AWS Lambda Function URLs: https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html
- AWS CloudFront Origin Access Control: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
- AWS RDS Public Accessibility: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html
- AWS OpenSearch Access Policies: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html
- AWS Security Groups Documentation: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html
- HackTricks Cloud — AWS Pentesting: https://cloud.hacktricks.xyz/pentesting-cloud/aws-security
- Can I Take Over XYZ: https://github.com/EdOverflow/can-i-take-over-xyz
- Rhino Security Labs — AWS Attack Research: https://rhinosecuritylabs.com/aws/
- cloud_enum: https://github.com/initstring/cloud_enum
- subjack: https://github.com/haccer/subjack
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates
- Shodan: https://www.shodan.io/
- Censys: https://search.censys.io/
