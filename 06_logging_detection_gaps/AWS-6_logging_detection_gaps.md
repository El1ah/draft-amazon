Repeatability: per_account
Prerequisites: Valid AWS credentials with cloudtrail:Describe*, guardduty:List*, securityhub:Describe*, ec2:DescribeFlowLogs, logs:Describe* permissions
Description: Assess the completeness and effectiveness of the target environment's logging, monitoring, and threat detection capabilities across CloudTrail, GuardDuty, Security Hub, VPC Flow Logs, and CloudWatch. Identify gaps that would allow attacker activity to go undetected.
Tags: logging, detection, cloudtrail, guardduty, security-hub, vpc-flow-logs, cloudwatch, monitoring
Potential Severity: high

------------------------------------------
Procedure 0 — Verify Multi-Region Trail Exists Per Account
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Verify that a multi-region CloudTrail trail is configured in each account to ensure all API activity is captured regardless of the region where it occurs.

Step 1: List all trails and check multi-region status:
  aws cloudtrail describe-trails --query 'trailList[*].[Name,HomeRegion,IsMultiRegionTrail,IsOrganizationTrail,S3BucketName]' --output table

Step 2: Verify at least one multi-region trail exists:
  multi_region=$(aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`] | length(@)' --output text)
  if [ "$multi_region" -eq 0 ]; then echo "FINDING: No multi-region trail configured"; fi

Step 3: Verify trail is actively logging:
  for trail in $(aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`].TrailARN' --output text); do
    aws cloudtrail get-trail-status --name "$trail" --query '[IsLogging,LatestDeliveryTime]'
  done

Step 4: Prowler automated check:
  prowler aws -c cloudtrail_multi_region_enabled

Flag: No multi-region CloudTrail trail is configured, or the existing trail is not actively logging.

------------------------------------------
Procedure 1 — Verify Log File Integrity Validation Enabled
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Verify that CloudTrail log file integrity validation (digest files) is enabled, which ensures tamper detection for delivered log files.

Step 1: Check integrity validation status:
  aws cloudtrail describe-trails --query 'trailList[*].[Name,LogFileValidationEnabled]' --output table

Step 2: For any trail without validation:
  for trail in $(aws cloudtrail describe-trails --query 'trailList[?LogFileValidationEnabled==`false`].Name' --output text); do
    echo "FINDING: Trail '$trail' does not have log file integrity validation enabled"
  done

Step 3: Verify digest files are being delivered:
  aws cloudtrail get-trail-status --name <trail-name> --query 'LatestDigestDeliveryTime'

Step 4: Prowler check:
  prowler aws -c cloudtrail_log_file_validation_enabled

Flag: One or more CloudTrail trails have log file integrity validation disabled, meaning log tampering cannot be detected.

------------------------------------------
Procedure 2 — Verify CloudTrail S3 Bucket Has Block Public Access
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Verify that the S3 bucket storing CloudTrail logs has Block Public Access enabled and appropriate access controls to prevent unauthorized log access or tampering.

Step 1: Identify CloudTrail S3 buckets:
  aws cloudtrail describe-trails --query 'trailList[*].[Name,S3BucketName]' --output table

Step 2: Check Block Public Access:
  for bucket in $(aws cloudtrail describe-trails --query 'trailList[*].S3BucketName' --output text | sort -u); do
    echo "=== $bucket ==="
    aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "FINDING: No Block Public Access configuration"
  done

Step 3: Check bucket policy:
  for bucket in $(aws cloudtrail describe-trails --query 'trailList[*].S3BucketName' --output text | sort -u); do
    aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null | python3 -m json.tool
  done

Step 4: Check bucket ACL:
  for bucket in $(aws cloudtrail describe-trails --query 'trailList[*].S3BucketName' --output text | sort -u); do
    aws s3api get-bucket-acl --bucket "$bucket"
  done

Step 5: Prowler check:
  prowler aws -c s3_bucket_public_access

Flag: CloudTrail log bucket does not have Block Public Access enabled, or has overly permissive bucket policy/ACL.

------------------------------------------
Procedure 3 — Verify S3 / Lambda Data Events Enabled Where Required
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Verify that CloudTrail data events are enabled for S3 (object-level access) and Lambda (function invocations) to ensure complete visibility into data access patterns.

Step 1: Check event selectors for each trail:
  for trail in $(aws cloudtrail describe-trails --query 'trailList[*].TrailARN' --output text); do
    echo "=== $trail ==="
    aws cloudtrail get-event-selectors --trail-name "$trail" --output json
  done

Step 2: Check for S3 data events:
  # Look for DataResources with Type: AWS::S3::Object
  # IncludeManagementEvents should be true
  # ReadWriteType should be "All" (not just "ReadOnly" or "WriteOnly")

Step 3: Check for Lambda data events:
  # Look for DataResources with Type: AWS::Lambda::Function

Step 4: Document gaps:
  - S3 data events missing → GetObject/PutObject/DeleteObject not logged
  - Lambda data events missing → Invoke not logged
  - Only specific buckets/functions covered vs all

Step 5: Prowler checks:
  prowler aws -c cloudtrail_s3_dataevents_read_enabled cloudtrail_s3_dataevents_write_enabled cloudtrail_lambda_dataevents_enabled

Flag: S3 or Lambda data events are not enabled in CloudTrail, creating blind spots for data access and function invocation monitoring.

------------------------------------------
Procedure 4 — Verify CloudTrail-to-CloudWatch Logs Integration
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Verify that CloudTrail is integrated with CloudWatch Logs for real-time alerting and metric filter-based monitoring of security-relevant API events.

Step 1: Check CloudWatch Logs integration:
  aws cloudtrail describe-trails --query 'trailList[*].[Name,CloudWatchLogsLogGroupArn,CloudWatchLogsRoleArn]' --output table

Step 2: Verify log delivery is current:
  for trail in $(aws cloudtrail describe-trails --query 'trailList[*].TrailARN' --output text); do
    aws cloudtrail get-trail-status --name "$trail" --query '[LatestCloudWatchLogsDeliveryTime,LatestCloudWatchLogsDeliveryError]'
  done

Step 3: Check for metric filters on the CloudWatch log group:
  log_group=$(aws cloudtrail describe-trails --query 'trailList[0].CloudWatchLogsLogGroupArn' --output text | sed 's/.*log-group://' | sed 's/:.*//')
  aws logs describe-metric-filters --log-group-name "$log_group" --query 'metricFilters[*].[filterName,filterPattern]' --output table

Step 4: Prowler check:
  prowler aws -c cloudtrail_cloudwatch_logging_enabled

Flag: CloudTrail is not integrated with CloudWatch Logs, or integration exists but no metric filters/alarms are configured for security events.

------------------------------------------
Procedure 5 — Verify GuardDuty Enabled in All Active Regions
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Verify that Amazon GuardDuty is enabled in all active regions to provide threat detection coverage.

Step 1: Check GuardDuty status in all regions:
  for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
    detector=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null)
    if [ "$detector" = "None" ] || [ -z "$detector" ]; then
      echo "FINDING: GuardDuty NOT enabled in region: $region"
    else
      status=$(aws guardduty get-detector --detector-id "$detector" --region "$region" --query 'Status' --output text)
      echo "OK: $region | Detector: $detector | Status: $status"
    fi
  done

Step 2: Prowler check:
  prowler aws -c guardduty_is_enabled

Flag: GuardDuty is not enabled in one or more active regions, leaving those regions without threat detection.

------------------------------------------
Procedure 6 — Verify GuardDuty Organization-Level Auto-Enroll
Tools: aws cli
Intrusiveness: passive
Description: Verify that GuardDuty is configured at the Organization level with auto-enroll for new member accounts.

Step 1: Check for delegated administrator:
  aws guardduty list-organization-admin-accounts

Step 2: Check auto-enable configuration:
  detector_id=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
  aws guardduty describe-organization-configuration --detector-id "$detector_id" 2>/dev/null

Step 3: List member accounts and their status:
  aws guardduty list-members --detector-id "$detector_id" --query 'Members[*].[AccountId,RelationshipStatus]' --output table 2>/dev/null

Flag: GuardDuty is not configured with Organization-level management and auto-enroll, meaning new accounts may not have threat detection.

------------------------------------------
Procedure 7 — Verify GuardDuty Protection Plans
Tools: aws cli
Intrusiveness: passive
Description: Verify that additional GuardDuty protection plans (EKS, S3, Malware, RDS, Lambda) are enabled for comprehensive threat coverage.

Step 1: Check enabled features:
  detector_id=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
  aws guardduty get-detector --detector-id "$detector_id" --query 'Features'

Step 2: Verify specific protections:
  # S3 Protection — detects suspicious S3 access patterns
  # EKS Audit Log Monitoring — detects Kubernetes-level threats
  # Malware Protection — scans EBS volumes for malware
  # RDS Protection — detects suspicious RDS login activity
  # Lambda Protection — detects threats in Lambda function activity
  # Runtime Monitoring — detects runtime threats in EC2/ECS/EKS

Step 3: Document missing protections and their implications.

Flag: One or more GuardDuty protection plans are disabled, reducing threat detection coverage for specific services.

------------------------------------------
Procedure 8 — Verify Security Hub Cross-Region Aggregation
Tools: aws cli
Intrusiveness: passive
Description: Verify that Security Hub findings are aggregated across all regions into a single view for comprehensive security posture management.

Step 1: Check Security Hub status:
  aws securityhub describe-hub 2>/dev/null

Step 2: Check finding aggregation configuration:
  aws securityhub get-finding-aggregator --finding-aggregator-arn <arn> 2>/dev/null
  # Or list aggregators:
  aws securityhub list-finding-aggregators 2>/dev/null

Step 3: Check enabled standards:
  aws securityhub get-enabled-standards --query 'StandardsSubscriptions[*].[StandardsArn,StandardsStatus]' --output table

Step 4: Verify GuardDuty findings integration:
  aws securityhub list-enabled-products-for-import --query 'ProductSubscriptions' --output table

Flag: Security Hub is not enabled, does not aggregate findings across regions, or is missing key standard subscriptions (CIS, FSBP).

------------------------------------------
Procedure 9 — Verify GuardDuty Findings Export to S3 / Security Hub
Tools: aws cli
Intrusiveness: passive
Description: Verify that GuardDuty findings are exported for long-term retention and correlation.

Step 1: Check publishing destination:
  detector_id=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
  aws guardduty list-publishing-destinations --detector-id "$detector_id"

Step 2: Check finding publishing frequency:
  aws guardduty get-detector --detector-id "$detector_id" --query 'FindingPublishingFrequency'

Step 3: Verify Security Hub integration:
  # GuardDuty findings should automatically appear in Security Hub when both are enabled

Step 4: Check for any suppression rules:
  aws guardduty list-filters --detector-id "$detector_id"

Flag: GuardDuty findings are not exported to S3 for long-term retention, or finding publishing frequency is not set to FIFTEEN_MINUTES.

------------------------------------------
Procedure 10 — Verify VPC Flow Logs Enabled on All VPCs
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Verify that VPC Flow Logs are enabled on all VPCs to capture network traffic metadata for security analysis.

Step 1: Enumerate all VPCs and check for flow logs:
  for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text); do
    flow_logs=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --query 'FlowLogs[*].[FlowLogId,TrafficType,LogDestination]' --output text)
    if [ -z "$flow_logs" ]; then
      echo "FINDING: No Flow Logs on VPC: $vpc"
    else
      echo "OK: $vpc | $flow_logs"
    fi
  done

Step 2: Prowler check:
  prowler aws -c vpc_flow_logs_enabled

Flag: One or more VPCs do not have Flow Logs enabled, creating network-level visibility gaps.

------------------------------------------
Procedure 11 — Verify Flow Logs Cover ACCEPT and REJECT
Tools: aws cli
Intrusiveness: passive
Description: Verify that VPC Flow Logs capture both ACCEPT and REJECT traffic (or ALL) for complete network visibility.

Step 1: Check flow log traffic type:
  aws ec2 describe-flow-logs --query 'FlowLogs[*].[FlowLogId,ResourceId,TrafficType,LogDestination]' --output table

Step 2: Identify flow logs capturing only ACCEPT or only REJECT:
  for flow_log in $(aws ec2 describe-flow-logs --query 'FlowLogs[?TrafficType!=`ALL`].FlowLogId' --output text); do
    traffic=$(aws ec2 describe-flow-logs --flow-log-ids "$flow_log" --query 'FlowLogs[0].TrafficType' --output text)
    resource=$(aws ec2 describe-flow-logs --flow-log-ids "$flow_log" --query 'FlowLogs[0].ResourceId' --output text)
    echo "FINDING: Flow Log $flow_log on $resource captures only $traffic traffic"
  done

Flag: Flow Logs capture only ACCEPT or only REJECT traffic instead of ALL, missing either successful connections or blocked attempts.

------------------------------------------
Procedure 12 — Verify CloudWatch Alarms for Critical Security Events
Tools: aws cli, Prowler
Intrusiveness: passive
Description: Verify that CloudWatch alarms are configured for critical security events including root account usage, IAM changes, unauthorized API calls, and console login without MFA.

Step 1: List existing CloudWatch alarms:
  aws cloudwatch describe-alarms --query 'MetricAlarms[*].[AlarmName,MetricName,Namespace]' --output table

Step 2: Check for metric filters on CloudTrail log group:
  log_group=$(aws cloudtrail describe-trails --query 'trailList[0].CloudWatchLogsLogGroupArn' --output text | sed 's/.*log-group://' | sed 's/:.*//')
  aws logs describe-metric-filters --log-group-name "$log_group" --query 'metricFilters[*].[filterName,filterPattern]' --output table

Step 3: Check for required CIS Benchmark alarms:
  - Root account usage: { $.userIdentity.type = "Root" }
  - Unauthorized API calls: { ($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied*") }
  - IAM policy changes: { ($.eventName = "DeleteGroupPolicy") || ... }
  - Console login without MFA: { ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }
  - CloudTrail config changes: { ($.eventName = "StopLogging") || ($.eventName = "DeleteTrail") }
  - S3 bucket policy changes
  - Security group changes
  - Network ACL changes
  - VPC changes

Step 4: Prowler CIS checks:
  prowler aws -c cloudwatch_log_metric_filter_root_usage cloudwatch_log_metric_filter_unauthorized_api_calls cloudwatch_log_metric_filter_iam_policy_changes

Flag: Critical CIS Benchmark CloudWatch alarms are missing — root usage, unauthorized API calls, IAM changes, or console login without MFA are not monitored.

------------------------------------------
References:
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html
- https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
- https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
- https://d1.awsstatic.com/whitepapers/compliance/CIS_Amazon_Web_Services_Foundations_Benchmark.pdf
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-logging
- https://github.com/prowler-cloud/prowler
