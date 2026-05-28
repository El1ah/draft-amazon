# APPENDIX B | Toolchain Reference

| Tool | Purpose | Phase |
|------|---------|-------|
| cloud_enum / s3recon | S3 bucket discovery | AWS-1 |
| trufflehog / gitleaks | Secret scanning in repos | AWS-1.4 |
| enumerate-iam | Permission enumeration from valid creds | AWS-2.1 |
| CloudFox | Attack surface mapping (secrets, endpoints, roles) | AWS-2.2 |
| PMapper | IAM privilege escalation graph | AWS-3 |
| CloudSplaining | IAM policy analysis report | AWS-3.1 |
| Pacu | AWS exploitation framework | AWS-3, AWS-4 |
| IAM Access Analyzer | External access findings | AWS-3.1 |
| Prowler | Config assessment + CIS/FSBP (optional) | OPT-2 |
| ScoutSuite | Multi-service config review (optional) | OPT-2 |
| Checkov / tfsec / cfn-nag | IaC static analysis | OPT |
