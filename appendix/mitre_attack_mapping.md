# APPENDIX A | MITRE ATT&CK for Cloud Mapping

| Tactic | Technique | Checklist Reference |
|--------|-----------|-------------------|
| Initial Access | Valid Accounts (T1078) | AWS-1.4 |
| Initial Access | Exploit Public-Facing Application (T1190) | AWS-1.2 |
| Credential Access | Unsecured Credentials in Cloud Storage (T1552.005) | AWS-1.2, AWS-4.4, AWS-4.5 |
| Credential Access | Instance Metadata API (T1552.005) | AWS-4.6.3, AWS-4.6.4 |
| Privilege Escalation | Cloud Account Permissions (T1098.003) | AWS-3.2 |
| Privilege Escalation | Valid Accounts: Cloud (T1078.004) | AWS-3.3 |
| Defense Evasion | Disable Cloud Logs (T1562.008) | AWS-5.4 |
| Lateral Movement | Use Alternate Auth Material (T1550) | AWS-5.2 |
| Collection | Data from Cloud Storage (T1530) | AWS-5.3 |
| Exfiltration | Transfer Data to Cloud Account (T1537) | AWS-5.3 |
| Impact | Data Destruction (T1485) | AWS-5.5 |
| Persistence | Create Cloud Instance (T1578.002) | AWS-5.1 |
