# Part 0: Engagement Setup & Scoping

> NOT a checklist. Pre-engagement template to be completed before testing begins.
> Output: signed scoping document, provisioned credentials, agreed Rules of Engagement.

## Scoping Document Template

**Client:** _______________
**Assessment Type:** AWS Cloud Penetration Test
**Date:** _______________
**Lead Tester:** _______________

### In-Scope Definition
- AWS Account IDs: _______________
- OUs in scope: _______________
- Regions in scope: _______________
- Services in scope (if restricted): _______________
- Services explicitly out of scope: _______________

### Credential Provisioning
- [ ] Unauthenticated testing only
- [ ] Read-only audit role provisioned (SecurityAudit / ViewOnlyAccess)
- [ ] Assumed breach role provisioned (specify permissions): _______________
- [ ] Additional test accounts/users: _______________

### Rules of Engagement
- [ ] Destructive actions permitted: YES / NO
- [ ] Data access (read sensitive data for PoC): YES / NO
- [ ] Snapshot/image creation permitted: YES / NO
- [ ] Active exploitation of production resources: YES / NO
- [ ] DoS / resource exhaustion testing: YES / NO
- [ ] Out-of-band exfiltration simulation: YES / NO

### Timing
- Assessment window: _______________
- Rate limit expectations: _______________
- Emergency stop contact: _______________

### Data Handling
- Evidence storage: _______________
- Retention period: _______________
- Confidentiality level: _______________

### Alignment
- [ ] AWS Customer Penetration Testing Policy reviewed and aligned
- [ ] Client has provided written authorization
- [ ] Emergency escalation contacts documented
