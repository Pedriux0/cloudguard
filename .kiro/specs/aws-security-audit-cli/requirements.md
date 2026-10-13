# Requirements Document

## Introduction

`cloudguard` is a read-only Python command-line tool that audits an AWS account for common security misconfigurations and produces a report. Each finding is mapped to a CIS AWS Foundations Benchmark control. The project is a portfolio piece for a graduating developer with CompTIA Security+ and AWS Solutions Architect Associate certifications, built in roughly one hour.

The tool is hardened in line with its own subject matter. It can't change AWS resources. It shows nothing until the user authenticates with MFA. It runs as an in-memory interactive session that leaves no command history. It locks itself and wipes the screen after 10 minutes of inactivity.

Constraints:
- **Free to run.** The tool only uses read/describe/list AWS API calls plus STS `AssumeRole`, which have no charge. The IAM role and its CloudFormation stack are also free. It never creates billable resources.
- **Works with AWS.** It runs against a real AWS account by assuming a dedicated read-only role with MFA. It can also run fully offline against a mocked AWS (moto) for demos and tests.
- **Safe.** The tool never modifies AWS resources. This is enforced both in AWS (IAM) and in the client code.

## Glossary

- **Check**: A single security rule evaluated against the account (for example, "root account has MFA").
- **Finding**: The result of a Check for a specific resource, with a status of PASS, FAIL, or ERROR.
- **Severity**: One of CRITICAL, HIGH, MEDIUM, or LOW.
- **Report**: The collection of Findings from one audit run.
- **Audit Role**: The dedicated IAM role `CloudGuardAuditRole` that the tool assumes to read the account.
- **Operator User**: The dedicated IAM user `cloudguard-operator` whose only permission is assuming the Audit Role.
- **Base Credentials**: The user's own AWS credentials (profile, env vars, or SSO). They are used only to call `sts:AssumeRole` on the Audit Role.
- **Session**: The interactive, in-memory shell opened after successful authentication.
- **Locked**: The state in which the Session holds no AWS credentials or Findings and requires re-authentication.

## Requirements

### Requirement 1: Base credentials and configuration

**User Story:** As a user, I want the tool to use my existing AWS identity only to request access, so that I don't have to create new long-lived keys.

#### Acceptance Criteria

1. WHEN the user starts the tool, THE CLI SHALL resolve Base Credentials through the standard boto3 credential chain (environment variables, `~/.aws` profiles, SSO).
2. WHERE the user passes `--profile <name>`, THE CLI SHALL use that named profile as the Base Credentials.
3. WHERE the user passes `--region <region>`, THE CLI SHALL use that region for regional checks; otherwise THE CLI SHALL use the profile's default region, falling back to `us-east-1`.
4. THE CLI SHALL read the Audit Role ARN and MFA device ARN from `--role-arn` / `--mfa-serial` or from the environment variables `CLOUDGUARD_ROLE_ARN` / `CLOUDGUARD_MFA_SERIAL`. These values are identifiers, not secrets.
5. IF no valid Base Credentials are found, THEN THE CLI SHALL print a clear error message and exit with code 2, without printing a stack trace.
6. THE CLI SHALL NOT use Base Credentials for any AWS call other than `sts:AssumeRole` and `sts:GetCallerIdentity`.

### Requirement 2: IAM security checks

**User Story:** As a security reviewer, I want identity risks flagged, so that I can reduce the chance of account takeover.

#### Acceptance Criteria

1. THE CLI SHALL report a CRITICAL finding IF the root account does not have MFA enabled.
2. THE CLI SHALL report a CRITICAL finding IF the root account has active access keys.
3. THE CLI SHALL report a HIGH finding for each IAM user with console access who does not have MFA enabled.
4. THE CLI SHALL report a MEDIUM finding for each active access key older than 90 days.
5. THE CLI SHALL report a MEDIUM finding IF the account password policy is missing or requires fewer than 14 characters.

### Requirement 3: S3 security checks

**User Story:** As a security reviewer, I want public or weakly protected buckets flagged, so that I can prevent data leaks.

#### Acceptance Criteria

1. THE CLI SHALL report a HIGH finding IF account-level S3 Block Public Access is not fully enabled.
2. THE CLI SHALL report a HIGH finding for each bucket whose bucket-level Block Public Access is not fully enabled.
3. THE CLI SHALL report a CRITICAL finding for each bucket whose policy status reports it as public.
4. IF the CLI lacks permission to read a bucket's configuration, THEN THE CLI SHALL record an ERROR finding for that bucket and continue the audit.

### Requirement 4: Network (EC2 security group) checks

**User Story:** As a security reviewer, I want risky inbound rules flagged, so that I can shrink the attack surface.

#### Acceptance Criteria

1. THE CLI SHALL report a HIGH finding for each security group that allows inbound traffic from `0.0.0.0/0` or `::/0` on port 22 (SSH).
2. THE CLI SHALL report a HIGH finding for each security group that allows inbound traffic from `0.0.0.0/0` or `::/0` on port 3389 (RDP).
3. THE CLI SHALL treat a rule with protocol `-1` (all traffic), or a port range that includes 22 or 3389, as matching.

### Requirement 5: Logging and detection checks

**User Story:** As a security reviewer, I want to know if logging and threat detection are off, so that incidents don't go unnoticed.

#### Acceptance Criteria

1. THE CLI SHALL report a HIGH finding IF no CloudTrail trail is both multi-region and actively logging.
2. THE CLI SHALL report a MEDIUM finding IF GuardDuty has no enabled detector in the audited region.
3. THE CLI SHALL NOT enable CloudTrail, GuardDuty, or any other service on the user's behalf.

### Requirement 6: Findings model and CIS mapping

**User Story:** As a user, I want every finding to be explained and actionable, so that I know why it matters and how to fix it.

#### Acceptance Criteria

1. THE CLI SHALL include, for each Finding: check ID, title, status, severity, resource identifier, CIS control reference, and a one-line remediation.
2. THE CLI SHALL include PASS findings in the report so that coverage is visible.
3. IF a Check raises an unexpected error, THEN THE CLI SHALL record an ERROR finding for that Check and continue running the remaining Checks.

### Requirement 7: Report output

**User Story:** As a user, I want readable results inside the secure session, and an explicit opt-in to export them, so that sensitive data doesn't leak to disk by accident.

#### Acceptance Criteria

1. WHEN the user runs `audit` inside the Session, THE CLI SHALL print a colored summary table grouped by severity.
2. WHEN the user runs `show <severity|check-id>` inside the Session, THE CLI SHALL display the matching Findings with remediation details.
3. WHEN the user runs `export markdown <file>` or `export json <file>` inside the Session, THE CLI SHALL ask for confirmation, warn that the file contains sensitive account data, and on confirmation write the report with file permissions `0600` (owner read/write only).
4. THE CLI SHALL include a summary in every report: account ID, region, timestamp, and the count of findings by status and severity.
5. THE CLI SHALL NOT write any Findings to disk unless the user explicitly runs `export`.

### Requirement 8: Read-only, least-privilege Audit Role

**User Story:** As a security-conscious account owner, I want the tool's AWS identity to be physically unable to change resources, so that a bug or a compromise can't cause damage.

#### Acceptance Criteria

1. THE project SHALL ship a CloudFormation template (`infra/cloudguard-role.yaml`) that creates the Audit Role at no cost.
2. THE Audit Role permission policy SHALL allow only the specific read-only actions the Checks require. It SHALL NOT use wildcard actions (`*`, `service:*`) or AWS managed policies such as `SecurityAudit` or `ReadOnlyAccess`.
3. THE Audit Role SHALL include an explicit `Deny` statement using `NotAction` that denies every action except the allowlisted read-only actions. An accidentally attached broader policy then still can't grant write access.
4. THE Audit Role trust policy SHALL allow `sts:AssumeRole` only from principals in the same AWS account, and only WHEN `aws:MultiFactorAuthPresent` is `true` and `aws:MultiFactorAuthAge` is under 900 seconds.
5. THE Audit Role SHALL have `MaxSessionDuration` set to 3600 seconds, the AWS minimum.
6. THE CLI SHALL also enforce read-only access client-side. It SHALL register a botocore `before-call` hook that blocks any operation not on the same allowlist before the request is sent, and records the blocked attempt as an ERROR.
7. WHEN authentication succeeds, THE CLI SHALL verify via `sts:GetCallerIdentity` that the active identity is an assumed-role session of the configured Audit Role, and IF it is not, THEN THE CLI SHALL refuse to run Checks.
8. THE project SHALL ship the same allowlist as a standalone `iam-policy.json` for users who prefer to create the role manually.

### Requirement 9: Offline demo mode

**User Story:** As a candidate showing this to a recruiter, I want to demo the tool without a live AWS account, so that the demo is free and repeatable.

#### Acceptance Criteria

1. WHERE the user passes `--demo`, THE CLI SHALL start a mocked AWS environment (moto), seed it with intentionally misconfigured resources (a public bucket, an SSH-open security group, a user without MFA), and open a Session against it.
2. WHEN running with `--demo`, THE CLI SHALL make no network calls to real AWS endpoints.
3. WHEN running with `--demo`, THE CLI SHALL require a demo MFA code (shown in the demo banner) so that the authentication and lock flow can be demonstrated. All other session protections (Requirements 11 and 12) SHALL apply unchanged.
4. WHEN running with `--demo`, THE CLI SHALL label all output as `DEMO DATA`.

### Requirement 10: Testing and documentation

**User Story:** As a hiring manager, I want to see quality signals, so that I can trust the candidate's engineering practices.

#### Acceptance Criteria

1. THE project SHALL include pytest unit tests that use moto, covering at least one PASS and one FAIL case for each check category (IAM, S3, network, logging).
2. THE project SHALL include tests proving that the client-side guard blocks a write operation (for example, `s3:DeleteBucket`) and that the idle timeout locks the Session and clears credentials and Findings.
3. THE project SHALL include a README with the problem statement, a Mermaid architecture diagram, setup and usage instructions, a "Security decisions" section, a "Threat model and limitations" section, and a "Cost: $0" section explaining why the tool is free to run.

### Requirement 11: Authentication before any data is shown

**User Story:** As an account owner, I want the tool to show nothing about my account until I prove who I am, so that someone at an unlocked laptop can't read my security posture.

#### Acceptance Criteria

1. WHEN the tool starts, THE CLI SHALL prompt for a 6-digit MFA code before making any call that returns account data. The prompt SHALL NOT echo the input.
2. THE CLI SHALL obtain Audit Role credentials by calling `sts:AssumeRole` with `SerialNumber` and `TokenCode`, and `DurationSeconds` set to 900 (the STS minimum).
3. THE CLI SHALL NOT accept the MFA code as a command-line argument or environment variable, so that it can't end up in shell history or process listings.
4. IF the MFA code is malformed or rejected, THEN THE CLI SHALL display a generic "Authentication failed" message, without revealing whether the role, device, or code was wrong.
5. IF authentication fails 3 times in a row, THEN THE CLI SHALL exit with code 3.
6. WHILE the Session is Locked, THE CLI SHALL accept no commands other than authentication and `quit`.

### Requirement 12: Session lifetime and inactivity lock

**User Story:** As an account owner, I want the session to lock itself when I walk away, so that results don't stay on screen or in memory.

#### Acceptance Criteria

1. IF no input is received for 10 minutes (600 seconds) while the Session is unlocked, THEN THE CLI SHALL lock the Session.
2. WHEN the Session locks, THE CLI SHALL clear the terminal screen and scrollback, discard the Audit Role credentials and all Findings from memory, and prompt for MFA again.
3. WHEN the Audit Role credentials reach their 15-minute STS expiry, THE CLI SHALL lock the Session, even if the user is active.
4. THE CLI SHALL display the time remaining until the session expires in the prompt.
5. WHEN the user runs `lock`, THE CLI SHALL lock the Session immediately.

### Requirement 13: No persistence of commands or credentials

**User Story:** As an account owner, I want the tool to leave no trace after I close it, so that nothing sensitive is left on the machine.

#### Acceptance Criteria

1. THE CLI SHALL keep commands typed inside the Session in memory only, and SHALL NOT write a command history file (no readline or prompt history persistence).
2. THE CLI SHALL keep Audit Role credentials in memory only, and SHALL NOT write them to disk, to `~/.aws`, to a credentials cache, or to environment variables.
3. WHEN the user runs `quit` or `exit`, presses Ctrl+C or Ctrl+D, or closes the terminal (SIGHUP/SIGTERM), THE CLI SHALL clear the terminal screen and scrollback and discard credentials and Findings before exiting.
4. THE CLI SHALL NOT write credentials, MFA codes, or Findings to log output.
5. THE launch command (`cloudguard`, `cloudguard --demo`) SHALL contain no secrets, so its entry in the user's shell history reveals nothing sensitive.

### Requirement 14: Least-privilege operator identity

**User Story:** As an account owner, I want the identity that runs cloudguard to have the smallest possible permissions, so that a leaked operator key exposes nothing about my account.

#### Acceptance Criteria

1. THE project SHALL ship a CloudFormation template (`infra/cloudguard-operator.yaml`) that creates an IAM user named `cloudguard-operator` at no cost.
2. THE Operator User permission policy SHALL allow only `sts:AssumeRole`, and only on the Audit Role ARN.
3. THE Operator User permission policy SHALL include an explicit `Deny` statement with `NotAction: sts:AssumeRole`, so a broader policy attached later can't grant other actions.
4. THE Operator User SHALL have no console password (no `LoginProfile`).
5. THE Operator User permission policy SHALL NOT use an MFA condition key. MFA SHALL be enforced by the Audit Role trust policy (Requirement 8.4), because AWS doesn't include `aws:MultiFactorAuthPresent` in requests signed with long-term access keys.
6. THE project SHALL ship the same operator policy as a standalone `iam-operator-policy.json`.
7. THE project SHALL include a test that fails IF the operator policy allows any action other than `sts:AssumeRole`, or IF the operator template defines a console password.
8. THE README SHALL document the deployment order (operator user, then Audit Role), virtual MFA device setup, running the tool as the operator, a command that shows the operator alone gets `AccessDenied`, and full teardown.
