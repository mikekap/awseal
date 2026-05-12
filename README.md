# awseal 🔐

A secure AWS credential manager that protects your AWS credentials using
Apple's Secure Enclave. Inspired by
[Secretive](https://github.com/maxgoedjen/secretive), `awseal` protects you AWS
credentials from malicious code by ensuring they can only be accessed with your
explicit permission.

## 🚨 The Problem

Traditional AWS credential storage methods are vulnerable to credential theft:

- Credentials stored in plain text files can be read by any process
- Environment variables can be accessed by child processes
- Malicious code can easily exfiltrate your AWS access keys or cached AWS SSO credentials

## 🛡️ The Solution

`awseal` leverages Apple's Secure Enclave to provide hardware-backed security
for your AWS credentials:

- **Secure Storage**: AWS credentials are encrypted using keys stored in the
Secure Enclave
- **User Presence Required**: Access to credentials requires biometric
authentication (Touch ID, Face ID) or device passcode
- **Malware Protection**: Even if malicious code runs on your system, it cannot
access your AWS credentials without your physical presence
- **Seamless Integration**: Works transparently with the AWS CLI via `credential_process`

## ✨ Features

- **Secure Authentication**: Login once with `awseal login` and your
credentials are safely stored
- **Automatic Credential Rotation**: Fresh role credentials are minted
on-demand when needed
- **Multiple Profile Support**: Configure different AWS accounts and roles
- **Hardware Security**: Leverages Apple's Secure Enclave for cryptographic operations
- **Touch ID Integration**: Biometric authentication for credential access

## 🚀 Installation

```bash
brew tap hyperscale-consulting/hyperscale
brew install awseal
```

## 📖 Quick Start

### 1. Configure awseal

`awseal` reads profile settings from `~/.aws/config` using `awseal_`-prefixed
keys:

```ini
[default]
region = eu-west-2
awseal_sso_session = company
awseal_sso_start_url = https://xxx.awsapps.com/start/#
awseal_sso_region = eu-west-2
awseal_sso_account_id = 123456789012
awseal_sso_role_name = MyRole
credential_process = awseal fetch-role-creds --autologin

[profile dev]
region = eu-west-2
awseal_sso_session = company
awseal_sso_start_url = https://xxx.awsapps.com/start/#
awseal_sso_region = eu-west-2
awseal_sso_account_id = 123456789012
awseal_sso_role_name = Developer
credential_process = awseal fetch-role-creds --profile dev --autologin
```

The `[profile name]` sections are the profiles you can reference through
`--profile name`. The `[default]` profile is used if this option is omitted. The
available configuration options for each profile are:

- **awseal_sso_session**: Optional shared SSO session name. Profiles with the same
  value share one encrypted SSO login. If omitted, awseal shares SSO
  credentials across profiles with the same `awseal_sso_start_url` and
  `awseal_sso_region`.
- **awseal_sso_start_url**: Your organization's AWS SSO start URL
- **awseal_sso_region**: AWS region where SSO is configured
- **region**: Default AWS region for API calls
- **awseal_sso_account_id**: Your AWS account ID
- **awseal_sso_role_name**: The role you want to assume

Values in `[default]` are inherited by named profiles. For compatibility,
`~/.awseal/config.json` is still loaded when present, but `~/.aws/config`
profiles take precedence.

### 2. Login to AWS SSO

```bash
awseal login
```

Profiles that share the same `awseal_sso_session` use the same encrypted SSO
login, so you only need to login once before switching between those profiles.

This will:

- Open your browser for AWS SSO authentication
- Store your SSO credentials encrypted under the Secure Enclave
- Require Touch ID/Face ID to access the stored credentials

### 3. Configure AWS CLI

Configure each AWS CLI profile to use `awseal` as an external credential
provider by setting `credential_process`:

```ini
[default]
credential_process = awseal fetch-role-creds

[profile my-profile]
credential_process = awseal fetch-role-creds --profile my-profile
```

To allow `credential_process` to open the browser and login automatically when
the encrypted SSO credentials are missing or can no longer be refreshed, add
`--autologin`:

```ini
[default]
credential_process = awseal fetch-role-creds --autologin

[profile my-profile]
credential_process = awseal fetch-role-creds --profile my-profile --autologin
```

### 4. Use AWS CLI Normally

```bash
# Credentials are automatically fetched and rotated
aws s3 ls
aws ec2 describe-instances
```

## 🔒 Security Architecture

### Secure Enclave Integration

`awseal` uses Apple's Secure Enclave to generate and store cryptographic keys:

1. **Key Generation**: A P-256 key pair is generated in the Secure Enclave
   during first use
2. **Access Control**: Keys are protected with `userPresence` requirement
3. **Credential Encryption**: AWS SSO credentials are encrypted using HPKE
   (Hybrid Public Key Encryption) with the P256-SHA256-AES-GCM-256 ciphersuite,
because the Secure Enclave only supports NIST P-256 elliptic curve keys
4. **Biometric Authentication**: Touch ID/Face ID required to access the
   encryption key

### Threat Model

`awseal` protects against:

- ✅ **Credential Theft**: Malicious code cannot read encrypted credentials
- ✅ **Key Extraction**: Private keys never leave the Secure Enclave
- ✅ **Unauthorized Access**: User presence required to access the Secure
Enclave key

## 🏗️ How It Works

1. **Login Phase** (`awseal login`):
   - Authenticate with AWS SSO via browser
   - Generate Secure Enclave key
   - Encrypt and store SSO credentials for the shared SSO session

2. **Credential Fetching** (`awseal fetch-role-creds`):
   - AWS CLI calls awseal via `credential_process`
   - awseal decrypts stored credentials (requires Touch ID/Face ID)
   - Role credentials are fetched from AWS SSO OIDC API and returned to AWS CLI
   - Role credentials are stored encrypted per profile until they expire
   - Refresh tokens are used to keep access tokens short-lived for OIDC
   - With `--autologin`, awseal opens the browser and performs SSO login when
     the encrypted SSO credentials are missing or cannot be refreshed

3. **Security Guarantees**:
   - Credentials are never stored in plain text
   - Access requires physical user presence
   - Malicious code cannot bypass authentication

## ✅ Verifying a Build

`awseal` has access to your AWS credentials, so you should verify that you're
installing what you think you are.

The code is easy to audit; it's relatively straightforward and is all in one
file: [Sources/Awseal.swift](Sources/Awseal/Awseal.swift).

To verify that the binary release was built from the source code you have
audited, you can use the [slsa-verifier
tool](https://github.com/slsa-framework/slsa-verifier). `awseal` uses
[slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator/tree/main)
for including provenance in releases. After
[installing](https://github.com/slsa-framework/slsa-verifier#installation)
`slsa-verifier`, and fetching the binary and provenance file for the [latest
release](https://github.com/hyperscale-consulting/awseal/releases/latest), you
can verify the built artifact with:

```bash
slsa-verifier verify-artifact awseal-v${VERSION}.tar.gz \
  --provenance-path awseal-v${VERSION}.tar.gz.intoto.jsonl \
  --source-uri github.com/hyperscale-consulting/awseal \
  --source-tag v${VERSION}
```

If you're installing through Homebrew, you can compare the sha256 checksum with
the checksum in
[formula](https://github.com/hyperscale-consulting/homebrew-hyperscale/blob/main/Formula/awseal.rb)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE)
file for details.

## Security

Our security policy is detailed in [SECURITY.md](SECURITY.md). To report
security issues, please use [GitHub's private reporting
feature.](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability#privately-reporting-a-security-vulnerability)

---
