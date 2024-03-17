# Security

The runbooks of this Azure Automation framework intent to be as secure as possible. They are intended to be run in automation accounts that might follow a tiering security concept, and are classified as Tier 0.

For that particular reason, it was also a design decision to _not_ have this functionality put into a dedicated PowerShell module that can be installed from PowerShell Gallery.

If you believe you have found a security vulnerability or would like to suggest improvements that may contribute to increased security, please report it to us as described below.

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them to the project team by opening a security advisory here:
https://github.com/Workoho/Entra-Tiering-Security-Model/security/advisories/new

As an alternative, you may also report them to the Workoho Security Team by email to [secure@workoho.com](mailto:secure@workoho.com). If desired, you may also encrypt your message with our PGP key; please see [Workoho's Security.txt file](https://workoho.com/.well-known/security.txt) for further details.

Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:

* Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
* Full paths of source file(s) related to the manifestation of the issue
* The location of the affected source code (tag/branch/commit or direct URL)
* Any special configuration required to reproduce the issue
* Step-by-step instructions to reproduce the issue
* Proof-of-concept or exploit code (if possible)
* Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

**Please note that Workoho does _not_ offer any bug bounty program.**

## Preferred Languages

We prefer all communications to be in English.
