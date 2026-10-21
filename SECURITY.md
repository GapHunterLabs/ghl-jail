# Security Policy

## What ghl-jail is, for the purpose of this policy

ghl-jail is harm reduction for untrusted command-line tools on Windows, not a
hard security boundary. It raises the cost of a mistake a great deal; it is not
a guarantee against an attacker who is actively targeting this specific sandbox.
This matters for what counts as a vulnerability below.

## Supported versions

Security fixes are released for the latest version on the `main` branch and the
latest tagged release. Earlier revisions do not receive fixes — update to the
latest.

## Reporting a vulnerability

Report suspected vulnerabilities privately, not in a public issue, discussion,
or pull request.

- **Preferred:** GitHub private vulnerability reporting, the **Report a
  vulnerability** button under this repository's **Security** tab.
- **Alternative:** email **gaphunterlabs@gmail.com** with the subject
  `SECURITY: ghl-jail`.

Include the Windows edition and build, the Python version, the exact command
you ran, and what the jailed process was able to do that it should not have been
(or was prevented from doing that it should have). A minimal reproduction is
worth more than anything else.

If there is evidence that the issue is being exploited in the wild, say so in
the first message. Those reports are handled first.

## What to expect

- Acknowledgement within **5 business days**.
- An assessment (confirmed or not, severity, and plan) within **10 business
  days**.
- Fix targets by severity (CVSS): critical within 7 days, high within 30 days,
  medium within 90 days, low in a later release.
- Coordinated disclosure: details stay private until a fix is released, for up
  to 90 days unless another date is agreed with the reporter.
- Each fix is published as a GitHub Security Advisory, with a CVE when
  applicable, and noted in the release.
- Reporters are credited unless they ask to stay anonymous.

## Scope

In scope — a failure of the isolation the tool actually claims:

- a jailed process reading or writing outside the `--project` directory (your
  user profile, `~/.ssh`, cloud credential files, another drive) when the mode
  used is supposed to prevent it;
- a jailed process reaching the network in `container` mode with `--net none`;
- a secret from the parent environment (a token, key or password not passed
  with `--keep-env`) leaking into the jailed process;
- `cleanup` failing to remove an access grant it recorded, leaving the
  AppContainer with standing access to a path.

Out of scope — documented limitations, not bugs (see the README):

- the fact that this is user-space isolation with no admin and no kernel
  driver, and therefore not proof against a kernel exploit or a determined,
  sandbox-aware attacker;
- `token` mode not restricting the network, or being able to read world-readable
  files outside your profile — this is stated behaviour;
- git requiring `token`/`auto` mode because an AppContainer cannot open the
  `NUL` device on some Windows builds;
- anything that requires administrator rights on the host to exploit.

## Good-faith research

Research that follows this policy, avoids privacy violations and service
disruption, and gives a reasonable time to fix before disclosure is welcome,
and will not be the subject of legal action by the maintainer.
