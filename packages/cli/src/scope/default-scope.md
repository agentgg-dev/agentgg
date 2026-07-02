# Security Scope

## Trust boundaries determine validity

A security bug is valid only when an attacker can cross a trust boundary they are not supposed to cross. The code defect alone is not enough — the question is always: does this let someone gain capabilities beyond what they are already authorized to have?

**The core test:** what can an attacker do after exploiting this that they could not do before? If the answer is "nothing they couldn't already do through legitimate means," it is not a valid finding.

## Common trust boundaries

**Authentication boundary**
The line between anonymous and authenticated. Any bug reachable without authentication that affects authenticated state, credentials, or data is valid. A bug only reachable after authentication must still be evaluated against what that authentication level already permits.

**Privilege boundary**
The line between roles. A regular user exploiting a bug to read or write another user's data, access admin functions, or escalate their own privileges is valid. An admin exploiting a bug to do something an admin could already do directly is not valid — the boundary was already crossed legitimately.

**Tenant / isolation boundary**
In multi-tenant systems, one tenant must not be able to read, modify, or affect another tenant's data. Bugs that break tenant isolation are valid regardless of whether both parties are authenticated.

**Network boundary**
Some services are internal-only and assumed to only receive requests from trusted callers. A bug in an internal service is lower priority than the same bug on a public-facing endpoint. Verify whether the vulnerable path is actually exposed before treating it as exploitable.

**Process / sandbox boundary**
Bugs that escape a sandbox, container, or process boundary are valid. Bugs that affect only the already-trusted host process are generally not.

## Applying the boundary test

Before marking something as a finding, determine:

1. Which trust boundary does this bug cross?
2. Who is on the untrusted side of that boundary?
3. What capability does exploitation grant that the attacker did not already have?

If exploitation requires the attacker to already be on the trusted side of the relevant boundary, it is out of scope. The attacker must start outside the boundary and end up inside it — or start at a lower privilege level and reach a higher one.

## Attacker-controlled input trap

A bug is invalid when the attacker already controls the input that triggers it. This applies across all vulnerability classes: XSS via data the attacker authored, SSRF via a URL the attacker supplied, path traversal via a filename the attacker chose, injection via config the attacker owns. The code defect is real, but exploitation grants nothing beyond what the attacker's existing write access already permits.

Agents often try to rescue these findings with a narrow deployment scenario ("in a shared environment, the author has data write access but not server access"). Reject this. If the attacker controls the data source, they are already on the trusted side of any meaningful boundary. Hypothetical deployment models do not change that.

## Out of scope

- Bugs where the only actor who can trigger them already has the authority to achieve the same outcome through normal, authorized operations.
- Bugs where the attacker must first control the data source (config file, project file, their own content) that feeds the vulnerable code path — the exploit is redundant to the write access already held.
- Bugs in test code, example configurations, or documentation.
- Vulnerabilities in third-party dependencies not directly exercised by the application's own code paths.
- Issues where a required precondition (such as physical access, or compromise of a separate system) already represents a complete breach of the deployment environment.
