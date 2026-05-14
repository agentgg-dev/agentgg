---
slug: command-injection
name: Command Injection
description: Shell or process invocations that include untrusted input in the command string, allowing arbitrary commands to be executed by an attacker.
version: 0.1.0
mode: file
noiseTier: precise
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
  - "**/*.{py,rb,go,rs,php,java,kt,cs,sh}"
references:
  - CWE-78
  - OWASP-A03:2021
---

You are reviewing source code for OS command injection — a shell or
process invocation that includes untrusted input in the command string,
letting an attacker execute arbitrary commands by injecting metacharacters
like `;`, `&&`, `|`, backticks, or `$(...)`.

## What to look for

- Node: `child_process.exec(cmd)` / `execSync(cmd)` where `cmd`
  is a string built from request data. Also `spawn(cmd, { shell: true })`
  with an interpolated string.
- Python: `os.system(...)`, `subprocess.call(..., shell=True)`,
  `subprocess.Popen(..., shell=True)`, `os.popen(...)` with a string
  composed from user input.
- Ruby: backticks `` `cmd` ``, `%x{cmd}`, `Kernel.system`,
  `Kernel.exec`, `IO.popen` with interpolated strings.
- Go: `exec.Command("sh", "-c", cmdString)` where `cmdString` is
  built from request input. Plain `exec.Command(name, arg1, arg2)`
  with separate args is safe.
- Java/Kotlin: `Runtime.getRuntime().exec(stringCmd)`,
  `ProcessBuilder(stringCmd)`.
- PHP: `exec()`, `shell_exec()`, `system()`, `passthru()`,
  `popen()`, backtick operator.
- Anywhere a user-controlled value flows into a shell pipeline, a
  `Dockerfile` `RUN` line built at runtime, or a `Makefile` rule
  evaluated with substitutions.

## True positive criteria

A value reaching the call comes from outside the trust boundary
(HTTP request, queue message, file upload, third-party API) AND
the call uses a shell interpreter OR passes the command as a single
string the runtime will split. The attacker can append shell
metacharacters to escape the intended command.

## What to ignore

- Calls that pass argv as an array with no shell:
  `spawn("ping", ["-c", "1", host])`,
  `exec.Command("ping", "-c", "1", host)`,
  `subprocess.run(["ping", "-c", "1", host])`.
  Even with an injected metachar in `host`, the OS treats the whole
  value as one argument. Flag only if `shell=True` / `{ shell: true }`
  is explicitly set.
- Hardcoded command strings with no user input.
- Test fixtures or scripts run only by developers locally.
- Cases where the user input has already been validated against a
  strict allowlist (e.g. matched against `^[a-z0-9.-]+$` AND the
  allowlist is enforced before the call). The validation has to be
  upstream and on the actual value used.

## Examples

True positives:
- `` exec(`ping -c 1 ${req.query.host}`) `` — classic, host can
  be `127.0.0.1; cat /etc/passwd`.
- `subprocess.call(f"convert {user_file} out.png", shell=True)` —
  filename can contain `;` or `&&`.
- `Runtime.getRuntime().exec("git log " + branchName)` — branch
  name from a webhook payload.
- `os.system("ls " + path)` in a Flask route.

False positives to skip:
- `spawn("ping", ["-c", "1", host])` (argv array, no shell).
- `exec.Command("git", "log", branchName)` in Go.
- A constant command string with no interpolation.
- A call where the input was just validated against a tight regex on
  the same path.

If the call uses a shell AND the input comes from a request, it's a
finding even if you can't immediately see exploitation — the burden
is on the code to demonstrate safety, not on the reviewer to prove
the exploit.
