# BashCoach

A VS Code extension for bash scripts. It highlights risky and insecure patterns as you type, and adds snippets for common shell syntax.

## Features

### Security linting

Open any shell script (language mode **Shell Script**) and the extension scans it line by line. Findings appear as squiggly underlines and in the **Problems** tab (`Ctrl+Shift+M`).

- Red = Error
- Yellow = Warning
- Blue = Information

The extension currently has **17 rules**:

| # | Severity | What it flags | Why it matters |
|---|----------|---------------|----------------|
| 1 | Error | `curl` / `wget` piped into `bash` or `sh` (including via `sudo`) | Runs unverified remote code |
| 2 | Warning | `eval` | Command injection if input is attacker-controlled |
| 3 | Warning | Assignments to `password`, `passwd`, `secret`, `api_key`, `token` | Possible hardcoded credential |
| 4 | Warning | Unquoted variable in `rm` (e.g. `rm -rf $DIR`) | Empty or spaced values can delete the wrong files |
| 5 | Warning | `chmod 777` | Gives everyone read, write and execute access |
| 6 | Error | `/dev/tcp/` or `/dev/udp/` | Common bash reverse shell technique |
| 7 | Error | `nc` / `ncat` / `netcat` with `-e` or `-c` | Reverse or bind shell |
| 8 | Error | `base64 -d` piped into a shell | Hides what the script executes |
| 9 | Error | `rm` on `/` or `/*` | Deletes the whole filesystem |
| 10 | Warning | `curl` / `wget` using `http://` | Download can be tampered with in transit |
| 11 | Warning | `curl -k` / `--insecure`, `wget --no-check-certificate` | TLS verification disabled (man-in-the-middle risk) |
| 12 | Warning | `StrictHostKeyChecking=no` | SSH host key checking disabled |
| 13 | Warning | Setuid/setgid changes (e.g. `chmod 4755`, `chmod u+s`) | Possible privilege escalation |
| 14 | Warning | `.` in `PATH` (e.g. `PATH=.:$PATH`) | A local binary can hijack commands |
| 15 | Warning | `history -c`, `unset HISTFILE`, `HISTFILE=/dev/null` | Clears shell history, often used to hide activity |
| 16 | Information | Redirecting output to a file in `/tmp/` | Predictable temp files can be hijacked; consider `mktemp` |
| 17 | Information | `sudo` | Confirm the script really needs elevated privileges |

Lines that start with `#` are skipped.

### Snippets

Type a prefix and press **Tab** to expand it. Press **Tab** again to move between placeholders.

| Prefix | Expands to |
|--------|-----------|
| `if` | `if ... then ... fi` |
| `ifelse` | `if ... else ... fi` |
| `ifelif` | `if ... elif ... else ... fi` |
| `for` | `for item in list; do ... done` |
| `forc` | C-style `for ((i=0; i<10; i++))` loop |
| `while` | `while ... do ... done` |
| `whileread` | Read a file line by line |
| `case` | `case ... esac` with a default branch |
| `function` | Function definition |
| `bashhead` | `#!/usr/bin/env bash` header with `set -euo pipefail` |

## Running it locally

The extension is not published to the VS Code Marketplace. To try it:

```bash
git clone https://github.com/Ashu-ye/bashcoach.git
cd bashcoach
npm install
npm run compile
```

Then open the folder in VS Code and press **F5**. A new *Extension Development Host* window opens with the extension loaded. Open or create a `.sh` file to see it in action.

**Requirements:** Node.js and VS Code 1.146.0 or newer.

**Windows note:** if PowerShell blocks `npm`, run
`Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`
once, or use `npm.cmd` instead of `npm`.

## Project structure

```
src/extension.ts      Linter logic and rule list
snippets/bash.json    Snippet definitions
package.json          Extension manifest (activation, snippet registration)
```

## Limitations

- Rules are regular expressions applied to one line at a time, so this is a heuristic scanner, not a full shell parser.
- Commands split across lines with `\` are not combined, and patterns inside strings can trigger false positives.
- It is a helper for spotting common mistakes, not a replacement for a full audit or for tools like ShellCheck.