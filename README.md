# BashCoach

A VS Code extension for bash scripts. It highlights risky and insecure patterns as you type, explains why they are risky and how to fix them, offers one-click fixes for some of them, and includes a library of 126 snippets for common shell tasks.

## Features

### Security linting

Open any shell script (language mode **Shell Script**) and the extension scans it line by line. Findings appear as squiggly underlines and in the **Problems** tab (`Ctrl+Shift+M`).

- Red = Error
- Yellow = Warning
- Blue = Information

Every finding carries a rule ID (for example `BC004`) and a short explanation. Hover over a squiggle to read what the problem is, **why** it is risky, and **how to fix** it.

The extension currently has **17 rules**:

| ID | Severity | What it flags | Why it matters |
|----|----------|---------------|----------------|
| BC001 | Error | `curl` / `wget` piped into `bash` or `sh` (including via `sudo`) | Runs unverified remote code |
| BC002 | Warning | `eval` used as a command (not text inside quotes) | Command injection if input is attacker-controlled |
| BC003 | Warning | A literal value assigned to a variable whose name contains `password`, `passwd`, `secret`, `api_key` or `token` | Possible hardcoded credential |
| BC004 | Warning | Unquoted variable in `rm` (e.g. `rm -rf $DIR`) | Empty or spaced values can delete the wrong files |
| BC005 | Warning | `chmod 777` | Gives everyone read, write and execute access |
| BC006 | Error | `/dev/tcp/` or `/dev/udp/` | Common bash reverse shell technique |
| BC007 | Error | `nc` / `ncat` / `netcat` with `-e` or `-c` | Reverse or bind shell |
| BC008 | Error | `base64 -d` piped into a shell | Hides what the script executes |
| BC009 | Error | `rm` on `/` or `/*` | Deletes the whole filesystem |
| BC010 | Warning | `curl` / `wget` using `http://` | Download can be tampered with in transit |
| BC011 | Warning | `curl -k` / `--insecure`, `wget --no-check-certificate` | TLS verification disabled (man-in-the-middle risk) |
| BC012 | Warning | `StrictHostKeyChecking=no` | SSH host key checking disabled |
| BC013 | Warning | Setuid/setgid changes (e.g. `chmod 4755`, `chmod u+s`) | Possible privilege escalation |
| BC014 | Warning | `.` in `PATH` (e.g. `PATH=.:$PATH`) | A local binary can hijack commands |
| BC015 | Warning | `history -c`, `unset HISTFILE`, `HISTFILE=/dev/null` | Clears shell history, often used to hide activity |
| BC016 | Information | Redirecting output to a file in `/tmp/` | Predictable temp files can be hijacked; consider `mktemp` |
| BC017 | Information | `sudo` used as a command | Confirm the script really needs elevated privileges |

Lines that start with `#` are skipped. For BC003, values that start with `$` or a backtick (variables and command substitutions) are not flagged.

### Quick fixes

Click a squiggle and press `Ctrl+.` (or click the lightbulb) to see the available actions.

| Rule | Fix offered |
|------|-------------|
| BC004 | Wrap the variable in quotes |
| BC005 | Change `777` to `755` |
| BC010 | Change `http://` to `https://` |

Every finding also offers **Ignore BCxxx on this line**, which inserts an ignore comment above it.

### Ignoring findings

Silence a rule for a single line with a comment:

```bash
# bashcoach-disable-next-line BC004
rm -rf $DIR

rm -rf $DIR  # bashcoach-disable-line BC004
sudo apt update  # bashcoach-disable-line
```

- `bashcoach-disable-next-line` applies to the following line, and `bashcoach-disable-line` applies to the line it is on.
- List several IDs to silence several rules (`BC004, BC005`).
- With no ID, every rule is silenced for that line.

### Settings

| Setting | Default | What it does |
|---------|---------|--------------|
| `bashcoach.disabledRules` | `[]` | Rule IDs to turn off, for example `["BC016", "BC017"]` |
| `bashcoach.minimumSeverity` | `Information` | Hide findings below this level: `Information`, `Warning` or `Error` |

Example `settings.json`:

```json
{
  "bashcoach.disabledRules": ["BC016", "BC017"],
  "bashcoach.minimumSeverity": "Warning"
}
```

### Snippet library

The extension includes **126 snippets in 10 categories**. Type a prefix and press **Tab** to expand it. Press **Tab** again to move between placeholders.

Notes:

- Snippets marked **Bash 4+** use features that are missing from the Bash 3.2 shipped with macOS.
- Snippets marked **Linux** rely on Linux-specific tool options.
- `heredoc` should be used at the start of a line, because the closing `EOF` must not be indented.
- Snippets that need an external tool (`jq`, `nc`, `openssl`, `flock`, `systemctl`) assume it is installed.

#### 1. Variables and user input

| Prefix | What it inserts |
|--------|-----------------|
| `readp` | Read input with a prompt |
| `reads` | Read hidden input (passwords) |
| `confirm` | Yes/no confirmation prompt |
| `selectmenu` | Interactive select menu |
| `argcheck` | Check the number of arguments |
| `getopts` | Parse command-line options with getopts |
| `defvar` | Set a default value if a variable is unset |
| `reqvar` | Exit if a variable is unset or empty |
| `var` | Variable assignment |
| `cmdsub` | Capture command output in a variable |
| `constant` | Read-only variable |
| `exportvar` | Export an environment variable |
| `arith` | Arithmetic expression |

#### 2. Conditions and comparisons

| Prefix | What it inserts |
|--------|-----------------|
| `if` | if block |
| `ifelse` | if / else block |
| `ifelif` | if / elif / else block |
| `case` | case statement |
| `ifstr` | Compare strings |
| `ifnum` | Compare numbers |
| `iffile` | Check that a file exists |
| `ifdir` | Check that a directory exists |
| `ifempty` | Check for an empty variable |
| `ifcmd` | Check that a command is installed |
| `ifregex` | Match a regular expression |

#### 3. Loops and flow control

| Prefix | What it inserts |
|--------|-----------------|
| `for` | for ... in loop |
| `forc` | C-style for loop |
| `while` | while loop |
| `whileread` | Read a file line by line |
| `whilecmd` | Read command output line by line |
| `forfiles` | Loop over files with a glob |
| `forarray` | Loop over an array |
| `forargs` | Loop over script arguments |
| `forrange` | Loop over a numeric range |
| `whiletrue` | Infinite loop with sleep |
| `until` | until loop |
| `retry` | Retry a command with a limit |

#### 4. Functions

| Prefix | What it inserts |
|--------|-----------------|
| `function` | Function definition |
| `funcargs` | Function with local variables and defaults |
| `funcreturn` | Function that returns a value |
| `main` | main function and entry point |
| `ifmain` | Run only when executed, not sourced |
| `usagefn` | usage() help function |
| `localvar` | Local variable |
| `sourcefile` | Source a file safely |

#### 5. File and directory operations

| Prefix | What it inserts |
|--------|-----------------|
| `readfile` | Read a whole file into a variable |
| `writefile` | Write text to a file |
| `appendfile` | Append text to a file |
| `mkdirp` | Create a directory (with parents) |
| `tmpfile` | Temporary file removed on exit |
| `tmpdir` | Temporary directory removed on exit |
| `findloop` | Loop over find results safely |
| `backupfile` | Back up a file with a timestamp |
| `scriptdir` | Directory of the current script |
| `heredoc` | Write a here-document to a file (use at the start of a line) |
| `renamebatch` | Rename files by changing the extension |
| `symlink` | Create a symbolic link |

#### 6. String and array operations

| Prefix | What it inserts |
|--------|-----------------|
| `array` | Create an array |
| `arrayadd` | Append to an array |
| `arraylen` | Array length |
| `assoc` | Associative array with loop (Bash 4+) |
| `strlen` | String length |
| `substr` | Substring |
| `replace` | Replace text in a string |
| `stripprefix` | Remove a prefix |
| `stripsuffix` | Remove a suffix |
| `upper` | Uppercase a string (Bash 4+) |
| `lower` | Lowercase a string (Bash 4+) |
| `splitstr` | Split a string into an array |
| `joinarr` | Join an array into a string |
| `mapfile` | Read lines into an array (Bash 4+) |

#### 7. Error handling and debugging

| Prefix | What it inserts |
|--------|-----------------|
| `bashhead` | Script header with set -euo pipefail |
| `strict` | Strict mode with safer IFS |
| `trapexit` | Cleanup function run on exit |
| `trapint` | Handle Ctrl+C and termination |
| `traperr` | Report the line of a failing command |
| `die` | die() error helper |
| `logfn` | Timestamped log() function |
| `orexit` | Run a command or exit with a message |
| `iffail` | Exit if a command fails |
| `needcmd` | Check required commands |
| `debugvar` | Print a variable for debugging |
| `debugblock` | Trace a block with set -x |
| `ps4` | Trace with file and line numbers |
| `shellcheck` | Disable a ShellCheck rule |

#### 8. Process and system administration

| Prefix | What it inserts |
|--------|-----------------|
| `ifroot` | Require root |
| `ifservice` | Check a systemd service |
| `ifuser` | Check that a user exists |
| `pgrep` | Find processes by name |
| `background` | Run a command in the background and wait |
| `parallel` | Run jobs in parallel |
| `singleinstance` | Allow only one running instance |
| `sysinfo` | Print host, user and date |
| `timeoutcmd` | Run a command with a timeout |
| `watchloop` | Repeat a command every few seconds |
| `diskalert` | Warn when disk usage is high |

#### 9. Networking and security

| Prefix | What it inserts |
|--------|-----------------|
| `curlget` | Download a file with curl |
| `curljson` | POST JSON with curl |
| `httpstatus` | Get an HTTP status code |
| `checkport` | Check whether a TCP port is open |
| `pingcheck` | Check that a host is reachable (Linux) |
| `sshrun` | Run a command over SSH |
| `scpfile` | Copy a file with scp |
| `sshkeygen` | Generate an ed25519 SSH key |
| `sha256check` | Verify a SHA-256 checksum |
| `randpass` | Generate a random base64 string |
| `certdates` | Show a server certificate's validity dates |
| `resolvehost` | Resolve a hostname |
| `chmod600` | Make a file private (600) |
| `umasksafe` | Restrictive umask (077) |

#### 10. Common Bash one-liners

| Prefix | What it inserts |
|--------|-----------------|
| `countlines` | Count lines in a file |
| `largestfiles` | Largest files and directories |
| `findlarge` | Find large files |
| `findold` | Find old files |
| `topcommands` | Most used shell commands |
| `countunique` | Count duplicate lines |
| `awkcol` | Print a column with awk |
| `sedreplace` | Replace text in a file (keeps a .bak backup) |
| `grepr` | Search recursively with line numbers |
| `tailgrep` | Follow a file and filter lines |
| `listenports` | List listening ports (Linux) |
| `topmem` | Processes using the most memory (Linux) |
| `timestamp` | Current timestamp |
| `tarcreate` | Create a tar.gz archive |
| `tarextract` | Extract a tar.gz archive |
| `findxargs` | Run a command on found files |
| `jqget` | Extract a value from JSON (needs jq) |

## Installation

Install **BashCoach** from the VS Code Marketplace:

1. Open the Extensions panel (`Ctrl+Shift+X`).
2. Search for `BashCoach` (or `ashray.bashcoach`) and click **Install**.

Or from a terminal:

```bash
code --install-extension ashray.bashcoach
```

The extension activates automatically for shell scripts (language mode **Shell Script**, for example `.sh` files).

**Requirements:** VS Code 1.146.0 or newer.

### Build from source

```bash
git clone https://github.com/Ashu-ye/bashcoach.git
cd bashcoach
npm install
npm run compile
```

Then open the folder in VS Code and press **F5**. A new *Extension Development Host* window opens with the extension loaded. Open or create a `.sh` file to see it in action.

Building needs Node.js.

**Windows note:** if PowerShell blocks `npm`, run
`Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`
once, or use `npm.cmd` instead of `npm`.

## Project structure

```
src/extension.ts      Linter rules, ignore comments, settings handling and quick fixes
snippets/             Snippet library, one JSON file per category (10 files)
package.json          Extension manifest (activation, snippets, settings)
icon.png              Extension icon
LICENSE               MIT license
```

To add a snippet, add an entry to the matching file in `snippets/` with a prefix that is not used elsewhere. To add a category, create a new file there and register it in `package.json` under `contributes.snippets`.

## Limitations

- Rules are regular expressions applied to one line at a time, so this is a heuristic scanner, not a full shell parser.
- Commands split across lines with `\` are not combined, and patterns inside strings can trigger false positives.
- It is a helper for spotting common mistakes, not a replacement for a full audit or for tools like ShellCheck.

## License

MIT. See the `LICENSE` file.