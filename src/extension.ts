import * as vscode from 'vscode';

interface Rule {
  id: string;
  title: string;
  why: string;
  fix: string;
  pattern: RegExp;
  severity: vscode.DiagnosticSeverity;
}

const rules: Rule[] = [
  {
    id: 'BC001',
    title: 'Piping a download straight into a shell runs unverified code.',
    why: 'Whatever the server sends is executed immediately, so a compromised or spoofed server controls your machine.',
    fix: 'Download the script to a file, read it, check a checksum or signature, then run it.',
    pattern: /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(bash|sh)\b/,
    severity: vscode.DiagnosticSeverity.Error,
  },
  {
    id: 'BC002',
    title: 'eval can execute attacker-controlled input (command injection).',
    why: 'eval treats text as code, so any untrusted value that reaches it can run arbitrary commands.',
    fix: 'Avoid eval. Use arrays for command arguments, case statements, or indirect expansion like ${!name}.',
    pattern: /(?<=(?:^|[;&|({]|\b(?:then|do|else|elif|if|while|until)\b)\s*)eval\b/,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC003',
    title: 'Possible hardcoded credential.',
    why: 'Secrets written in a script end up in version control, backups and shell history.',
    fix: 'Read secrets from environment variables, a secrets manager, or a protected file kept outside the repository.',
    pattern: /\b\w*(password|passwd|secret|api_?key|token)\w*\s*=(?![=~])\s*["']?(?![$`])[^\s"']+/i,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC004',
    title: 'Unquoted variable in rm.',
    why: 'If the variable is empty or contains spaces, rm can delete the wrong files.',
    fix: 'Quote it: rm -rf "$DIR". Using "${DIR:?}" makes the script stop if the variable is empty.',
    pattern: /\brm\s+(-\w+\s+)*\$\{?\w+\}?(\s|$)/,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC005',
    title: 'chmod 777 gives everyone read, write and execute access.',
    why: 'Any user or process on the system can modify or run the file.',
    fix: 'Use least privilege, for example 755 for executables, 644 for regular files, 600 or 700 for private ones.',
    pattern: /\bchmod\s+(-\w+\s+)*0?777\b/,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC006',
    title: 'Bash network redirection via /dev/tcp is a common reverse shell technique.',
    why: 'Bash can open network connections through /dev/tcp without any extra tools, which attackers use for reverse shells.',
    fix: 'Remove it unless you are deliberately testing connectivity. Prefer clearly named tools such as curl or nc for legitimate network access.',
    pattern: /\/dev\/(tcp|udp)\//,
    severity: vscode.DiagnosticSeverity.Error,
  },
  {
    id: 'BC007',
    title: 'netcat with -e/-c executes a program over the network (reverse/bind shell).',
    why: 'This hands a remote host an interactive shell on the machine running the script.',
    fix: 'Remove it. If you need to transfer data, use netcat without -e/-c, or a tool like scp or rsync.',
    pattern: /\b(nc|ncat|netcat)\b[^\n]*\s-(e|c)\b/,
    severity: vscode.DiagnosticSeverity.Error,
  },
  {
    id: 'BC008',
    title: 'Decoding base64 straight into a shell hides what the script runs.',
    why: 'Encoded payloads cannot be read at a glance, which is why malware often uses this pattern.',
    fix: 'Decode to a file, read it, and only then run it. Better still, keep the commands as plain text.',
    pattern: /\bbase64\s+(-d|--decode)\b[^\n]*\|\s*(bash|sh)\b/,
    severity: vscode.DiagnosticSeverity.Error,
  },
  {
    id: 'BC009',
    title: 'rm on the filesystem root deletes the whole system.',
    why: 'Running rm on / or /* attempts to remove everything the user has permission to delete.',
    fix: 'Double-check the path. Build paths from variables with "${VAR:?}" so an empty value stops the script.',
    pattern: /\brm\s+(-\w+\s+)*\/(\*)?(\s|$)/,
    severity: vscode.DiagnosticSeverity.Error,
  },
  {
    id: 'BC010',
    title: 'Download over plain HTTP can be tampered with.',
    why: 'Anyone on the network path can modify the content before it reaches you.',
    fix: 'Use https:// instead of http://.',
    pattern: /\b(curl|wget)\b[^\n]*\bhttp:\/\//,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC011',
    title: 'TLS certificate verification is disabled (man-in-the-middle risk).',
    why: 'Without certificate checks, the client cannot tell the real server from an impostor.',
    fix: 'Remove -k, --insecure or --no-check-certificate. If you use a private CA, point to it with --cacert (curl) or --ca-certificate (wget).',
    pattern: /\bcurl\b[^\n]*\s(-\w*k\w*|--insecure)\b|\bwget\b[^\n]*--no-check-certificate/,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC012',
    title: 'Disabling SSH host key checking allows man-in-the-middle attacks.',
    why: 'SSH can no longer detect whether you are connecting to the real host.',
    fix: 'Keep host key checking on and add the host to known_hosts after verifying its fingerprint.',
    pattern: /StrictHostKeyChecking\s*=?\s*no\b/,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC013',
    title: 'Setting setuid/setgid bits can enable privilege escalation.',
    why: 'A setuid program runs with its owner\'s privileges, so any flaw in it can give an attacker those privileges.',
    fix: 'Avoid setuid/setgid. Use targeted sudo rules or Linux capabilities where elevated access is really needed.',
    pattern: /\bchmod\s+(-\w+\s+)*([2467][0-7]{3}|[ug]\+s)\b/,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC014',
    title: 'Current directory in PATH lets a malicious local binary hijack commands.',
    why: 'A file named like a common command in the current directory would run instead of the real one.',
    fix: 'Remove the . entry from PATH and call local programs with an explicit path such as ./tool.',
    pattern: /\bPATH=([^\s]*:)?\.(:|\s|$|["'])/,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC015',
    title: 'Clearing shell history is a common way to hide activity.',
    why: 'Scripts that erase history remove the record of what was run, which also hides mistakes and misuse.',
    fix: 'Do not clear history in scripts. If the concern is secrets, avoid putting them on the command line in the first place.',
    pattern: /\b(history\s+-c|unset\s+HISTFILE|HISTFILE=\/dev\/null)\b/,
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    id: 'BC016',
    title: 'Predictable file in /tmp can be hijacked by symlink attacks.',
    why: 'Another user can create a file or symlink with the same name first and redirect your writes.',
    fix: 'Create temporary files safely: tmp=$(mktemp) and remove them when done.',
    pattern: />>?\s*\/tmp\//,
    severity: vscode.DiagnosticSeverity.Information,
  },
  {
    id: 'BC017',
    title: 'Script uses sudo.',
    why: 'Elevated commands raise the impact of any bug or injected input in the script.',
    fix: 'Check that each sudo call is needed, and elevate only the specific commands that require it.',
    pattern: /(?<=(?:^|[;&|({]|\b(?:then|do|else|elif|if|while|until)\b)\s*)sudo\b/,
    severity: vscode.DiagnosticSeverity.Information,
  },
];

const MIN_LEVEL: Record<string, number> = { Information: 1, Warning: 2, Error: 3 };

type IgnoreList = string[] | 'all' | null;

// Matches: # bashcoach-disable-next-line BC004, BC005   or   # bashcoach-disable-line
const DIRECTIVE = /#\s*bashcoach-disable-(next-line|line)\b(.*)$/;

function severityLevel(s: vscode.DiagnosticSeverity): number {
  switch (s) {
    case vscode.DiagnosticSeverity.Error:
      return 3;
    case vscode.DiagnosticSeverity.Warning:
      return 2;
    case vscode.DiagnosticSeverity.Information:
      return 1;
    default:
      return 0;
  }
}

// No IDs listed after the directive means "ignore every rule".
function parseIds(rest: string): IgnoreList {
  const ids = rest.match(/BC\d{3}/gi);
  return ids ? ids.map((i) => i.toUpperCase()) : 'all';
}

function isIgnored(list: IgnoreList, id: string): boolean {
  return list === 'all' || (list !== null && list.includes(id));
}

function scan(doc: vscode.TextDocument, collection: vscode.DiagnosticCollection) {
  if (doc.languageId !== 'shellscript') {
    return;
  }

  const config = vscode.workspace.getConfiguration('bashcoach', doc.uri);
  const disabled = new Set(
    config.get<string[]>('disabledRules', []).map((s) => s.toUpperCase())
  );
  const minLevel = MIN_LEVEL[config.get<string>('minimumSeverity', 'Information')] ?? 1;

  const diagnostics: vscode.Diagnostic[] = [];
  let nextLineIgnore: IgnoreList = null;

  for (let i = 0; i < doc.lineCount; i++) {
    const text = doc.lineAt(i).text;

    // Ignore rules set by the previous line apply to this line only.
    const ignoreFromPrevious = nextLineIgnore;
    nextLineIgnore = null;

    let ignoreOnThisLine: IgnoreList = null;
    const directive = DIRECTIVE.exec(text);
    if (directive) {
      const ids = parseIds(directive[2]);
      if (directive[1] === 'next-line') {
        nextLineIgnore = ids;
      } else {
        ignoreOnThisLine = ids;
      }
    }

    if (text.trim().startsWith('#')) {
      continue; // skip comments
    }

    for (const rule of rules) {
      if (disabled.has(rule.id)) {
        continue;
      }
      if (severityLevel(rule.severity) < minLevel) {
        continue;
      }
      if (isIgnored(ignoreFromPrevious, rule.id) || isIgnored(ignoreOnThisLine, rule.id)) {
        continue;
      }
      const match = rule.pattern.exec(text);
      if (match) {
        const range = new vscode.Range(i, match.index, i, match.index + match[0].length);
        const message = `${rule.title}\nWhy: ${rule.why}\nFix: ${rule.fix}`;
        const diag = new vscode.Diagnostic(range, message, rule.severity);
        diag.source = 'BashCoach';
        diag.code = rule.id;
        diagnostics.push(diag);
      }
    }
  }
  collection.set(doc.uri, diagnostics);
}

function autoFix(id: string, text: string): { title: string; text: string } | undefined {
  switch (id) {
    case 'BC004':
      return { title: 'Quote the variable', text: text.replace(/(\$\{?\w+\}?)(\s?)$/, '"$1"$2') };
    case 'BC005':
      return { title: 'Change 777 to 755', text: text.replace(/0?777$/, '755') };
    case 'BC010':
      return { title: 'Use https:// instead of http://', text: text.replace(/http:\/\/$/, 'https://') };
    default:
      return undefined;
  }
}

class BashCoachActions implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    doc: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== 'BashCoach' || typeof diag.code !== 'string') {
        continue;
      }

      // 1. Automatic fix, for the rules that have one
      const original = doc.getText(diag.range);
      const fix = autoFix(diag.code, original);
      if (fix && fix.text !== original) {
        const action = new vscode.CodeAction(fix.title, vscode.CodeActionKind.QuickFix);
        action.edit = new vscode.WorkspaceEdit();
        action.edit.replace(doc.uri, diag.range, fix.text);
        action.diagnostics = [diag];
        action.isPreferred = true;
        actions.push(action);
      }

      // 2. Ignore this rule on this line (works for every rule)
      const line = doc.lineAt(diag.range.start.line);
      const indent = line.text.match(/^\s*/)?.[0] ?? '';
      const ignore = new vscode.CodeAction(
        `Ignore ${diag.code} on this line`,
        vscode.CodeActionKind.QuickFix
      );
      ignore.edit = new vscode.WorkspaceEdit();
      ignore.edit.insert(
        doc.uri,
        new vscode.Position(line.lineNumber, 0),
        `${indent}# bashcoach-disable-next-line ${diag.code}\n`
      );
      ignore.diagnostics = [diag];
      actions.push(ignore);
    }
    return actions;
  }
}

export function activate(context: vscode.ExtensionContext) {
  const collection = vscode.languages.createDiagnosticCollection('bashcoach');
  context.subscriptions.push(collection);

    context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider('shellscript', new BashCoachActions(), {
      providedCodeActionKinds: BashCoachActions.providedCodeActionKinds,
    })
  );
  vscode.workspace.textDocuments.forEach((d) => scan(d, collection));

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((d) => scan(d, collection)),
    vscode.workspace.onDidChangeTextDocument((e) => scan(e.document, collection)),
    vscode.workspace.onDidCloseTextDocument((d) => collection.delete(d.uri)),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('bashcoach')) {
        vscode.workspace.textDocuments.forEach((d) => scan(d, collection));
      }
    })
  );
}

export function deactivate() {}