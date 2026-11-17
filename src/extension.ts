import * as vscode from 'vscode';

interface Rule {
  pattern: RegExp;
  message: string;
  severity: vscode.DiagnosticSeverity;
}

const rules: Rule[] = [
  {
    pattern: /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(bash|sh)\b/,
    message: 'Piping a download straight into a shell runs unverified code.',
    severity: vscode.DiagnosticSeverity.Error,
  },
  {
    pattern: /\beval\b/,
    message: 'eval can execute attacker-controlled input (command injection).',
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    pattern: /\b(password|passwd|secret|api_?key|token)\s*=\s*["']?[^\s"']+/i,
    message: 'Possible hardcoded credential. Use environment variables or a secrets manager.',
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    pattern: /\brm\s+(-\w+\s+)*\$\{?\w+\}?(\s|$)/,
    message: 'Unquoted variable in rm. If it is empty or contains spaces, the wrong files can be deleted.',
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    pattern: /\bchmod\s+(-\w+\s+)*0?777\b/,
    message: 'chmod 777 gives everyone read, write, and execute access.',
    severity: vscode.DiagnosticSeverity.Warning,
  },
    // --- Reverse shells and backdoors ---
  {
    pattern: /\/dev\/(tcp|udp)\//,
    message: 'Bash network redirection via /dev/tcp is a common reverse shell technique.',
    severity: vscode.DiagnosticSeverity.Error,
  },
  {
    pattern: /\b(nc|ncat|netcat)\b[^\n]*\s-(e|c)\b/,
    message: 'netcat with -e/-c executes a program over the network (reverse/bind shell).',
    severity: vscode.DiagnosticSeverity.Error,
  },
  {
    pattern: /\bbase64\s+(-d|--decode)\b[^\n]*\|\s*(bash|sh)\b/,
    message: 'Decoding base64 straight into a shell hides what the script runs.',
    severity: vscode.DiagnosticSeverity.Error,
  },
  // --- Destructive commands ---
  {
    pattern: /\brm\s+(-\w+\s+)*\/(\*)?(\s|$)/,
    message: 'rm on the filesystem root deletes the whole system.',
    severity: vscode.DiagnosticSeverity.Error,
  },
  // --- Insecure transport ---
  {
    pattern: /\b(curl|wget)\b[^\n]*\bhttp:\/\//,
    message: 'Download over plain HTTP can be tampered with. Use HTTPS.',
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    pattern: /\bcurl\b[^\n]*\s(-\w*k\w*|--insecure)\b|\bwget\b[^\n]*--no-check-certificate/,
    message: 'TLS certificate verification is disabled (man-in-the-middle risk).',
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    pattern: /StrictHostKeyChecking\s*=?\s*no\b/,
    message: 'Disabling SSH host key checking allows man-in-the-middle attacks.',
    severity: vscode.DiagnosticSeverity.Warning,
  },
  // --- Privilege and permissions ---
  {
    pattern: /\bchmod\s+(-\w+\s+)*([2467][0-7]{3}|[ug]\+s)\b/,
    message: 'Setting setuid/setgid bits can enable privilege escalation.',
    severity: vscode.DiagnosticSeverity.Warning,
  },
  {
    pattern: /\bPATH=([^\s]*:)?\.(:|\s|$|["'])/,
    message: 'Current directory in PATH lets a malicious local binary hijack commands.',
    severity: vscode.DiagnosticSeverity.Warning,
  },
  // --- Anti-forensics ---
  {
    pattern: /\b(history\s+-c|unset\s+HISTFILE|HISTFILE=\/dev\/null)\b/,
    message: 'Clearing shell history is a common way to hide activity.',
    severity: vscode.DiagnosticSeverity.Warning,
  },
  // --- Informational ---
  {
    pattern: />>?\s*\/tmp\//,
    message: 'Predictable file in /tmp can be hijacked by symlink attacks. Consider mktemp.',
    severity: vscode.DiagnosticSeverity.Information,
  },
  {
    pattern: /\bsudo\b/,
    message: 'Script uses sudo. Make sure it needs elevated privileges.',
    severity: vscode.DiagnosticSeverity.Information,
  },
];

function scan(doc: vscode.TextDocument, collection: vscode.DiagnosticCollection) {
  if (doc.languageId !== 'shellscript') {
    return;
  }
  const diagnostics: vscode.Diagnostic[] = [];

  for (let i = 0; i < doc.lineCount; i++) {
    const text = doc.lineAt(i).text;
    if (text.trim().startsWith('#')) {
      continue; // skip comments
    }
    for (const rule of rules) {
      const match = rule.pattern.exec(text);
      if (match) {
        const range = new vscode.Range(i, match.index, i, match.index + match[0].length);
        const diag = new vscode.Diagnostic(range, rule.message, rule.severity);
        diag.source = 'BashCoach';
        diagnostics.push(diag);
      }
    }
  }
  collection.set(doc.uri, diagnostics);
}

export function activate(context: vscode.ExtensionContext) {
  const collection = vscode.languages.createDiagnosticCollection('bashcoach');
  context.subscriptions.push(collection);

  vscode.workspace.textDocuments.forEach((d) => scan(d, collection));

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((d) => scan(d, collection)),
    vscode.workspace.onDidChangeTextDocument((e) => scan(e.document, collection)),
    vscode.workspace.onDidCloseTextDocument((d) => collection.delete(d.uri))
  );
}

export function deactivate() {}