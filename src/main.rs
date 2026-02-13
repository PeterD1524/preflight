use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use indexmap::IndexMap;
use serde::Deserialize;

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "preflight",
    about = "Declarative environment checker and shell launcher"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run all checks defined in the config file
    Check {
        #[arg(long, short)]
        config: String,
        /// Confirm each check before running it
        #[arg(long, short = 'i')]
        interactive: bool,
    },
    /// Launch a shell with the environment defined in the config file
    Shell {
        #[arg(long, short)]
        config: String,
    },
}

// ── Config types ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RawConfig {
    vars: Option<IndexMap<String, String>>,
    shell: Option<ShellConfig>,
    check: Option<Vec<Check>>,
}

#[derive(Deserialize)]
struct ShellConfig {
    home: Option<String>,
    shell: Option<String>,
    env_clear: Option<bool>,
    env: Option<IndexMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Check {
    EnvVar {
        description: Option<String>,
        name: String,
        value: String,
    },
    CommandExists {
        description: Option<String>,
        command: String,
    },
    FileExists {
        description: Option<String>,
        path: String,
    },
    DirExists {
        description: Option<String>,
        path: String,
    },
    FileContains {
        description: Option<String>,
        path: String,
        contains: String,
    },
    Command {
        description: Option<String>,
        command: String,
        args: Option<Vec<String>>,
        exit_code: Option<i32>,
        stdout_contains: Option<String>,
        stderr_contains: Option<String>,
    },
    Script {
        description: Option<String>,
        script: String,
    },
}

// ── Variable substitution ────────────────────────────────────────────

fn substitute(s: &str, vars: &HashMap<String, String>) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let key: String = chars.by_ref().take_while(|&c| c != '}').collect();
            if let Some(val) = vars.get(&key) {
                result.push_str(val);
            } else {
                // preserve unresolved references as-is
                result.push_str(&format!("${{{}}}", key));
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn resolve_vars(
    user_vars: Option<IndexMap<String, String>>,
) -> Result<HashMap<String, String>, String> {
    let mut vars: HashMap<String, String> = std::env::vars().collect();

    // Add UID if not present
    if !vars.contains_key("UID") {
        let uid = unsafe { libc::getuid() };
        vars.insert("UID".to_string(), uid.to_string());
    }

    // Resolve user-defined vars in order
    if let Some(user_vars) = user_vars {
        for (k, v) in user_vars {
            let resolved = substitute(&v, &vars);
            if resolved.contains("${") {
                return Err(format!("unresolved variable in '{}': {}", k, resolved));
            }
            vars.insert(k, resolved);
        }
    }
    Ok(vars)
}

fn substitute_config(config: RawConfig, vars: &HashMap<String, String>) -> RawConfig {
    let shell = config.shell.map(|s| ShellConfig {
        home: s.home.map(|v| substitute(&v, vars)),
        shell: s.shell.map(|v| substitute(&v, vars)),
        env_clear: s.env_clear,
        env: s.env.map(|m| {
            m.into_iter()
                .map(|(k, v)| (substitute(&k, vars), substitute(&v, vars)))
                .collect()
        }),
    });

    let check = config.check.map(|checks| {
        checks
            .into_iter()
            .map(|c| substitute_check(c, vars))
            .collect()
    });

    RawConfig {
        vars: None,
        shell,
        check,
    }
}

fn substitute_check(check: Check, vars: &HashMap<String, String>) -> Check {
    match check {
        Check::EnvVar {
            description,
            name,
            value,
        } => Check::EnvVar {
            description: description.map(|d| substitute(&d, vars)),
            name: substitute(&name, vars),
            value: substitute(&value, vars),
        },
        Check::CommandExists {
            description,
            command,
        } => Check::CommandExists {
            description: description.map(|d| substitute(&d, vars)),
            command: substitute(&command, vars),
        },
        Check::FileExists { description, path } => Check::FileExists {
            description: description.map(|d| substitute(&d, vars)),
            path: substitute(&path, vars),
        },
        Check::DirExists { description, path } => Check::DirExists {
            description: description.map(|d| substitute(&d, vars)),
            path: substitute(&path, vars),
        },
        Check::FileContains {
            description,
            path,
            contains,
        } => Check::FileContains {
            description: description.map(|d| substitute(&d, vars)),
            path: substitute(&path, vars),
            contains: substitute(&contains, vars),
        },
        Check::Command {
            description,
            command,
            args,
            exit_code,
            stdout_contains,
            stderr_contains,
        } => Check::Command {
            description: description.map(|d| substitute(&d, vars)),
            command: substitute(&command, vars),
            args: args.map(|a| a.iter().map(|s| substitute(s, vars)).collect()),
            exit_code,
            stdout_contains: stdout_contains.map(|s| substitute(&s, vars)),
            stderr_contains: stderr_contains.map(|s| substitute(&s, vars)),
        },
        Check::Script {
            description,
            script,
        } => Check::Script {
            description: description.map(|d| substitute(&d, vars)),
            script: substitute(&script, vars),
        },
    }
}

// ── Check runner ─────────────────────────────────────────────────────

struct CheckResult {
    description: String,
    passed: bool,
    detail: Option<String>,
}

fn check_description(check: &Check) -> &str {
    match check {
        Check::EnvVar { description, .. }
        | Check::CommandExists { description, .. }
        | Check::FileExists { description, .. }
        | Check::DirExists { description, .. }
        | Check::FileContains { description, .. }
        | Check::Command { description, .. }
        | Check::Script { description, .. } => description.as_deref().unwrap_or("(unnamed)"),
    }
}

fn run_check(check: &Check) -> CheckResult {
    match check {
        Check::EnvVar {
            description,
            name,
            value,
        } => {
            let desc = description
                .clone()
                .unwrap_or_else(|| format!("env {} = {}", name, value));
            match std::env::var(name) {
                Ok(actual) if actual == *value => CheckResult {
                    description: desc,
                    passed: true,
                    detail: None,
                },
                Ok(actual) => CheckResult {
                    description: desc,
                    passed: false,
                    detail: Some(format!("got '{}'", actual)),
                },
                Err(_) => CheckResult {
                    description: desc,
                    passed: false,
                    detail: Some("not set".to_string()),
                },
            }
        }

        Check::CommandExists {
            description,
            command,
        } => {
            let desc = description
                .clone()
                .unwrap_or_else(|| format!("{} in PATH", command));
            let found = which(command);
            CheckResult {
                description: desc,
                passed: found,
                detail: if found {
                    None
                } else {
                    Some("not found in PATH".to_string())
                },
            }
        }

        Check::FileExists { description, path } => {
            let desc = description
                .clone()
                .unwrap_or_else(|| format!("file {}", path));
            let exists = Path::new(path).is_file();
            CheckResult {
                description: desc,
                passed: exists,
                detail: if exists {
                    None
                } else {
                    Some("not found".to_string())
                },
            }
        }

        Check::DirExists { description, path } => {
            let desc = description
                .clone()
                .unwrap_or_else(|| format!("dir {}", path));
            let exists = Path::new(path).is_dir();
            CheckResult {
                description: desc,
                passed: exists,
                detail: if exists {
                    None
                } else {
                    Some("not found".to_string())
                },
            }
        }

        Check::FileContains {
            description,
            path,
            contains,
        } => {
            let desc = description
                .clone()
                .unwrap_or_else(|| format!("{} contains '{}'", path, contains));
            match std::fs::read_to_string(path) {
                Ok(content) if content.contains(contains.as_str()) => CheckResult {
                    description: desc,
                    passed: true,
                    detail: None,
                },
                Ok(_) => CheckResult {
                    description: desc,
                    passed: false,
                    detail: Some(format!("'{}' not found in file", contains)),
                },
                Err(e) => CheckResult {
                    description: desc,
                    passed: false,
                    detail: Some(e.to_string()),
                },
            }
        }

        Check::Command {
            description,
            command,
            args,
            exit_code,
            stdout_contains,
            stderr_contains,
        } => {
            let desc = description.clone().unwrap_or_else(|| {
                let a = args.as_ref().map(|a| a.join(" ")).unwrap_or_default();
                format!("{} {}", command, a).trim().to_string()
            });
            let expected_code = exit_code.unwrap_or(0);

            let mut cmd = Command::new(command);
            if let Some(args) = args {
                cmd.args(args);
            }

            match cmd.output() {
                Ok(output) => {
                    let code = output.status.code().unwrap_or(-1);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);

                    let mut failures: Vec<String> = Vec::new();

                    if code != expected_code {
                        failures.push(format!("exit code {} (expected {})", code, expected_code));
                    }
                    if let Some(expected) = stdout_contains
                        && !stdout.contains(expected.as_str())
                    {
                        failures.push(format!("stdout missing '{}'", expected));
                    }
                    if let Some(expected) = stderr_contains
                        && !stderr.contains(expected.as_str())
                    {
                        failures.push(format!("stderr missing '{}'", expected));
                    }

                    CheckResult {
                        description: desc,
                        passed: failures.is_empty(),
                        detail: if failures.is_empty() {
                            None
                        } else {
                            Some(failures.join(", "))
                        },
                    }
                }
                Err(e) => CheckResult {
                    description: desc,
                    passed: false,
                    detail: Some(e.to_string()),
                },
            }
        }

        Check::Script {
            description,
            script,
        } => {
            let desc = description
                .clone()
                .unwrap_or_else(|| format!("script: {}", script));

            // script check runs inline shell code via sh -c
            // This is intentional — the script content comes from the user's own config file,
            // not from untrusted input.
            match Command::new("sh").arg("-c").arg(script).status() {
                Ok(status) => CheckResult {
                    description: desc,
                    passed: status.success(),
                    detail: if status.success() {
                        None
                    } else {
                        Some(format!("exit code {}", status.code().unwrap_or(-1)))
                    },
                },
                Err(e) => CheckResult {
                    description: desc,
                    passed: false,
                    detail: Some(e.to_string()),
                },
            }
        }
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match path.metadata() {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

fn which(cmd: &str) -> bool {
    if cmd.contains('/') {
        return is_executable(Path::new(cmd));
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            if is_executable(&Path::new(dir).join(cmd)) {
                return true;
            }
        }
    }
    false
}

// ── Shell launcher ───────────────────────────────────────────────────

fn launch_shell(shell_config: ShellConfig) -> Result<(), Box<dyn std::error::Error>> {
    let shell = shell_config.shell.ok_or("shell.shell is required")?;

    let mut cmd = Command::new(&shell);

    if shell_config.env_clear.unwrap_or(false) {
        cmd.env_clear();
    }

    if let Some(ref home) = shell_config.home {
        std::env::set_current_dir(home)?;
        cmd.env("HOME", home);
    }

    if let Some(env) = shell_config.env {
        for (k, v) in env {
            cmd.env(k, v);
        }
    }

    let err = cmd.exec();
    Err(err.into())
}

// ── Main ─────────────────────────────────────────────────────────────

fn load_config(path: &str) -> Result<RawConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let mut config: RawConfig = toml::from_str(&content)?;
    let vars =
        resolve_vars(config.vars.take()).map_err(|e| format!("variable resolution failed: {e}"))?;
    Ok(substitute_config(config, &vars))
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Cmd::Check {
            config,
            interactive,
        } => {
            let cfg = load_config(&config)?;
            let checks = cfg.check.unwrap_or_default();

            if checks.is_empty() {
                println!("No checks defined.");
                return Ok(true);
            }

            let mut passed = 0;
            let mut failed = 0;
            let stdin = std::io::stdin();

            for (i, check) in checks.iter().enumerate() {
                if interactive {
                    let desc = check_description(check);
                    eprint!("[{}/{}] Run '{}'? [Y/n] ", i + 1, checks.len(), desc);
                    let mut input = String::new();
                    stdin.read_line(&mut input)?;
                    let input = input.trim();
                    if input.eq_ignore_ascii_case("n") || input.eq_ignore_ascii_case("no") {
                        println!("[SKIP] {}", desc);
                        continue;
                    }
                }

                let result = run_check(check);
                if result.passed {
                    println!("[PASS] {}", result.description);
                    passed += 1;
                } else {
                    let detail = result.detail.as_deref().unwrap_or("failed");
                    println!("[FAIL] {} — {}", result.description, detail);
                    failed += 1;
                }
            }

            let total = passed + failed;
            println!();
            println!("{} passed, {} failed (of {} checks)", passed, failed, total);

            Ok(failed == 0)
        }

        Cmd::Shell { config } => {
            let cfg = load_config(&config)?;
            let shell_config = cfg.shell.ok_or("no [shell] section in config")?;
            launch_shell(shell_config)?;
            Ok(true)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
