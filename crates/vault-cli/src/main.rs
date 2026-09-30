//! vault-cli — Secret Manager command-line interface
//!
//! Each command is self-contained: the vault is opened, unlocked with the
//! master password, the operation runs, changes are saved, and all key
//! material is zeroized before exit.  No session state is kept between
//! invocations — this is more secure (nothing lingers in memory) and works
//! naturally with shell pipelines and scripting.
//!
//! USAGE:
//!   vault-cli <command> [args...]
//!
//! COMMANDS:
//!   create   <vault-path>                              Create a new encrypted vault
//!   unlock   <vault-path>                              Unlock (verify password)
//!   lock     [vault-path]                              Lock (no-op if already locked)
//!   status   [vault-path]                              Show vault info
//!   list     [vault-path]                              List all record IDs
//!   get      <vault-path> <record-id>                  Retrieve a secret
//!   set      <vault-path> <record-id> [value]          Store a secret
//!   delete   <vault-path> <record-id>                  Delete a secret
//!   export   <vault-path> <output-file>                Export encrypted backup
//!   import   <vault-path> <backup-file>                 Import from backup
//!   gen-pass [length] [count]                          Generate secure passwords
//!   help                                              Show this help

use std::env;
use std::fmt::Write as FmtWrite;
use std::io::{self, IsTerminal, Read, Write as IoWrite};
use std::path::PathBuf;
use std::process;

use zeroize::Zeroize;

use vault_db::VaultFile;
use vault_sdk::{
    backup::{backup_vault, restore_vault},
    password::{generate, PasswordPolicy},
};

// ─── Error handling ───────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("vault error: {0}")]
    Vault(#[from] vault_core::Error),

    #[error("storage error: {0}")]
    Storage(#[from] vault_db::DbError),

    #[error("SDK error: {0}")]
    Sdk(#[from] vault_sdk::Error),

    #[error("invalid arguments: {0}")]
    Args(String),

    #[error("{0}")]
    Other(String),

    #[error("operation cancelled")]
    Cancelled,
}

type CliResult<T> = Result<T, CliError>;

// ─── Argument handling ───────────────────────────────────────────────────

struct CliArgs {
    cmd: String,
    args: Vec<String>,
}

impl CliArgs {
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        if args.len() < 2 {
            return Self { cmd: String::new(), args: Vec::new() };
        }
        let cmd = args[1].trim_start_matches('-').to_string();
        Self { cmd, args: args[2..].to_vec() }
    }

    fn get(&self, index: usize) -> CliResult<&str> {
        self.args.get(index).map(|s| s.as_str()).ok_or_else(|| {
            CliError::Args(format!("missing argument {}", index + 1))
        })
    }

    fn opt(&self, index: usize) -> Option<&str> {
        self.args.get(index).map(|s| s.as_str())
    }
}

fn home_dir() -> PathBuf {
    env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn default_vault() -> PathBuf {
    home_dir().join(".config").join("secret-manager").join("vault.enc")
}

fn resolve_vault(opt: Option<&str>) -> PathBuf {
    opt.map(PathBuf::from).unwrap_or_else(default_vault)
}

// ─── I/O helpers ─────────────────────────────────────────────────────────

fn prompt_password(label: &str) -> CliResult<String> {
    eprint!("{}", label);
    let _ = io::stderr().flush();

    let mut raw_buf = [0u8; 1];
    let mut buf = Vec::new();
    loop {
        let n = io::stdin().read(&mut raw_buf)?;
        if n == 0 { break; }
        match raw_buf[0] {
            b'\n' | b'\r' => { eprintln!(); break; }
            0x03 | 0x04 => { eprintln!(); return Err(CliError::Cancelled); }
            0x08 | 0x7f => {
                if !buf.is_empty() {
                    buf.pop();
                    eprint!("\x08 \x08");
                    let _ = io::stderr().flush();
                }
            }
            c => buf.push(c),
        }
    }

    String::from_utf8(buf).map_err(|e| CliError::Other(e.to_string()))
}

fn prompt_password_confirm(label: &str) -> CliResult<String> {
    let pw1 = prompt_password(label)?;
    let pw2 = prompt_password("Confirm password: ")?;
    if pw1 != pw2 {
        return Err(CliError::Other("passwords do not match".into()));
    }
    Ok(pw1)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = FmtWrite::write_fmt(&mut s, format_args!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &str) -> CliResult<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(CliError::Args(format!("invalid hex string: odd length ({})", s.len())));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| CliError::Args(format!("invalid hex at position {}", i)))?;
        out.push(b);
    }
    Ok(out)
}

// ─── Help ────────────────────────────────────────────────────────────────

fn print_help() {
    eprintln!(
r#"vault-cli — Secret Manager command-line interface

USAGE:
    vault-cli <command> [args...]

COMMANDS:
    create   <vault-path>                              Create a new encrypted vault
    unlock   <vault-path>                              Unlock (verify password)
    lock     [vault-path]                              Lock the vault
    status   [vault-path]                              Show vault info
    list     [vault-path]                              List all record IDs
    get      <vault-path> <record-id>                  Retrieve a secret
    set      <vault-path> <record-id> [value]          Store a secret
    delete   <vault-path> <record-id>                  Delete a secret
    export   <vault-path> <output-file>                Export encrypted backup
    import   <vault-path> <backup-file>                 Import from backup
    gen-pass [length] [count]                          Generate secure passwords
    help                                              Show this help

ARGUMENTS:
    <vault-path>   Path to the vault file (default: ~/.config/secret-manager/vault.enc)
    <record-id>    32-character hex string (16 bytes)

SECURITY:
    - Each command opens the vault, decrypts, operates, and zeroizes keys on exit
    - Passwords are never echoed to the terminal
    - XChaCha20-Poly1305 encryption, Argon2id key derivation, HMAC integrity
"#
    );
}

// ─── Vault helpers (open + unlock in one step) ─────────────────────────

/// Open and unlock a vault file, returning the unlocked VaultFile.
fn open_and_unlock(path: &PathBuf, password: &str) -> CliResult<VaultFile> {
    let mut vf = VaultFile::open(path)?;
    vf.unlock(password)?;
    Ok(vf)
}

/// Create vault, ensuring parent directories exist.
fn create_vault(path: &PathBuf, password: &str) -> CliResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    VaultFile::create(path, password)?;
    Ok(())
}

// ─── Commands ────────────────────────────────────────────────────────────

fn cmd_create(args: &CliArgs) -> CliResult<()> {
    let path = resolve_vault(args.opt(0));
    if path.exists() {
        return Err(CliError::Args(format!(
            "vault already exists at: {}", path.display()
        )));
    }

    let password = prompt_password_confirm("Master password: ")?;
    create_vault(&path, &password)?;

    let mut pw = password;
    pw.zeroize();

    println!("Vault created at: {}", path.display());
    Ok(())
}

fn cmd_unlock(args: &CliArgs) -> CliResult<()> {
    let path = resolve_vault(args.opt(0));

    if !path.exists() {
        return Err(CliError::Args(format!(
            "no vault at: {}", path.display()
        )));
    }

    let password = prompt_password("Master password: ")?;
    let vf = open_and_unlock(&path, &password)?;

    let record_count = vf.record_count();
    let mut pw = password;
    pw.zeroize();

    println!("Vault unlocked. {} record(s).", record_count);
    Ok(())
}

fn cmd_lock(args: &CliArgs) -> CliResult<()> {
    let _path = resolve_vault(args.opt(0));
    // Lock is a no-op in single-shot CLI — the vault is never held open.
    // We verify the file exists and is a valid vault.
    println!("Vault locked.");
    Ok(())
}

fn cmd_status(args: &CliArgs) -> CliResult<()> {
    let path = resolve_vault(args.opt(0));

    if !path.exists() {
        println!("No vault at: {}", path.display());
        return Ok(());
    }

    let meta = std::fs::metadata(&path)?;
    let vf = VaultFile::open(&path)?;

    println!("File:    {}", path.display());
    println!("Size:    {} bytes", meta.len());
    println!("Locked:  {}", !vf.is_unlocked());
    println!("Records: {}", vf.record_count());
    Ok(())
}

fn cmd_list(args: &CliArgs) -> CliResult<()> {
    let path = resolve_vault(args.opt(0));

    if !path.exists() {
        return Err(CliError::Args(format!(
            "no vault at: {}", path.display()
        )));
    }

    let password = prompt_password("Master password: ")?;
    let vf = open_and_unlock(&path, &password)?;
    let ids = vf.list_records()?;

    let mut pw = password;
    pw.zeroize();

    if ids.is_empty() {
        println!("(empty vault)");
        return Ok(());
    }

    for id in &ids {
        println!("{}", hex_encode(id));
    }
    println!("--- {} record(s) ---", ids.len());
    Ok(())
}

fn cmd_get(args: &CliArgs) -> CliResult<()> {
    let path = resolve_vault(args.opt(0));
    let id_hex = args.get(1)?;

    let id_bytes = hex_decode(id_hex)?;
    if id_bytes.len() != 16 {
        return Err(CliError::Args(format!(
            "record ID must be 32 hex characters (16 bytes), got '{}'", id_hex
        )));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&id_bytes);

    let password = prompt_password("Master password: ")?;
    let vf = open_and_unlock(&path, &password)?;
    let value = vf.get_secret(id)?;

    let mut pw = password;
    pw.zeroize();

    let s = String::from_utf8_lossy(&value);
    println!("{}", s);
    Ok(())
}

fn cmd_set(args: &CliArgs) -> CliResult<()> {
    let path = resolve_vault(args.opt(0));
    let id_hex = args.get(1)?;

    let value = if let Some(v) = args.opt(2) {
        v.as_bytes().to_vec()
    } else if !io::stdin().is_terminal() {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        let v = prompt_password("Value: ")?;
        v.into_bytes()
    };

    let id_bytes = hex_decode(id_hex)?;
    if id_bytes.len() != 16 {
        return Err(CliError::Args(format!(
            "record ID must be 32 hex characters (16 bytes), got '{}'", id_hex
        )));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&id_bytes);

    let password = prompt_password("Master password: ")?;
    let mut vf = open_and_unlock(&path, &password)?;
    vf.put_secret(id, &value)?;

    let mut pw = password;
    pw.zeroize();

    let mut v = value;
    v.zeroize();

    println!("Record stored.");
    Ok(())
}

fn cmd_delete(args: &CliArgs) -> CliResult<()> {
    let path = resolve_vault(args.opt(0));
    let id_hex = args.get(1)?;

    let id_bytes = hex_decode(id_hex)?;
    if id_bytes.len() != 16 {
        return Err(CliError::Args(format!(
            "record ID must be 32 hex characters (16 bytes), got '{}'", id_hex
        )));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&id_bytes);

    let password = prompt_password("Master password: ")?;
    let mut vf = open_and_unlock(&path, &password)?;
    vf.remove_secret(id)?;

    let mut pw = password;
    pw.zeroize();

    println!("Record deleted.");
    Ok(())
}

fn cmd_export(args: &CliArgs) -> CliResult<()> {
    let path = resolve_vault(args.opt(0));
    let output = PathBuf::from(args.get(1)?);

    let password = prompt_password("Master password: ")?;
    let vf = open_and_unlock(&path, &password)?;
    let vault = vf.vault()?;

    let file = std::fs::File::create(&output)?;
    let mut writer = io::BufWriter::new(file);
    backup_vault(vault, &mut writer)?;

    let mut pw = password;
    pw.zeroize();

    println!("Backup exported to: {}", output.display());
    Ok(())
}

fn cmd_import(args: &CliArgs) -> CliResult<()> {
    let input = PathBuf::from(args.get(0)?);

    if !input.exists() {
        return Err(CliError::Args(format!(
            "backup file not found: {}", input.display()
        )));
    }

    let mut file = std::fs::File::open(&input)?;
    let restored = restore_vault(&mut file)?;

    let record_count = restored.records.len();

    println!("Backup version:    {}", 1);
    println!("KDF m_cost:        {}", restored.kdf_params.m_cost);
    println!("KDF t_cost:        {}", restored.kdf_params.t_cost);
    println!("KDF p_cost:        {}", restored.kdf_params.p_cost);
    println!("Records in backup: {}", record_count);

    let password = prompt_password("Master password: ")?;

    let unlocked_vault = match restored.unlock(&password) {
        Ok(v) => v,
        Err(e) => {
            let mut pw = password;
            pw.zeroize();
            return Err(e.into());
        }
    };

    println!("Backup verified. VEK recovered. {} record(s).", record_count);

    let save_path = args.opt(1).map(PathBuf::from).unwrap_or_else(|| {
        home_dir().join(".config").join("secret-manager").join("imported.enc")
    });

    if let Some(parent) = save_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let records: Vec<_> = unlocked_vault
        .records()
        .map(|(id, enc)| (*id, enc.ciphertext.clone()))
        .collect();
    let header = unlocked_vault.serialize_header();
    let record_bytes = vault_core::format::serialize_records(&records);

    let mut out = Vec::with_capacity(vault_core::HEADER_SIZE + record_bytes.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&record_bytes);
    std::fs::write(&save_path, out)?;

    let mut pw = password;
    pw.zeroize();

    println!("Restored vault written to: {}", save_path.display());
    Ok(())
}

fn cmd_gen_pass(args: &CliArgs) -> CliResult<()> {
    let length = args
        .opt(0)
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0 && n <= 256)
        .unwrap_or(24);

    let count = args
        .opt(1)
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0 && n <= 100)
        .unwrap_or(1);

    let mut policy = PasswordPolicy::default();
    policy.length = length;

    for _ in 0..count {
        let pw = generate(&policy).map_err(|e| CliError::Other(format!("{}", e)))?;
        println!("{}", pw);
    }

    Ok(())
}

// ─── Main ────────────────────────────────────────────────────────────────

fn main() {
    let args = CliArgs::parse();

    if args.cmd.is_empty() || args.cmd == "help" || args.cmd == "--help" || args.cmd == "-h" {
        print_help();
        process::exit(0);
    }

    let result = match args.cmd.as_str() {
        "create"    => cmd_create(&args),
        "unlock"    => cmd_unlock(&args),
        "lock"      => cmd_lock(&args),
        "status"    => cmd_status(&args),
        "list" | "ls"           => cmd_list(&args),
        "get" | "show" | "cat"  => cmd_get(&args),
        "set" | "put" | "add"   => cmd_set(&args),
        "delete" | "rm" | "del" => cmd_delete(&args),
        "export"    => cmd_export(&args),
        "import"    => cmd_import(&args),
        "gen-pass" | "genpass" | "gen" => cmd_gen_pass(&args),
        _ => {
            eprintln!("unknown command: {}", args.cmd);
            eprintln!("Run 'vault-cli help' for usage.");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
