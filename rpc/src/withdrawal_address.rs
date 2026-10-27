//! Opt-in, write-once binding of the node's withdrawal address
//! (`summit run --withdrawal-address-path <file>`).
//!
//! The first `getDepositSignature` binds the request's address to a file, and
//! every later request must carry that same address or is refused. A founder
//! (a genesis validator) is bound to its genesis address at startup, before any
//! request. The file is never rewritten: changing the address means resetting
//! the node with new keys.

use alloy_primitives::{Address, AddressError};
use anyhow::{Context as _, anyhow, bail};
use std::fmt;
use std::fs;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

/// A withdrawal address that passed the strict parse: non-zero, and, when
/// parsed from a string, in its exact EIP-55 checksummed form. A typo bound
/// here is permanent, and withdrawals to the zero address are burned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawalAddress(Address);

impl FromStr for WithdrawalAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let address = Address::parse_checksummed(s, None).map_err(|e| match e {
            AddressError::Hex(_) => format!("{s:?} is not 0x followed by 40 hex characters"),
            // `parse_checksummed` only checks the checksum of `0x` plus 40 hex chars.
            AddressError::InvalidChecksum
                if !s[2..].bytes().any(|b| b.is_ascii_uppercase())
                    || !s[2..].bytes().any(|b| b.is_ascii_lowercase()) =>
            {
                format!("{s} has no EIP-55 checksum; pass the checksummed form")
            }
            AddressError::InvalidChecksum => {
                format!("{s} has an invalid EIP-55 checksum; check it for typos")
            }
        })?;
        Self::try_from(address)
    }
}

impl TryFrom<Address> for WithdrawalAddress {
    type Error = String;

    fn try_from(address: Address) -> Result<Self, Self::Error> {
        if address.is_zero() {
            return Err("the zero address is not a valid withdrawal address".to_string());
        }
        Ok(Self(address))
    }
}

impl From<WithdrawalAddress> for Address {
    fn from(address: WithdrawalAddress) -> Self {
        address.0
    }
}

impl fmt::Display for WithdrawalAddress {
    /// The EIP-55 checksummed form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The write-once file at `--withdrawal-address-path`, holding the address
/// this node signs deposits for once one is bound.
pub struct WithdrawalAddressFile {
    path: PathBuf,
    /// The file's address, or `None` while the file doesn't exist. Holding the
    /// lock while writing the file serializes concurrent first binds.
    address: Mutex<Option<WithdrawalAddress>>,
}

impl WithdrawalAddressFile {
    /// Opens the file at `path`, which need not exist yet. A missing parent
    /// directory, or an unreadable or malformed file, is an error rather than
    /// "unbound".
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let dir = parent_dir(&path);
        if !dir.is_dir() {
            bail!(
                "withdrawal address directory {} does not exist",
                dir.display()
            );
        }
        Ok(Self {
            address: Mutex::new(read(&path)?),
            path,
        })
    }

    /// The file's address, or `None` if nothing is bound yet.
    pub fn address(&self) -> Option<WithdrawalAddress> {
        *self.address.lock().unwrap()
    }

    /// Returns the file's address, first writing `address` to it if nothing is
    /// bound yet.
    pub fn get_or_bind(&self, address: WithdrawalAddress) -> anyhow::Result<WithdrawalAddress> {
        let mut guard = self.address.lock().unwrap();
        if let Some(bound) = *guard {
            return Ok(bound);
        }
        let bound = publish(&self.path, address).context("failed to bind withdrawal address")?;
        if bound == address {
            tracing::info!(%address, path = %self.path.display(), "bound withdrawal address");
        }
        *guard = Some(bound);
        Ok(bound)
    }
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

fn read(path: &Path) -> anyhow::Result<Option<WithdrawalAddress>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
    };
    let address = contents.strip_suffix('\n').unwrap_or(&contents);
    address
        .parse()
        .map(Some)
        .map_err(|e| anyhow!("malformed withdrawal address file {}: {e}", path.display()))
}

/// Writes `address` to `path` without ever replacing an existing file, and
/// returns the address the file holds afterwards: `address`, or the one
/// already there if another writer got in first.
///
/// The address is written and fsynced under a temporary name in the same
/// directory, then published with `link(2)`, which fails rather than replace
/// an existing file; the directory is fsynced last so the link is durable.
fn publish(path: &Path, address: WithdrawalAddress) -> anyhow::Result<WithdrawalAddress> {
    let dir = parent_dir(path);
    let file_name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?;
    let tmp_path = dir.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    // A temporary file left by a crashed process with the same PID is stale.
    let _ = fs::remove_file(&tmp_path);
    let result = write_and_link(&tmp_path, path, address);
    let _ = fs::remove_file(&tmp_path);

    if !result.with_context(|| format!("failed to write {}", path.display()))? {
        return read(path)?.with_context(|| format!("{} disappeared", path.display()));
    }
    fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("failed to sync {}", dir.display()))?;
    Ok(address)
}

/// Returns `false` if `path` already exists.
fn write_and_link(
    tmp_path: &Path,
    path: &Path,
    address: WithdrawalAddress,
) -> std::io::Result<bool> {
    let mut file = fs::File::create_new(tmp_path)?;
    writeln!(file, "{address}")?;
    file.sync_all()?;
    match fs::hard_link(tmp_path, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKSUMMED: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn address(byte: u8) -> WithdrawalAddress {
        WithdrawalAddress::try_from(Address::repeat_byte(byte)).unwrap()
    }

    #[test]
    fn parse_accepts_checksummed() {
        let parsed = CHECKSUMMED.parse::<WithdrawalAddress>().unwrap();
        assert_eq!(
            Address::from(parsed),
            CHECKSUMMED.parse::<Address>().unwrap()
        );
        assert_eq!(parsed.to_string(), CHECKSUMMED);
    }

    #[test]
    fn parse_rejects_malformed_addresses() {
        // Wrong checksum: one letter's case flipped.
        let bad_checksum = CHECKSUMMED.replacen("f39Fd", "f39fd", 1);
        let lower = CHECKSUMMED.to_lowercase();
        let upper = format!("0x{}", CHECKSUMMED[2..].to_uppercase());
        for bad in [
            bad_checksum.as_str(),
            &lower,
            &upper,
            &CHECKSUMMED[2..],                             // no 0x
            &format!("0X{}", &CHECKSUMMED[2..]),           // uppercase prefix
            &CHECKSUMMED[..41],                            // too short
            &format!("{CHECKSUMMED}00"),                   // too long
            &format!("0x{}g", &CHECKSUMMED[2..41]),        // non-hex
            " 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", // whitespace
            "0x0000000000000000000000000000000000000000",  // zero
        ] {
            assert!(
                bad.parse::<WithdrawalAddress>().is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(WithdrawalAddress::try_from(Address::ZERO).is_err());
    }

    #[test]
    fn parse_errors_say_what_went_wrong() {
        let reason = |s: &str| s.parse::<WithdrawalAddress>().unwrap_err();
        assert!(reason(&CHECKSUMMED[2..]).contains("not 0x followed by 40 hex"));
        assert!(reason(&CHECKSUMMED.to_lowercase()).contains("no EIP-55 checksum"));
        let upper = format!("0x{}", CHECKSUMMED[2..].to_uppercase());
        assert!(reason(&upper).contains("no EIP-55 checksum"));
        let typo = CHECKSUMMED.replacen("f39Fd", "f39fd", 1);
        assert!(reason(&typo).contains("invalid EIP-55 checksum"));
        assert!(reason("0x0000000000000000000000000000000000000000").contains("zero address"));
    }

    #[test]
    fn get_or_bind_writes_once_then_returns_the_bound_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("withdrawal-address");
        let file = WithdrawalAddressFile::open(path.clone()).unwrap();
        assert_eq!(file.address(), None);

        let first = CHECKSUMMED.parse().unwrap();
        assert_eq!(file.get_or_bind(first).unwrap(), first);
        assert_eq!(file.get_or_bind(address(0x22)).unwrap(), first);
        assert_eq!(file.address(), Some(first));

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("{CHECKSUMMED}\n")
        );
        // Only the published file is left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn open_rejects_missing_dir_and_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            WithdrawalAddressFile::open(dir.path().join("missing/withdrawal-address")).is_err()
        );

        let path = dir.path().join("withdrawal-address");
        fs::write(&path, "not an address\n").unwrap();
        assert!(WithdrawalAddressFile::open(path.clone()).is_err());

        fs::write(&path, "").unwrap();
        assert!(WithdrawalAddressFile::open(path).is_err());
    }

    #[test]
    fn publish_never_replaces_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("withdrawal-address");

        assert_eq!(publish(&path, address(0x11)).unwrap(), address(0x11));
        // A second writer (e.g. another process) sees the first one's address.
        assert_eq!(publish(&path, address(0x22)).unwrap(), address(0x11));
        assert_eq!(read(&path).unwrap(), Some(address(0x11)));
    }
}
