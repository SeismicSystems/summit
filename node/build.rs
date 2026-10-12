//! Embeds what `summit --version` reports about the build:
//! - `SUMMIT_COMMIT_HASH`: the full commit hash for a build of a clean
//!   checkout, `<hash>-dirty` when tracked files differ from that commit, or
//!   `unknown` when the source is not a git checkout of this workspace;
//! - `SUMMIT_COMMIT_DATE`: that commit's date (`YYYY-MM-DD`), or `unknown`;
//! - `SUMMIT_BUILD_TARGET`: the target triple the binary is built for.
//!
//! Nothing here depends on when the build ran, so rebuilding a commit
//! reproduces the same binary.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("node/ is inside the workspace root")
        .to_path_buf();
    let (commit_hash, commit_date) = git_commit(&workspace_root)
        .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));
    println!("cargo:rustc-env=SUMMIT_COMMIT_HASH={commit_hash}");
    println!("cargo:rustc-env=SUMMIT_COMMIT_DATE={commit_date}");
    println!(
        "cargo:rustc-env=SUMMIT_BUILD_TARGET={}",
        env::var("TARGET").expect("cargo sets TARGET for build scripts")
    );
    println!("cargo:rerun-if-changed=build.rs");
}

/// Returns the commit hash (with `-dirty` when tracked files differ from it)
/// and the commit date.
fn git_commit(workspace_root: &Path) -> Option<(String, String)> {
    // Sources copied into another repository would otherwise report that
    // repository's commit.
    let toplevel = PathBuf::from(git(workspace_root, &["rev-parse", "--show-toplevel"])?);
    if toplevel.canonicalize().ok()? != workspace_root.canonicalize().ok()? {
        return None;
    }

    let hash = git(workspace_root, &["rev-parse", "--verify", "HEAD"])?;
    let date = git(workspace_root, &["log", "-1", "--format=%cs", "HEAD"])?;
    // Untracked files are left out: none enters the build without a tracked
    // change that references it, which already marks the tree dirty.
    // `--no-optional-locks` keeps `status` from rewriting the index, which is
    // watched below and would rerun this script on every build.
    let dirty = !git(
        workspace_root,
        &[
            "--no-optional-locks",
            "status",
            "--porcelain",
            "--untracked-files=no",
        ],
    )?
    .is_empty();

    rerun_if_tree_or_head_changes(workspace_root);
    let hash = if dirty { format!("{hash}-dirty") } else { hash };
    Some((hash, date))
}

/// Reruns this script when a tracked file is edited or HEAD moves, so the
/// embedded commit and dirty mark never go stale.
fn rerun_if_tree_or_head_changes(workspace_root: &Path) {
    if let Some(tracked) = git(workspace_root, &["ls-files", "-z"]) {
        for path in tracked.split('\0').filter(|path| !path.is_empty()) {
            println!(
                "cargo:rerun-if-changed={}",
                workspace_root.join(path).display()
            );
        }
    }

    let mut git_paths = vec![
        "HEAD".to_string(),
        "index".to_string(),
        "packed-refs".to_string(),
    ];
    if let Some(branch_ref) = git(workspace_root, &["symbolic-ref", "-q", "HEAD"]) {
        git_paths.push(branch_ref);
    }
    for git_path in git_paths {
        let Some(path) = git(
            workspace_root,
            &[
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                &git_path,
            ],
        ) else {
            continue;
        };
        // Cargo reruns on every build for a path that does not exist, e.g. a
        // branch ref that is only in packed-refs.
        if Path::new(&path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

/// Runs git in `dir`, returning its trimmed stdout, or `None` when git is
/// missing or fails.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}
