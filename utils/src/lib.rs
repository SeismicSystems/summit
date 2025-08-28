use anyhow::{Context, Result};
use dirs::home_dir;
use std::{path::PathBuf, str::FromStr};

pub fn get_expanded_path(path: &str) -> Result<PathBuf> {
    let path_buf = PathBuf::from_str(path).context("unable to parse path")?;

    if path_buf.starts_with("~") {
        let home_dir = home_dir().context("Unable to find a home directory to use with path")?;

        if path_buf == PathBuf::from("~") {
            return Ok(home_dir);
        } else if let Ok(relative) = path_buf.strip_prefix("~/") {
            return Ok(home_dir.join(relative));
        }
    }

    Ok(path_buf)
}
