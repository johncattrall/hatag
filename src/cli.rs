use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::output::OutputFormat;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Format {
    Json,
    Plist,
    Both,
}

impl From<Format> for OutputFormat {
    fn from(value: Format) -> Self {
        match value {
            Format::Json => Self::Json,
            Format::Plist => Self::Plist,
            Format::Both => Self::Both,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Conversion {
    HomeAssistant,
}

#[derive(Debug, Parser)]
#[command(version, about = "Export Find My accessory keys and prepare Home Assistant imports")]
pub struct Args {
    /// Scan local Bluetooth advertisements; no Apple login is performed
    #[arg(long, conflicts_with = "convert")]
    pub diagnose: bool,

    /// Convert existing plist or JSON exports offline
    #[arg(long, value_enum, conflicts_with = "diagnose")]
    pub convert: Option<Conversion>,

    /// Export format; Home Assistant accepts the JSON files as rolling-derived devices
    #[arg(long, value_enum, default_value = "json", conflicts_with_all = ["diagnose", "convert"])]
    pub output: Format,

    /// Directory for exports or conversions; diagnostics scans its JSON files when no files are given
    #[arg(long, default_value = "ha-imports")]
    pub output_dir: PathBuf,

    /// Apple Account email (prompted if omitted)
    #[arg(long, conflicts_with_all = ["diagnose", "convert"])]
    pub apple_id: Option<String>,

    /// Remote anisette v3 service used only during iCloud export
    #[arg(long, default_value = "https://ani.sidestore.io", conflicts_with_all = ["diagnose", "convert"])]
    pub anisette_url: String,

    /// Python interpreter containing requirements-diagnostics.txt (or FINDMY_PYTHON)
    #[arg(long, env = "FINDMY_PYTHON", default_value = "python3")]
    pub python: PathBuf,

    /// Bluetooth capture duration; key matching may take longer
    #[arg(long, default_value = "30", value_parser = clap::value_parser!(u64).range(1..=3600), requires = "diagnose")]
    pub scan_seconds: u64,

    /// Save primary-key alignment matches after making a verified private backup
    #[arg(long, requires = "diagnose")]
    pub save_alignment: bool,

    /// Input files for --diagnose or --convert; omit for diagnostics to scan --output-dir
    #[arg(value_name = "FILE")]
    pub files: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_modes_are_exclusive() {
        assert!(Args::try_parse_from(["importer", "--diagnose", "--convert=home-assistant"]).is_err());
        assert!(Args::try_parse_from(["importer", "--save-alignment"]).is_err());
        assert!(Args::try_parse_from(["importer", "--diagnose", "--apple-id", "test@example.com"]).is_err());
        assert!(Args::try_parse_from(["importer", "--diagnose", "--scan-seconds", "0"]).is_err());
    }
}
