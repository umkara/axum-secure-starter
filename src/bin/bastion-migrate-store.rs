//! Copies a SQLite Bastion database into a PostgreSQL one.
//!
//! ```text
//! bastion-migrate-store --from sqlite:///var/lib/bastion/app.db --to postgres://user:pass@host/bastion
//! ```
//!
//! Build it with both drivers, since it talks to both at once:
//!
//! ```sh
//! cargo build --release --features postgres --bin bastion-migrate-store
//! ```
//!
//! The interesting parts — read-only source, empty-target check, single
//! transaction, verify-before-commit — are in [`bastion::migrate`]. This file is
//! argument parsing and the words the operator reads.

use std::process::ExitCode;

use bastion::migrate::{self, Plan};

const USAGE: &str = "\
copies a SQLite Bastion database into an empty PostgreSQL one

usage: bastion-migrate-store --from <sqlite-url> --to <postgres-url> [--dry-run]

  --from <url>   source, e.g. sqlite:///var/lib/bastion/app.db
  --to <url>     target, e.g. postgres://bastion:pw@localhost/bastion
  --dry-run      do the whole copy, verify it, then roll back
  -h, --help     this

Stop bastion.service first. Rows written to SQLite after the copy begins are
not carried across, and the most visible loss is sessions created mid-migration.

The source is opened read-only. The target must be empty, and everything
happens in one transaction, so a failed run leaves it untouched and a retry is
just a retry.";

#[tokio::main]
async fn main() -> ExitCode {
    let mut from: Option<String> = None;
    let mut to: Option<String> = None;
    let mut plan = Plan::default();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--from" => from = args.next(),
            "--to" => to = args.next(),
            "--dry-run" => plan.dry_run = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument `{other}`\n\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }

    let (Some(from), Some(to)) = (from, to) else {
        eprintln!("--from and --to are both required\n\n{USAGE}");
        return ExitCode::FAILURE;
    };

    // Printed before anything is touched, so the operator can stop here if the
    // numbers are not the ones they expected.
    match migrate::survey(&from).await {
        Ok(found) => println!("source holds {found}"),
        Err(error) => {
            eprintln!("error: {error:#}");
            return ExitCode::FAILURE;
        }
    }

    match migrate::sqlite_to_postgres(&from, &to, plan).await {
        Ok(moved) if plan.dry_run => {
            println!(
                "dry run: would have copied {moved} ({} rows)",
                moved.total()
            );
            println!("nothing was written — rerun without --dry-run to commit");
            ExitCode::SUCCESS
        }
        Ok(moved) => {
            println!("copied {moved} ({} rows)", moved.total());
            println!("point APP_DATABASE_URL at the PostgreSQL url and restart");
            ExitCode::SUCCESS
        }
        Err(error) => {
            // `{:#}` prints the whole anyhow chain: the top line says what
            // failed, the rest says which table and which driver error.
            eprintln!("error: {error:#}");
            eprintln!("nothing was committed to the target");
            ExitCode::FAILURE
        }
    }
}
