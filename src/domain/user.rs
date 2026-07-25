use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Admin => "admin",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Role::User),
            "admin" => Ok(Role::Admin),
            _ => Err(()),
        }
    }
}

/// A registered account.
///
/// `password_hash` never leaves this struct: there is no `Serialize` impl, and
/// the `Debug` impl below redacts it so it cannot reach a log line by accident.
#[derive(Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    #[sqlx(try_from = "String")]
    pub role: Role,
    pub failed_attempts: i64,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Present for schema fidelity; not read by the application today.
    #[allow(dead_code)]
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<String> for Role {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse().map_err(|_| format!("unknown role `{value}`"))
    }
}

impl User {
    /// Whether a lockout from repeated failed logins is still in effect.
    pub fn is_locked_at(&self, now: DateTime<Utc>) -> bool {
        self.locked_until.is_some_and(|until| until > now)
    }
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("password_hash", &"<redacted>")
            .field("role", &self.role)
            .field("failed_attempts", &self.failed_attempts)
            .field("locked_until", &self.locked_until)
            .finish_non_exhaustive()
    }
}
