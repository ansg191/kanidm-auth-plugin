use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct AuthRequest {
    pub step: AuthStep,
}

#[derive(Debug, Serialize)]
pub struct SingleStringRequest {
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    // pub sessionid: Uuid,
    pub state: AuthState,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AuthAllowed {
    Anonymous,
    BackupCode,
    Password,
    Totp,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthCredential {
    Anonymous,
    Password(String),
    Totp(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AuthMech {
    Anonymous,
    Password,
    PasswordBackupCode,
    // Now represents TOTP.
    #[serde(rename = "passwordmfa")]
    PasswordTotp,
    PasswordSecurityKey,
    Passkey,
}

#[derive(Debug, Serialize, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AuthIssueSession {
    /// Issue a bearer token for this client. This is the default.
    Token,
    // /// Issue a cookie for this client.
    // Cookie,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthState {
    /// You need to select how you want to proceed.
    Choose(Vec<AuthMech>),
    /// Continue to auth, allowed mechanisms/challenges listed.
    Continue(Vec<AuthAllowed>),
    /// Something was bad, your session is terminated and no cookie.
    Denied(String),
    /// Everything is good, your bearer token has been issued and is within.
    Success(String),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthStep {
    /// Initialise a new authentication session
    // Init(String),
    /// Initialise a new authentication session with extra flags
    /// for requesting different types of session tokens or
    /// immediate access to privileges.
    Init2 {
        username: String,
        issue: AuthIssueSession,
        #[serde(default)]
        /// If true, the session will have r/w access.
        privileged: bool,
    },
    /// Request the named authentication mechanism to proceed
    Begin(AuthMech),
    /// Provide a credential in response to a challenge
    Cred(AuthCredential),
}

#[derive(Debug, Deserialize, Clone)]
pub struct UnixUserToken {
    // pub name: String,
    // pub spn: String,
    // pub displayname: String,
    // pub gidnumber: u32,
    // pub uuid: Uuid,
    // pub shell: Option<String>,
    // pub groups: Vec<UnixGroupToken>,
    // pub sshkeys: Vec<SshPublicKey>,
    // The default value of bool is false.
    #[serde(default)]
    pub valid: bool,
}
