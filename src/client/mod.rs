use std::{collections::BTreeSet, sync::Arc};

use http::StatusCode;
use serde::{de::DeserializeOwned, Serialize};
use ureq::{
    config::AutoHeaderValue,
    tls::{RootCerts, TlsConfig},
    Agent,
};

mod spec;
pub use spec::UnixUserToken;
use spec::{AuthAllowed, SingleStringRequest};

use crate::client::spec::{
    AuthCredential, AuthIssueSession, AuthMech, AuthRequest, AuthResponse, AuthState, AuthStep,
};

#[derive(Debug)]
pub struct KanidmClient {
    client: Agent,
    base_url: String,

    token: Option<String>,
    session_id: Option<String>,
}

impl KanidmClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Agent::config_builder()
                .user_agent(AutoHeaderValue::Provided(Arc::new(
                    "kanidm-auth-plugin/0.1.0".to_owned(),
                )))
                .tls_config(
                    TlsConfig::builder()
                        .root_certs(RootCerts::PlatformVerifier)
                        .build(),
                )
                .build()
                .new_agent(),
            base_url,
            token: None,
            session_id: None,
        }
    }

    fn auth_post<S, T>(&mut self, dest: &str, body: S) -> Result<T, ureq::Error>
    where
        S: Serialize,
        T: DeserializeOwned,
    {
        let full_url = format!("{}{dest}", &self.base_url);
        let mut req = self.client.post(full_url);

        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        if let Some(session_id) = &self.session_id {
            req = req.header("X-KANIDM-AUTH-SESSION-ID", session_id);
        }

        let res = req.send_json(body)?;

        match res.status() {
            StatusCode::OK => {
                if let Some(session_id) = res.headers().get("X-KANIDM-AUTH-SESSION-ID") {
                    self.session_id = Some(session_id.to_str().unwrap().to_string());
                }
                res.into_body().read_json()
            }
            unexpected => Err(ureq::Error::StatusCode(unexpected.as_u16())),
        }
    }

    fn post<S, T>(&self, dest: &str, body: S) -> Result<T, ureq::Error>
    where
        S: Serialize,
        T: DeserializeOwned,
    {
        let full_url = format!("{}{dest}", &self.base_url);
        let mut req = self.client.post(full_url);

        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let res = req.send_json(body)?;

        match res.status() {
            StatusCode::OK => res.into_body().read_json(),
            unexpected => Err(ureq::Error::StatusCode(unexpected.as_u16())),
        }
    }

    fn auth_step_init(&mut self, ident: &str) -> Result<BTreeSet<AuthMech>, Error> {
        let auth_init = AuthRequest {
            step: AuthStep::Init2 {
                username: ident.to_string(),
                issue: AuthIssueSession::Token,
                privileged: false,
            },
        };

        let r: AuthResponse = self.auth_post("/v1/auth", auth_init)?;
        match r.state {
            AuthState::Choose(mechs) => Ok(mechs.into_iter().collect()),
            _ => Err(Error::AuthenticationFailed),
        }
    }

    fn auth_step_begin(&mut self, mech: AuthMech) -> Result<Vec<AuthAllowed>, Error> {
        let auth_begin = AuthRequest {
            step: AuthStep::Begin(mech),
        };

        let r: AuthResponse = self.auth_post("/v1/auth", auth_begin)?;
        match r.state {
            AuthState::Continue(allowed) => Ok(allowed),
            _ => Err(Error::AuthenticationFailed),
        }
    }

    pub fn auth_anonymous(&mut self) -> Result<(), Error> {
        let mechs = self.auth_step_init("anonymous")?;
        if !mechs.contains(&AuthMech::Anonymous) {
            return Err(Error::AuthenticationFailed);
        }

        let _state: Vec<AuthAllowed> = self.auth_step_begin(AuthMech::Anonymous)?;

        let auth_anon = AuthRequest {
            step: AuthStep::Cred(AuthCredential::Anonymous),
        };
        let r: AuthResponse = self.auth_post("/v1/auth", auth_anon)?;
        match r.state {
            AuthState::Success(token) => {
                self.token = Some(token);
                Ok(())
            }
            _ => Err(Error::AuthenticationFailed),
        }
    }

    pub fn idm_account_unix_cred_verify(
        &self,
        id: &str,
        cred: impl Into<String>,
    ) -> Result<Option<UnixUserToken>, Error> {
        let req = SingleStringRequest { value: cred.into() };
        Ok(self.post(&format!("/v1/account/{}/_unix/_auth", id), req)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ureq error: {0}")]
    UReq(#[from] ureq::Error),
    #[error("authentication failed")]
    AuthenticationFailed,
}
