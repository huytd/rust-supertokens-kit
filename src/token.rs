use std::{collections::HashMap, time::{Instant, Duration}, sync::Arc};
use tokio::sync::Mutex;

pub fn generate_token(length: usize) -> String {
    use rand::distributions::DistString;
    rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), length)
}

#[derive(Clone)]
pub struct TokenStore {
    store: HashMap<String, Instant>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    pub fn create_token(&mut self, token: &str, ttl: Duration) -> Result<(), bool> {
        if let Some(expired_at) = Instant::now().checked_add(ttl) {
            self.store.insert(token.to_owned(), expired_at);
            return Ok(());
        } else {
            return Err(false);
        }
    }

    pub fn validate_token(&mut self, token: &str) -> bool {
        if !self.store.contains_key(token) {
            return false;
        }
        let expired_at = self.store.get(token).unwrap();
        let is_expired = Instant::now() < *expired_at;
        if is_expired {
            self.store.remove(token);
        }
        return is_expired;
    }
}

pub type SharedTokenStore = Arc<Mutex<TokenStore>>;

pub fn create_token_store() -> SharedTokenStore {
    Arc::new(Mutex::new(TokenStore::new()))
}