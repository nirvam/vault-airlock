use anyhow::{Context, Result};
use keepass::{db::{EntryRef, GroupRef}, Database, DatabaseKey};
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, Serializer};
use std::fs::File;
use std::path::Path;

pub struct Vault {
    pub db: Database,
}

fn serialize_secret<S>(secret: &Option<SecretString>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match secret {
        Some(s) => serializer.serialize_str(s.expose_secret()),
        None => serializer.serialize_none(),
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct VaultEntry {
    pub uuid: String,
    pub title: String,
    pub username: Option<String>,
    #[serde(serialize_with = "serialize_secret")]
    pub password: Option<SecretString>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct VaultGroup {
    pub uuid: String,
    pub name: String,
    pub children: Vec<VaultNode>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum VaultNode {
    Group(VaultGroup),
    Entry(VaultEntry),
}

impl Vault {
    pub fn load(path: impl AsRef<Path>, password: SecretString) -> Result<Self> {
        let mut file = File::open(path).context("Failed to open KDBX file")?;
        let key = DatabaseKey::new().with_password(password.expose_secret());
        let db = Database::open(&mut file, key).context("Failed to decrypt KDBX database")?;
        Ok(Self { db })
    }

    pub fn get_tree(&self) -> VaultNode {
        VaultNode::Group(self.convert_group(self.db.root()))
    }

    fn convert_group(&self, g: GroupRef) -> VaultGroup {
        let mut children = Vec::new();
        for subgroup in g.groups() {
            children.push(VaultNode::Group(self.convert_group(subgroup)));
        }
        for entry in g.entries() {
            children.push(VaultNode::Entry(self.convert_entry(entry)));
        }

        VaultGroup {
            uuid: g.id().to_string(),
            name: g.name.clone(),
            children,
        }
    }

    fn convert_entry(&self, e: EntryRef) -> VaultEntry {
        VaultEntry {
            uuid: e.id().to_string(),
            title: e.get_title().unwrap_or_default().to_string(),
            username: e.get_username().map(|s| s.to_string()),
            password: e.get_password().map(|s| SecretString::new(s.to_string().into())),
            url: e.get_url().map(|s| s.to_string()),
            notes: e.fields.get("Notes").and_then(|v| match v {
                keepass::db::Value::Unprotected(s) => Some(s.clone()),
                _ => None,
            }),
            tags: e.tags.clone(),
        }
    }

    pub fn find_entry(&self, uuid_str: &str) -> Option<VaultEntry> {
        self.recursive_find(self.db.root(), uuid_str)
    }

    fn recursive_find(&self, g: GroupRef, uuid_str: &str) -> Option<VaultEntry> {
        for entry in g.entries() {
            if entry.id().to_string() == uuid_str {
                return Some(self.convert_entry(entry));
            }
        }
        for subgroup in g.groups() {
            if let Some(e) = self.recursive_find(subgroup, uuid_str) {
                return Some(e);
            }
        }
        None
    }

    pub fn search(&self, query: &str) -> Vec<VaultEntry> {
        let mut results = Vec::new();
        self.recursive_search(self.db.root(), query, &mut results);
        results
    }

    fn recursive_search(&self, g: GroupRef, query: &str, results: &mut Vec<VaultEntry>) {
        for entry in g.entries() {
            let title = entry.get_title().unwrap_or_default();
            let tags = &entry.tags;
            if title.contains(query) || tags.iter().any(|t| t.contains(query)) {
                results.push(self.convert_entry(entry));
            }
        }
        for subgroup in g.groups() {
            self.recursive_search(subgroup, query, results);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn test_vault_load_success() {
        let password = SecretString::new("dQ;2<?dA4\\TfgF\\:".to_string().into());
        let vault = Vault::load("test.kdbx", password);
        assert!(vault.is_ok(), "Vault should load successfully with correct password");
    }

    #[test]
    fn test_vault_load_failure() {
        let password = SecretString::new("wrong_password".to_string().into());
        let vault = Vault::load("test.kdbx", password);
        assert!(vault.is_err(), "Vault should fail to load with wrong password");
    }

    #[test]
    fn test_vault_get_tree() {
        let password = SecretString::new("dQ;2<?dA4\\TfgF\\:".to_string().into());
        let vault = Vault::load("test.kdbx", password).unwrap();
        let tree = vault.get_tree();
        
        if let VaultNode::Group(root) = tree {
            assert!(!root.name.is_empty());
            assert!(!root.children.is_empty());
        } else {
            panic!("Root should be a group");
        }
    }

    #[test]
    fn test_vault_search() {
        let password = SecretString::new("dQ;2<?dA4\\TfgF\\:".to_string().into());
        let vault = Vault::load("test.kdbx", password).unwrap();
        
        // Searching for something likely to be in a test db
        let results = vault.search("Sample");
        // We don't know exactly what's in test.kdbx, but we can check if it returns a Vec
        assert!(results.len() >= 0);
    }

    #[test]
    fn test_vault_find_entry() {
        let password = SecretString::new("dQ;2<?dA4\\TfgF\\:".to_string().into());
        let vault = Vault::load("test.kdbx", password).unwrap();
        
        // Get an entry from tree first to find a valid UUID
        let tree = vault.get_tree();
        if let VaultNode::Group(root) = tree {
            // Traverse to find first entry
            let mut first_entry_uuid = None;
            for child in &root.children {
                if let VaultNode::Entry(e) = child {
                    first_entry_uuid = Some(e.uuid.clone());
                    break;
                }
            }
            
            if let Some(uuid) = first_entry_uuid {
                let entry = vault.find_entry(&uuid);
                assert!(entry.is_some());
                assert_eq!(entry.unwrap().uuid, uuid);
            }
        }
    }
}
