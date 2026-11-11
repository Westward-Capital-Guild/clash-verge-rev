use anyhow::{Result, ensure};
use sysproxy::{Autoproxy, Sysproxy};
use system_configuration::{
    core_foundation::{
        base::{CFType, TCFType as _},
        data::CFData,
        dictionary::CFDictionary,
        number::CFNumber,
        propertylist,
        string::CFString,
    },
    network_configuration::SCNetworkService,
    preferences::SCPreferences,
    sys::{
        network_configuration::{
            SCNetworkProtocolGetConfiguration, SCNetworkProtocolSetConfiguration, SCNetworkServiceCopy,
            SCNetworkServiceCopyProtocol,
        },
        preferences::{SCPreferencesApplyChanges, SCPreferencesCommitChanges, SCPreferencesLock, SCPreferencesUnlock},
    },
};

#[derive(Clone, Default)]
pub(super) struct ProxyLease {
    original: Vec<(String, Vec<u8>)>,
    applied: Vec<(String, Vec<u8>)>,
}

fn protocol(preferences: &SCPreferences, id: &str) -> Result<(CFType, CFDictionary)> {
    unsafe {
        let service = SCNetworkServiceCopy(
            preferences.as_concrete_TypeRef(),
            CFString::new(id).as_concrete_TypeRef(),
        );
        ensure!(!service.is_null(), "SYSPROXY_SNAPSHOT_FAILED");
        let _service = CFType::wrap_under_create_rule(service.cast());
        let protocol = SCNetworkServiceCopyProtocol(service, CFString::new("Proxies").as_concrete_TypeRef());
        ensure!(!protocol.is_null(), "SYSPROXY_SNAPSHOT_FAILED");
        let owner = CFType::wrap_under_create_rule(protocol.cast());
        let value = SCNetworkProtocolGetConfiguration(protocol);
        ensure!(!value.is_null(), "SYSPROXY_SNAPSHOT_FAILED");
        Ok((owner, CFDictionary::wrap_under_get_rule(value)))
    }
}

fn decode(bytes: &[u8]) -> Result<CFDictionary> {
    let (raw, _) = propertylist::create_with_data(CFData::from_buffer(bytes), propertylist::kCFPropertyListImmutable)
        .map_err(|_| anyhow::anyhow!("SYSPROXY_SNAPSHOT_FAILED"))?;
    unsafe { CFType::wrap_under_create_rule(raw) }
        .downcast_into::<CFDictionary>()
        .ok_or_else(|| anyhow::anyhow!("SYSPROXY_SNAPSHOT_FAILED"))
}

fn encode(value: &CFDictionary) -> Result<Vec<u8>> {
    Ok(
        propertylist::create_data(value.as_CFTypeRef(), propertylist::kCFPropertyListBinaryFormat_v1_0)
            .map_err(|_| anyhow::anyhow!("SYSPROXY_SNAPSHOT_FAILED"))?
            .bytes()
            .to_vec(),
    )
}

fn field(value: &CFDictionary, key: &str) -> Option<CFType> {
    let key = CFString::new(key);
    value
        .find(key.as_CFTypeRef())
        .map(|raw| unsafe { CFType::wrap_under_get_rule(*raw) })
}

fn number(value: &CFDictionary, key: &str) -> i64 {
    field(value, key)
        .and_then(|v| v.downcast_into::<CFNumber>())
        .and_then(|v| v.to_i64())
        .unwrap_or(0)
}

fn string(value: &CFDictionary, key: &str) -> Option<String> {
    field(value, key)
        .and_then(|v| v.downcast_into::<CFString>())
        .map(|v| v.to_string())
}

fn matches_target(value: &CFDictionary, sys: &Sysproxy, auto: &Autoproxy) -> bool {
    if auto.enable {
        number(value, "ProxyAutoConfigEnable") == 1
            && string(value, "ProxyAutoConfigURLString").as_deref() == Some(&auto.url)
            && ["HTTPEnable", "HTTPSEnable", "SOCKSEnable"]
                .iter()
                .all(|key| number(value, key) == 0)
    } else if sys.enable {
        number(value, "ProxyAutoConfigEnable") == 0
            && ["HTTP", "HTTPS", "SOCKS"].iter().all(|prefix| {
                number(value, &format!("{prefix}Enable")) == 1
                    && number(value, &format!("{prefix}Port")) == i64::from(sys.port)
                    && string(value, &format!("{prefix}Proxy")).as_deref() == Some(&sys.host)
            })
    } else {
        false
    }
}

impl ProxyLease {
    pub(super) fn capture() -> Result<Self> {
        let preferences = SCPreferences::default(&CFString::new("Pilgrim Workspace"));
        let mut original = Vec::new();
        for service in SCNetworkService::get_services(&preferences).iter() {
            if let Some(id) = service.id() {
                let id = id.to_string();
                if let Ok((_, dictionary)) = protocol(&preferences, &id) {
                    original.push((id, encode(&dictionary)?));
                }
            }
        }
        ensure!(!original.is_empty(), "SYSPROXY_SNAPSHOT_FAILED");
        Ok(Self {
            original,
            applied: Vec::new(),
        })
    }

    pub(super) fn record_applied(&mut self, sys: &Sysproxy, auto: &Autoproxy) -> Result<()> {
        let preferences = SCPreferences::default(&CFString::new("Pilgrim Workspace"));
        for (id, before) in &self.original {
            if let Ok((_, current)) = protocol(&preferences, id)
                && matches_target(&current, sys, auto)
                && current.as_CFType() != decode(before)?.as_CFType()
            {
                let bytes = encode(&current)?;
                if let Some(entry) = self.applied.iter_mut().find(|entry| entry.0 == *id) {
                    entry.1 = bytes;
                } else {
                    self.applied.push((id.clone(), bytes));
                }
            }
        }
        Ok(())
    }

    pub(super) fn restore(&self) -> Result<()> {
        if self.applied.is_empty() {
            return Ok(());
        }
        let preferences = SCPreferences::default(&CFString::new("Pilgrim Workspace"));
        unsafe {
            ensure!(
                SCPreferencesLock(preferences.as_concrete_TypeRef(), 0) != 0,
                "SYSPROXY_RESTORE_FAILED"
            );
        }
        scopeguard::defer! { unsafe { SCPreferencesUnlock(preferences.as_concrete_TypeRef()); } }
        let mut changed = false;
        for (id, applied) in &self.applied {
            let (owner, current) = protocol(&preferences, id)?;
            // Preserve changes made by another client, including a different network service.
            if current.as_CFType() != decode(applied)?.as_CFType() {
                continue;
            }
            let original = self
                .original
                .iter()
                .find(|entry| entry.0 == *id)
                .ok_or_else(|| anyhow::anyhow!("SYSPROXY_RESTORE_FAILED"))?;
            let dictionary = decode(&original.1)?;
            unsafe {
                ensure!(
                    SCNetworkProtocolSetConfiguration(owner.as_CFTypeRef() as _, dictionary.as_concrete_TypeRef()) != 0,
                    "SYSPROXY_RESTORE_FAILED"
                );
            }
            changed = true;
        }
        if changed {
            unsafe {
                ensure!(
                    SCPreferencesCommitChanges(preferences.as_concrete_TypeRef()) != 0,
                    "SYSPROXY_RESTORE_FAILED"
                );
                ensure!(
                    SCPreferencesApplyChanges(preferences.as_concrete_TypeRef()) != 0,
                    "SYSPROXY_RESTORE_FAILED"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Tests assert by panicking")]
mod tests {
    use super::*;

    #[test]
    fn workspace_proxy_snapshot_roundtrip_preserves_disabled_fields_and_bypass() {
        let keys = [CFString::new("HTTPProxy"), CFString::new("ExceptionsList")];
        let values = [CFString::new("previous.invalid"), CFString::new("localhost")];
        let dictionary = CFDictionary::from_CFType_pairs(&[
            (keys[0].clone(), values[0].clone()),
            (keys[1].clone(), values[1].clone()),
        ]);
        let dictionary = unsafe { CFDictionary::wrap_under_get_rule(dictionary.as_concrete_TypeRef()) };
        let restored = decode(&encode(&dictionary).unwrap()).unwrap();
        assert_eq!(restored.as_CFType(), dictionary.as_CFType());
        let changed = CFDictionary::from_CFType_pairs(&[(keys[0].clone(), CFString::new("third-party.invalid"))]);
        assert_ne!(restored.as_CFType(), changed.as_CFType());
    }
}
