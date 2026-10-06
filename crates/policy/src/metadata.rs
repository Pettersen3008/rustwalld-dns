//! Descriptive binding annotations. Never consulted for DNS admission or selection.
use crate::{Binding, PolicyError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub(crate) fn validate(bindings: &[Binding]) -> Result<(), PolicyError> {
    let mut bytes = 0usize;
    for binding in bindings {
        let Some(metadata) = &binding.metadata else {
            continue;
        };
        let label_valid = |value: &Option<String>, max: usize| {
            value.as_ref().is_none_or(|value| {
                !value.is_empty()
                    && value.len() <= max
                    && value.trim() == value
                    && !value.chars().any(char::is_control)
            })
        };
        let mut tags = HashSet::new();
        if *metadata == BindingMetadata::default()
            || !label_valid(&metadata.group, 128)
            || !label_valid(&metadata.owner, 128)
            || !label_valid(&metadata.note, 1024)
            || metadata
                .vlan
                .is_some_and(|vlan| !(1..=4094).contains(&vlan))
            || metadata.tags.len() > 16
            || metadata.tags.iter().any(|tag| {
                tag.is_empty()
                    || tag.len() > 32
                    || !tag.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_')
                    })
                    || !tags.insert(tag.as_str())
            })
        {
            return Err(PolicyError::Invalid(format!(
                "invalid metadata for binding {}",
                binding.name
            )));
        }
        bytes = bytes.saturating_add(
            [&metadata.group, &metadata.owner, &metadata.note]
                .iter()
                .filter_map(|value| value.as_ref())
                .map(|value| value.len())
                .sum::<usize>()
                + metadata.tags.iter().map(String::len).sum::<usize>(),
        );
        if bytes > MAX_METADATA_BYTES {
            return Err(PolicyError::Invalid(
                "combined binding metadata exceeds 8 MiB".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{Assertion, PolicyConfigSet, PolicySnapshot};
    use filtering::Action;

    fn binding(network: &str, group: &str) -> Binding {
        Binding {
            network: network.parse().unwrap(),
            policy: "default".into(),
            name: group.into(),
            metadata: Some(BindingMetadata {
                group: Some(group.into()),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn selected_annotations_are_specific_canonical_and_never_grant_admission() {
        let mut config = PolicyConfigSet {
            bindings: vec![
                binding("127.5.1.9/8", "Network"),
                binding("127.0.0.1/32", "Device"),
                binding("2001:db8:1::9/32", "IPv6"),
            ],
            assertions: vec![Assertion {
                client: "127.0.0.1".parse().unwrap(),
                domain: "safe.test".into(),
                expected: Action::Allow,
            }],
            ..Default::default()
        };
        let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
        for (ip, group) in [
            ("127.0.0.1", "Device"),
            ("::ffff:127.0.0.1", "Device"),
            ("127.2.3.4", "Network"),
            ("2001:db8:7::1", "IPv6"),
        ] {
            let ip = ip.parse().unwrap();
            let explanation = snapshot.explain(ip, "safe.test").unwrap();
            assert_eq!(
                explanation.binding_metadata.unwrap().group.as_deref(),
                Some(group)
            );
            assert_eq!(snapshot.select(ip).policy.id, 0);
        }
        assert!(!snapshot.permits("127.2.3.4".parse().unwrap()));
        assert!(!snapshot.permits("2001:db8::1".parse().unwrap()));
        assert!(
            snapshot
                .explain("192.0.2.1".parse().unwrap(), "safe.test")
                .unwrap()
                .binding_metadata
                .is_none()
        );
        let report = PolicySnapshot::check(config.clone()).unwrap();
        assert_eq!(
            report.results[0]
                .trace
                .as_ref()
                .unwrap()
                .binding_metadata
                .as_ref()
                .unwrap()
                .group
                .as_deref(),
            Some("Device")
        );
        config.bindings[1].metadata = None;
        let next = PolicySnapshot::compile(config, 2).unwrap();
        assert!(
            next.explain("127.0.0.1".parse().unwrap(), "safe.test")
                .unwrap()
                .binding_metadata
                .is_none()
        );
        // An older immutable generation retains its own labels.
        assert_eq!(
            snapshot
                .explain("127.0.0.1".parse().unwrap(), "safe.test")
                .unwrap()
                .binding_metadata
                .unwrap()
                .group
                .as_deref(),
            Some("Device")
        );
    }

    #[test]
    fn annotations_reject_invalid_values_and_bound_combined_text() {
        let valid = BindingMetadata {
            group: Some("Work – 内部".into()),
            owner: Some("Pettersen".into()),
            vlan: Some(4094),
            tags: vec!["work".into(), "managed_1".into()],
            note: Some("Fixed DHCP reservation".into()),
        };
        let mut input = binding("192.0.2.0/24", "network");
        input.metadata = Some(valid.clone());
        assert!(validate(std::slice::from_ref(&input)).is_ok());
        let mut invalid = vec![BindingMetadata::default()];
        for value in ["", " padded", "trailing ", "line\nbreak", "\u{0000}"] {
            invalid.push(BindingMetadata {
                group: Some(value.into()),
                ..valid.clone()
            });
            invalid.push(BindingMetadata {
                owner: Some(value.into()),
                ..valid.clone()
            });
            invalid.push(BindingMetadata {
                note: Some(value.into()),
                ..valid.clone()
            });
        }
        invalid.extend([
            BindingMetadata {
                group: Some("é".repeat(65)),
                ..valid.clone()
            },
            BindingMetadata {
                owner: Some("o".repeat(129)),
                ..valid.clone()
            },
            BindingMetadata {
                note: Some("n".repeat(1025)),
                ..valid.clone()
            },
            BindingMetadata {
                vlan: Some(0),
                ..valid.clone()
            },
            BindingMetadata {
                vlan: Some(4095),
                ..valid.clone()
            },
        ]);
        for tags in [
            vec!["".into()],
            vec!["WORK".into()],
            vec!["with space".into()],
            vec!["日本語".into()],
            vec!["a".repeat(33)],
            vec!["a".into(); 2],
            (0..17).map(|i| format!("tag{i}")).collect(),
        ] {
            invalid.push(BindingMetadata {
                tags,
                ..valid.clone()
            });
        }
        for metadata in invalid {
            input.metadata = Some(metadata);
            assert!(
                validate(std::slice::from_ref(&input)).is_err(),
                "{:?}",
                input.metadata
            );
        }
        input.metadata = Some(BindingMetadata {
            note: Some("n".repeat(1024)),
            ..Default::default()
        });
        assert!(validate(&vec![input.clone(); 8192]).is_ok());
        assert!(validate(&vec![input; 8193]).is_err());
    }
}
