use serde::Deserialize;
use std::collections::BTreeSet;
use url::Url;

use super::{
    catalog_http::{metadata, official_destination},
    catalog_upstream::Publisher,
};

const INDEX_LIMIT: usize = 256 * 1024;
const FEDORA_LIMIT: usize = 2 * 1024 * 1024;
const ONION_LIMIT: usize = 32 * 1024;
const INVALID: &str = "The publisher feed did not identify a supported official installer.";
const FEDORA_MIRRORS: &str = "download.fedoraproject.org";
const FEDORA_ORIGIN: &str = "dl.fedoraproject.org";
const ONION_ISOS: &str = "https://download.securityonion.net/file/securityonion/";

#[derive(Default)]
pub(super) struct Plan {
    pub(super) directory: String,
    pub(super) manifest: Option<String>,
    pub(super) signature: Option<String>,
    pub(super) image: Option<String>,
    pub(super) published_sha256: Option<String>,
    pub(super) published_sha512: Option<String>,
    pub(super) asset_signature: Option<String>,
}

// Feed records locate candidates. The caller still verifies the publisher's evidence
// before accepting a candidate and checks the downloaded bytes before publication.
pub(super) fn plan(publisher: &Publisher, fallback: bool) -> Result<Plan, String> {
    let source = if fallback { &publisher.fallback } else { &publisher.current };
    match (publisher.feed.as_str(), fallback) {
        ("manifest", _) | ("ubuntu-lts" | "version-index", true) => {
            configured_manifest(publisher, source, fallback)
        }
        ("ubuntu-lts", false) => {
            let feed = feed_text(source, &publisher.metadata_hosts, INDEX_LIMIT)?;
            let release = ubuntu_lts(&feed)?;
            let directory = format!("https://releases.ubuntu.com/{release}/");
            configured_manifest(publisher, &directory, false)
        }
        ("version-index", false) => {
            let feed = feed_text(source, &publisher.metadata_hosts, INDEX_LIMIT)?;
            let release = directory_links(&feed).filter_map(|link| {
                let release = link.strip_suffix('/')?;
                Some((numbers(release)?, release))
            }).max().ok_or(INVALID)?.1;
            let directory = check_directory(source, &publisher.metadata_hosts)?.join(&format!("{release}/"))
                .map_err(|_| INVALID)?;
            configured_manifest(publisher, directory.as_str(), false)
        }
        ("rocky", _) => rocky(publisher, source, fallback),
        ("fedora", _) => fedora(publisher, source, fallback),
        ("opensuse", _) => opensuse(publisher, source, fallback),
        ("security-onion", _) => security_onion(publisher, source),
        _ => Err(INVALID.into()),
    }
}

fn checked_url(raw: &str, hosts: &[String]) -> Result<Url, String> {
    if !official_destination(raw, hosts) || raw.contains('?') || raw.contains('%') {
        return Err(INVALID.into());
    }
    Url::parse(raw).map_err(|_| INVALID.into())
}

fn check_directory(raw: &str, hosts: &[String]) -> Result<Url, String> {
    let url = checked_url(raw, hosts)?;
    if !url.path().ends_with('/') {
        return Err(INVALID.into());
    }
    Ok(url)
}

fn checked_child(directory: &Url, name: &str, hosts: &[String]) -> Result<String, String> {
    if !component(name) {
        return Err(INVALID.into());
    }
    let child = directory.join(name).map_err(|_| INVALID)?;
    Ok(checked_url(child.as_str(), hosts)?.into())
}

fn component(name: &str) -> bool {
    name.len() <= 200 && name.bytes().next().is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
}

fn matching_name<'a>(publisher: &Publisher, name: &'a str) -> Option<&'a str> {
    if !component(name) || !name.ends_with(".iso") {
        return None;
    }
    name.strip_prefix(publisher.prefix.as_str())?.strip_suffix(publisher.suffix.as_str())
}

fn feed_text(url: &str, hosts: &[String], limit: usize) -> Result<String, String> {
    checked_url(url, hosts)?;
    String::from_utf8(metadata(url, hosts, limit)?).map_err(|_| INVALID.into())
}

fn numbers(value: &str) -> Option<Vec<u32>> {
    if value.len() > 32 {
        return None;
    }
    value.split('.').map(|part| {
        if !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    }).collect()
}

fn hex(value: &str, digits: usize) -> Option<String> {
    (value.len() == digits && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn directory_links(html: &str) -> impl Iterator<Item = &str> {
    html.split('<').filter_map(|entry| {
        let attributes = entry.split_once('>')?.0.strip_prefix('a')?;
        if !attributes.starts_with(char::is_whitespace) {
            return None;
        }
        attributes.split_ascii_whitespace().find_map(|field| {
            let quoted = field.strip_prefix("href=")?;
            let quote = quoted.chars().next()?;
            if !matches!(quote, '"' | '\'') {
                return None;
            }
            quoted.strip_prefix(quote)?.strip_suffix(quote)
        })
    })
}

fn configured_manifest(publisher: &Publisher, source: &str, fallback: bool) -> Result<Plan, String> {
    let directory = check_directory(source, &publisher.media_hosts)?;
    let manifest = checked_child(&directory, &publisher.manifest, &publisher.metadata_hosts)?;
    let signature = publisher.signature.as_deref()
        .map(|name| checked_child(&directory, name, &publisher.metadata_hosts)).transpose()?;
    let image = if fallback {
        publisher.fallback_name.as_ref().map(|name| {
            matching_name(publisher, name).ok_or(INVALID)?;
            Ok::<_, &str>(name.clone())
        }).transpose()?
    } else {
        None
    };
    Ok(Plan { directory: directory.into(), manifest: Some(manifest), signature, image, ..Plan::default() })
}

fn stanza_field<'a>(stanza: &'a str, key: &str) -> Result<Option<&'a str>, String> {
    let mut fields = stanza.lines().filter_map(|line| line.strip_prefix(key).map(str::trim));
    let value = fields.next();
    if fields.next().is_some() {
        return Err(INVALID.into());
    }
    Ok(value)
}

fn ubuntu_lts(feed: &str) -> Result<String, String> {
    let feed = feed.replace("\r\n", "\n");
    let mut releases = Vec::new();
    for stanza in feed.split("\n\n") {
        if stanza_field(stanza, "Supported:")? != Some("1") {
            continue;
        }
        let Some(version) = stanza_field(stanza, "Version:")?.and_then(|value| value.strip_suffix(" LTS")) else {
            continue;
        };
        let Some(parts) = numbers(version) else { continue; };
        let series = match parts.as_slice() {
            [_, _] => version,
            [_, _, _] => version.rsplit_once('.').ok_or(INVALID)?.0,
            _ => continue,
        };
        releases.push((parts, series));
    }
    releases.into_iter().max().map(|(_, series)| series.to_owned()).ok_or_else(|| INVALID.into())
}

fn fallback_image(publisher: &Publisher, source: &str) -> Result<(Url, String), String> {
    let url = checked_url(source, &publisher.media_hosts)?;
    let (directory, name) = if url.path().ends_with('/') {
        let name = publisher.fallback_name.as_deref().ok_or(INVALID)?.to_owned();
        (url, name)
    } else {
        let name = url.path_segments().and_then(Iterator::last).ok_or(INVALID)?.to_owned();
        let directory = url.join(".").map_err(|_| INVALID)?;
        if publisher.fallback_name.as_ref().is_some_and(|expected| expected != &name) {
            return Err(INVALID.into());
        }
        (directory, name)
    };
    matching_name(publisher, &name).ok_or(INVALID)?;
    Ok((directory, name))
}

fn detached_manifest(
    publisher: &Publisher, directory: &Url, name: &str, extension: &str,
) -> Result<Plan, String> {
    Ok(Plan {
        directory: directory.as_str().to_owned(),
        manifest: Some(checked_child(directory, &format!("{name}{extension}"), &publisher.metadata_hosts)?),
        signature: Some(checked_child(directory, &format!("{name}{extension}.asc"), &publisher.metadata_hosts)?),
        image: Some(name.to_owned()),
        ..Plan::default()
    })
}

fn rocky_build(version: &str) -> Option<(Vec<u32>, Vec<u32>)> {
    let (release, build) = version.split_once('-')?;
    let release = numbers(release)?;
    let (date, _) = build.split_once('.')?;
    let build = numbers(build)?;
    (release.len() == 2 && date.len() == 8 && build.len() == 2).then_some((release, build))
}

fn rocky(publisher: &Publisher, source: &str, fallback: bool) -> Result<Plan, String> {
    let (directory, name) = if fallback {
        fallback_image(publisher, source)?
    } else {
        let directory = check_directory(source, &publisher.media_hosts)?;
        let feed = feed_text(source, &publisher.metadata_hosts, INDEX_LIMIT)?;
        let names: BTreeSet<_> = directory_links(&feed).collect();
        let name = names.iter().copied().filter_map(|name| {
            let version = rocky_build(matching_name(publisher, name)?)?;
            let checksum = format!("{name}.CHECKSUM");
            let signature = format!("{checksum}.asc");
            (names.contains(checksum.as_str()) && names.contains(signature.as_str())).then_some((version, name))
        }).max().ok_or(INVALID)?.1.to_owned();
        (directory, name)
    };
    detached_manifest(publisher, &directory, &name, ".CHECKSUM")
}

#[derive(Deserialize)]
struct FedoraRelease {
    version: String,
    arch: String,
    link: String,
    variant: String,
    subvariant: String,
    sha256: String,
}

fn fedora_build(publisher: &Publisher, name: &str) -> Option<(u32, Vec<u32>)> {
    let (release, build) = matching_name(publisher, name)?.split_once('-')?;
    let major = release.parse::<u32>().ok()?;
    Some((major, numbers(build)?))
}

fn fedora_candidates(publisher: &Publisher, feed: &str) -> Result<(Url, String, String), String> {
    let entries: Vec<FedoraRelease> = serde_json::from_str(feed).map_err(|_| INVALID)?;
    let declared_hosts = [FEDORA_MIRRORS.to_owned(), FEDORA_ORIGIN.to_owned()];
    let best = entries.iter().filter_map(|entry| {
        if entry.arch != "x86_64" || entry.variant != "Workstation" || entry.subvariant != "Workstation" {
            return None;
        }
        let mut url = checked_url(&entry.link, &declared_hosts).ok()?;
        let leading = format!("/pub/fedora/linux/releases/{}/Workstation/x86_64/iso/", entry.version);
        let name = url.path().strip_prefix(leading.as_str())?.to_owned();
        let (major, build) = fedora_build(publisher, &name)?;
        if entry.version != major.to_string() {
            return None;
        }
        let digest = hex(&entry.sha256, 64)?;
        url.set_host(Some(FEDORA_ORIGIN)).ok()?;
        let directory = url.join(".").ok()?;
        official_destination(url.as_str(), &publisher.media_hosts)
            .then_some(((major, build), directory, name, digest))
    }).max_by(|left, right| left.0.cmp(&right.0).then_with(|| left.2.cmp(&right.2)))
        .ok_or(INVALID)?;
    Ok((best.1, best.2, best.3))
}

fn fedora(publisher: &Publisher, source: &str, fallback: bool) -> Result<Plan, String> {
    let (directory, name, published_sha256) = if fallback {
        let (directory, name) = fallback_image(publisher, source)?;
        (directory, name, None)
    } else {
        let feed = feed_text(source, &publisher.metadata_hosts, FEDORA_LIMIT)?;
        let (directory, name, digest) = fedora_candidates(publisher, &feed)?;
        (directory, name, Some(digest))
    };
    fedora_build(publisher, &name).ok_or(INVALID)?;
    let version = matching_name(publisher, &name).ok_or(INVALID)?;
    let manifest = format!("Fedora-Workstation-{version}-x86_64-CHECKSUM");
    Ok(Plan {
        directory: directory.as_str().to_owned(),
        manifest: Some(checked_child(&directory, &manifest, &publisher.metadata_hosts)?),
        image: Some(name),
        published_sha256,
        ..Plan::default()
    })
}

fn metalink_name_matches(expected: &str, actual: &str) -> bool {
    if expected == actual {
        return true;
    }
    let Some(stem) = expected.strip_suffix(".install.iso") else { return false; };
    let Some(build) = actual.strip_prefix(stem)
        .and_then(|rest| rest.strip_prefix("-Build"))
        .and_then(|rest| rest.strip_suffix(".install.iso"))
    else { return false; };
    numbers(build).is_some()
}

fn metalink_hash(xml: &str, algorithm: &str, digits: usize) -> Result<String, String> {
    let marker = format!("<hash type=\"{algorithm}\">");
    let mut matches = xml.match_indices(marker.as_str());
    let (offset, marker) = matches.next().ok_or(INVALID)?;
    if matches.next().is_some() {
        return Err(INVALID.into());
    }
    let digest = xml[offset + marker.len()..].split_once("</hash>").ok_or(INVALID)?.0.trim();
    hex(digest, digits).ok_or_else(|| INVALID.into())
}

fn metalink_hashes(xml: &str, expected: &str) -> Result<(String, String), String> {
    let mut files = xml.split("<file ");
    files.next();
    let file = files.next().ok_or(INVALID)?;
    if files.next().is_some() {
        return Err(INVALID.into());
    }
    let (attributes, contents) = file.split_once('>').ok_or(INVALID)?;
    let (contents, _) = contents.split_once("</file>").ok_or(INVALID)?;
    let actual = attributes.split_ascii_whitespace().find_map(|attribute| {
        attribute.strip_prefix("name=\"")?.strip_suffix('"')
    }).ok_or(INVALID)?;
    if !metalink_name_matches(expected, actual) {
        return Err(INVALID.into());
    }
    Ok((metalink_hash(contents, "sha-256", 64)?, metalink_hash(contents, "sha-512", 128)?))
}

fn opensuse(publisher: &Publisher, source: &str, fallback: bool) -> Result<Plan, String> {
    let (directory, name) = if fallback && publisher.fallback_name.is_some() {
        fallback_image(publisher, source)?
    } else {
        let directory = check_directory(source, &publisher.media_hosts)?;
        let feed = feed_text(source, &publisher.metadata_hosts, INDEX_LIMIT)?;
        let names: BTreeSet<_> = directory_links(&feed).collect();
        let name = names.iter().copied().filter_map(|name| {
            let version = numbers(matching_name(publisher, name)?)?;
            let checksum = format!("{name}.sha512");
            let signature = format!("{checksum}.asc");
            (names.contains(checksum.as_str()) && names.contains(signature.as_str())).then_some((version, name))
        }).max().ok_or(INVALID)?.1.to_owned();
        (directory, name)
    };
    let mut result = detached_manifest(publisher, &directory, &name, ".sha512")?;
    let mut metalink = directory;
    let path = metalink.path().strip_prefix("/pub/opensuse/").ok_or(INVALID)?;
    let path = format!("/{path}{name}.meta4");
    metalink.set_path(&path);
    checked_url(metalink.as_str(), &publisher.metadata_hosts)?;
    let host = metalink.host_str().ok_or(INVALID)?.to_owned();
    let feed = feed_text(metalink.as_str(), &[host], INDEX_LIMIT)?;
    let (sha256, sha512) = metalink_hashes(&feed, &name)?;
    result.published_sha256 = Some(sha256);
    result.published_sha512 = Some(sha512);
    Ok(result)
}

fn security_onion_fields(publisher: &Publisher, markdown: &str) -> Result<(String, String), String> {
    let mut names = BTreeSet::new();
    for (offset, prefix) in markdown.match_indices(ONION_ISOS) {
        let tail = &markdown[offset + prefix.len()..];
        let end = tail.find(|ch: char| ch.is_ascii_whitespace() || "\x60<>)]".contains(ch)).unwrap_or(tail.len());
        let name = &tail[..end];
        let Some(version) = matching_name(publisher, name) else { continue; };
        let Some((release, date)) = version.split_once('-') else { continue; };
        if numbers(release).is_some_and(|parts| parts.len() == 3)
            && date.len() == 8 && date.bytes().all(|byte| byte.is_ascii_digit())
        {
            names.insert(name);
        }
    }
    let digest = stanza_field(markdown, "SHA256:")?.and_then(|field| hex(field, 64)).ok_or(INVALID)?;
    if names.len() != 1 {
        return Err(INVALID.into());
    }
    Ok((names.into_iter().next().ok_or(INVALID)?.to_owned(), digest))
}

fn security_onion(publisher: &Publisher, source: &str) -> Result<Plan, String> {
    let directory = check_directory(ONION_ISOS, &publisher.media_hosts)?;
    let doc = checked_url(source, &publisher.metadata_hosts)?;
    if doc.host_str() != Some("raw.githubusercontent.com")
        || !doc.path().starts_with("/Security-Onion-Solutions/securityonion/")
        || !doc.path().ends_with("/DOWNLOAD_AND_VERIFY_ISO.md")
    {
        return Err(INVALID.into());
    }
    let markdown = feed_text(source, &publisher.metadata_hosts, ONION_LIMIT)?;
    let (name, digest) = security_onion_fields(publisher, &markdown)?;
    let signatures = doc.join("sigs/").map_err(|_| INVALID)?;
    let signature = checked_child(&signatures, &format!("{name}.sig"), &publisher.metadata_hosts)?;
    Ok(Plan {
        directory: directory.as_str().to_owned(),
        image: Some(name),
        published_sha256: Some(digest),
        asset_signature: Some(signature),
        ..Plan::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ubuntu_uses_supported_lts_series_in_numeric_order() {
        let feed = concat!(
            "Version: 9.04 LTS\r\nSupported: 1\r\n\r\n",
            "Version: 30.04 LTS\r\nSupported: 0\r\n\r\n",
            "Version: 26.10\r\nSupported: 1\r\n\r\n",
            "Version: 26.04.2 LTS\r\nSupported: 1\r\n",
        );
        assert_eq!(ubuntu_lts(feed).unwrap(), "26.04");
        assert!(ubuntu_lts("Version: 26.04 LTS\nSupported: 0\nSupported: 1").is_err());
    }

    #[test]
    fn directory_candidates_only_use_safe_relative_components() {
        let html = r#"<a href="../">Parent</a><a href="22.3/">22.3</a>
                      <a href='23/'>23</a><a href="23.1-BETA/">Beta</a>
                      <a href="https://other.example/90/">Other</a>"#;
        let versions = directory_links(html).filter_map(|link| {
            numbers(link.strip_suffix('/')?)?;
            Some(link)
        }).collect::<Vec<_>>();
        assert_eq!(versions, ["22.3/", "23/"]);
        assert!(!component("../installer.iso"));
        assert!(!component("%2e%2e"));
    }

    #[test]
    fn metalink_binds_both_hashes_to_the_selected_build() {
        let sha256 = "A".repeat(64);
        let sha512 = "b".repeat(128);
        let xml = format!(
            r#"<metalink><file name="Leap-16.1-online-x86_64-Build60.2.install.iso">
            <hash type="sha-256">{sha256}</hash><hash type="sha-512">{sha512}</hash>
            <url>https://unlisted.example/irrelevant.iso</url></file></metalink>"#,
        );
        let name = "Leap-16.1-online-x86_64.install.iso";
        assert_eq!(metalink_hashes(&xml, name).unwrap(), (sha256.to_lowercase(), sha512));
        assert!(metalink_hashes(&xml, "Leap-16.2-online-x86_64.install.iso").is_err());
    }
}
