use super::{
    catalog::{Entry, lower_hex},
    catalog_feeds,
    catalog_http::{media_size, metadata, official_destination},
    catalog_signature::{require_verifier, verified_publisher_manifest, verify_publisher_asset},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    thread::JoinHandle,
};
use svm_qemu::LocalFolder;

const MAX_KEY: usize = 256 * 1024;
const MAX_MANIFEST: usize = 64 * 1024;
const MAX_SIGNATURE: usize = 16 * 1024;
const MAX_RECORD: u64 = 4 * 1024 * 1024;
const MAX_RELEASES: usize = 128;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Publisher {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) edition: String,
    pub(super) collection: String,
    pub(super) reference_id: String,
    pub(super) feed: String,
    pub(super) current: String,
    pub(super) fallback: String,
    pub(super) fallback_name: Option<String>,
    pub(super) manifest: String,
    pub(super) signature: Option<String>,
    pub(super) prefix: String,
    pub(super) suffix: String,
    pub(super) media_hosts: Vec<String>,
    pub(super) metadata_hosts: Vec<String>,
    key_url: String,
    fallback_key_url: Option<String>,
    fingerprint: String,
    #[serde(default)]
    asset_signature: bool,
    #[serde(default)]
    sha512: bool,
    pub(super) vcpu: u16,
    pub(super) ram_gb: u32,
    pub(super) disk_gb: u32,
}

impl Publisher {
    pub(super) fn signs_version_name(&self) -> bool { !self.asset_signature }

    pub(super) fn version<'a>(&self, name: &'a str) -> Option<&'a str> {
        if !svm_core::library::ordinary_file_name(name) || !name.ends_with(".iso")
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return None;
        }
        let version = name.strip_prefix(&self.prefix)?.strip_suffix(&self.suffix)?;
        (version.bytes().next().is_some_and(|byte| byte.is_ascii_digit())
            && version.bytes().all(|byte| byte.is_ascii_digit() || b".-".contains(&byte)))
            .then_some(version)
    }

    fn valid(&self) -> bool {
        self.id.len() <= 40 && !self.id.is_empty()
            && self.id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && matches!(self.collection.as_str(), "Open source" | "Security")
            && !self.prefix.is_empty() && self.suffix.ends_with(".iso")
            && self.vcpu > 0 && self.ram_gb > 0 && self.disk_gb > 0
            && self.fingerprint.len() == 40 && self.fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            && !self.media_hosts.is_empty() && exact_official(&self.key_url)
            && self.fallback_key_url.as_deref().is_none_or(exact_official)
            && official_destination(&self.current, &self.metadata_hosts)
            && official_destination(&self.fallback, &self.metadata_hosts)
            && self.fallback_name.as_deref().is_none_or(|name| self.version(name).is_some())
    }
}

fn exact_official(url: &str) -> bool {
    let host = url::Url::parse(url).ok().and_then(|parsed| parsed.domain().map(str::to_owned));
    host.is_some_and(|host| official_destination(url, &[host]))
}

pub(super) fn publishers() -> Result<&'static [Publisher], String> {
    static SOURCES: LazyLock<Option<Vec<Publisher>>> = LazyLock::new(|| {
        let sources: Vec<Publisher> = serde_json::from_str(include_str!("../catalog/publishers.json")).ok()?;
        let mut ids = BTreeSet::new();
        sources.iter().all(|publisher| publisher.valid() && ids.insert(publisher.id.as_str())).then_some(sources)
    });
    SOURCES.as_deref().ok_or_else(|| "The bundled publisher sources are invalid.".to_owned())
}

pub(super) fn publisher(id: &str) -> Option<&'static Publisher> {
    publishers().ok()?.iter().find(|publisher| publisher.id == id)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Release {
    publisher_id: String,
    pub(super) file_name: String,
    pub(super) url: String,
    pub(super) bytes: u64,
    pub(super) sha256: String,
    sha512: Option<String>,
    keyring: Vec<u8>,
    manifest: Vec<u8>,
    signature: Option<Vec<u8>>,
    fallback: bool,
    #[serde(default)]
    resolved_ns: u64,
}

impl Release {
    pub(super) fn id(&self) -> String {
        let pin = format!("{:x}", Sha256::digest(format!("{}\n{}", self.file_name, self.sha256)));
        format!("{}-{}", self.publisher_id, &pin[..16])
    }

    fn valid(&self, publisher: &Publisher) -> bool {
        self.publisher_id == publisher.id && publisher.version(&self.file_name).is_some()
            && (1..=128 * 1024 * 1024 * 1024).contains(&self.bytes)
            && lower_hex(&self.sha256, 64)
            && self.sha512.as_deref().is_none_or(|digest| lower_hex(digest, 128))
            && publisher.sha512 == self.sha512.is_some()
            && !self.keyring.is_empty() && self.keyring.len() <= MAX_KEY
            && self.manifest.len() <= MAX_MANIFEST
            && self.signature.as_ref().is_none_or(|signature| !signature.is_empty() && signature.len() <= MAX_SIGNATURE)
            && (if publisher.asset_signature { self.manifest.is_empty() && self.signature.is_some() }
                else { !self.manifest.is_empty() })
            && official_destination(&self.url, &publisher.media_hosts)
            && url::Url::parse(&self.url).ok().is_some_and(|url| {
                url.path_segments().and_then(|segments| segments.last()) == Some(self.file_name.as_str())
            })
    }

    fn entry(self: &Arc<Self>) -> Option<Entry> {
        let publisher = publisher(&self.publisher_id)?;
        Entry::publisher_release(publisher, Arc::clone(self))
    }

    pub(super) fn publisher_id(&self) -> &str { &self.publisher_id }

    pub(super) fn signed_sha512(&self) -> Option<&str> { self.sha512.as_deref() }

    pub(super) fn check_manifest(&self, library: &Path) -> Result<(), String> {
        let publisher = publisher(&self.publisher_id).ok_or("Unknown publisher source.")?;
        if !self.valid(publisher) { return Err("The saved publisher evidence is invalid.".into()); }
        require_verifier()?;
        if publisher.asset_signature { return Ok(()); }
        let signed = verified_publisher_manifest(
            library, &self.keyring, &self.manifest, self.signature.as_deref(), &publisher.fingerprint,
        )?;
        let expected = self.sha512.as_deref().unwrap_or(&self.sha256);
        let actual = manifest_entry(publisher, &signed, Some(&self.file_name))?;
        if actual.1 != expected { return Err("The saved installer does not match the publisher's signed checksum.".into()); }
        Ok(())
    }

    pub(super) fn check_asset(
        &self, library: &Path, path: &Path, sha512: &str, cancelled: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        let publisher = publisher(&self.publisher_id).ok_or("Unknown publisher source.")?;
        if self.sha512.as_deref().is_some_and(|digest| digest != sha512) {
            return Err("The installer does not match the publisher's signed SHA-512.".into());
        }
        if publisher.asset_signature {
            let signature = self.signature.as_deref().ok_or("The publisher's installer signature is missing.")?;
            verify_publisher_asset(library, &self.keyring, signature, &publisher.fingerprint, path, cancelled)?;
        }
        Ok(())
    }
}

fn keyring(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    const BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    const END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) { return Ok(bytes); }
    let text = std::str::from_utf8(&bytes).map_err(|_| "The publisher's public key had an invalid format.")?;
    let mut parsed = Vec::new();
    for part in text.split(BEGIN).skip(1) {
        let (block, _) = part.split_once(END).ok_or("The publisher's public key was incomplete.")?;
        let body: String = block.lines().map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('=') && !line.contains(':'))
            .collect();
        let key = STANDARD.decode(body).map_err(|_| "The publisher's public key could not be decoded.")?;
        parsed.extend(key);
    }
    if parsed.is_empty() || parsed.len() > MAX_KEY {
        return Err("The publisher did not return a valid public keyring.".into());
    }
    Ok(parsed)
}

fn version_key(version: &str) -> Vec<u64> {
    version.split(|character: char| !character.is_ascii_digit())
        .filter_map(|part| part.parse().ok()).collect()
}

fn manifest_entry(
    publisher: &Publisher, document: &[u8], only: Option<&str>,
) -> Result<(String, String), String> {
    let text = std::str::from_utf8(document).map_err(|_| "The publisher checksum file was not UTF-8.")?;
    let size = if publisher.sha512 { 128 } else { 64 };
    let tag = if publisher.sha512 { "SHA512 (" } else { "SHA256 (" };
    let mut rows = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        let tagged = line.strip_prefix(tag).and_then(|value| value.rsplit_once(") = "));
        let gnu = line.split_once(char::is_whitespace)
            .map(|(digest, name)| (name.trim().trim_start_matches('*'), digest));
        let Some((name, digest)) = tagged.or(gnu) else { continue; };
        if publisher.version(name).is_none() || only.is_some_and(|only| only != name) { continue; }
        let digest = digest.to_ascii_lowercase();
        if digest.len() != size && matches!(digest.len(), 32 | 64 | 128) && lower_hex(&digest, digest.len()) {
            // Some publishers keep several checksum algorithms in the same signed document.
            continue;
        }
        if !lower_hex(&digest, size) || rows.insert(name, digest).is_some() {
            return Err("The publisher checksum file contains an invalid or duplicate installer record.".into());
        }
    }
    rows.into_iter().max_by_key(|(name, _)| {
        (version_key(publisher.version(name).unwrap_or_default()), *name)
    }).map(|(name, digest)| (name.to_owned(), digest))
        .ok_or_else(|| "The publisher checksum file lists no matching installer.".to_owned())
}

fn join(directory: &str, name: &str) -> Result<String, String> {
    let directory = format!("{}/", directory.trim_end_matches('/'));
    url::Url::parse(&directory).and_then(|directory| directory.join(name))
        .map(|url| url.to_string()).map_err(|_| "The publisher installer location is invalid.".into())
}

fn resolve_at(publisher: &Publisher, library: &Path, fallback: bool) -> Result<Release, String> {
    let plan = catalog_feeds::plan(publisher, fallback)?;
    let key_source = if fallback {
        publisher.fallback_key_url.as_deref().unwrap_or(&publisher.key_url)
    } else {
        &publisher.key_url
    };
    let key_host = url::Url::parse(key_source).ok().and_then(|url| url.domain().map(str::to_owned))
        .ok_or("The publisher signing-key host is invalid.")?;
    let keyring = keyring(metadata(key_source, &[key_host], MAX_KEY)?)?;
    let manifest = plan.manifest.as_deref().map(|url| metadata(url, &publisher.metadata_hosts, MAX_MANIFEST)).transpose()?;
    let mut signature = plan.signature.as_deref().map(|url| metadata(url, &publisher.metadata_hosts, MAX_SIGNATURE)).transpose()?;
    let (file_name, hash) = match manifest.as_deref() {
        Some(document) if !publisher.asset_signature => {
            let signed = verified_publisher_manifest(library, &keyring, document, signature.as_deref(), &publisher.fingerprint)?;
            manifest_entry(publisher, &signed, plan.image.as_deref())?
        }
        Some(document) => manifest_entry(publisher, document, plan.image.as_deref())?,
        None if publisher.asset_signature => (
            plan.image.clone().ok_or("The official publisher metadata has no installer name.")?,
            plan.published_sha256.clone().ok_or("The official publisher metadata has no installer SHA-256.")?,
        ),
        None => return Err("The publisher's signed checksums were unavailable.".into()),
    };
    let version = publisher.version(&file_name).ok_or("The publisher installer name was not valid.")?;
    let pinned = publisher.fallback_name.as_deref();
    if fallback && pinned.is_some_and(|name| name != file_name) {
        return Err("The publisher's pinned release did not match its expected installer name.".into());
    }
    if !fallback && pinned.and_then(|name| publisher.version(name))
        .is_some_and(|minimum| version_key(version) < version_key(minimum))
    {
        return Err("The publisher feed was older than the pinned release.".into());
    }
    let directory = if publisher.id == "arch-linux" && plan.directory.ends_with("/iso/latest/") {
        join(&plan.directory, &format!("../{version}/"))?
    } else if publisher.id == "kali-linux" && plan.directory == "https://cdimage.kali.org/current/" {
        format!("https://kali.download/base-images/kali-{version}/")
    } else {
        plan.directory
    };
    let (sha256, sha512) = if publisher.sha512 {
        if plan.published_sha512.as_deref() != Some(&hash) {
            return Err("The official file metadata did not match the signed SHA-512.".into());
        }
        (plan.published_sha256.ok_or("The publisher did not provide the installer SHA-256.")?, Some(hash))
    } else {
        if plan.published_sha256.as_deref().is_some_and(|digest| digest != hash) {
            return Err("The official file metadata did not match the installer checksum.".into());
        }
        (hash, None)
    };
    if publisher.asset_signature {
        let url = match plan.asset_signature {
            Some(url) => url,
            None => join(&directory, &format!("{file_name}.sig"))?,
        };
        signature = Some(metadata(&url, &publisher.metadata_hosts, MAX_SIGNATURE)?);
    }
    let url = join(&directory, &file_name)?;
    let bytes = media_size(&url, &publisher.media_hosts)?;
    let result = Release {
        publisher_id: publisher.id.clone(), file_name, url, bytes, sha256, sha512,
        keyring, manifest: if publisher.asset_signature { Vec::new() } else { manifest.unwrap_or_default() },
        signature, fallback,
        resolved_ns: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()
            .and_then(|time| u64::try_from(time.as_nanos()).ok()).unwrap_or_default(),
    };
    if !result.valid(publisher) { return Err("The resolved publisher installer was invalid.".into()); }
    Ok(result)
}

fn resolve(publisher: &Publisher, library: &Path) -> Result<Release, String> {
    require_verifier()?;
    match resolve_at(publisher, library, false) {
        Ok(release) => Ok(release),
        Err(current_error) => resolve_at(publisher, library, true)
            .map_err(|fallback_error| format!("{current_error} The pinned release check also failed. {fallback_error}")),
    }
}

fn cache_path(library: &Path) -> PathBuf { library.join("catalog-releases") }

fn save(library: &Path, release: &Release) -> Result<(), String> {
    let cache = cache_path(library);
    let folder = if cache.exists() {
        LocalFolder::open(&cache)
    } else {
        LocalFolder::open(library).and_then(|library| library.create_private_child("catalog-releases"))
    }.map_err(|_| "The library could not safely keep the verified publisher record.")?;
    svm_core::write_json(&folder.path.join(format!("{}.json", release.id())), release)
        .map_err(|_| "The library could not save the verified publisher record.".to_owned())
}

fn regular(path: &Path, directory: bool) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else { return false; };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 { return false; }
    }
    if directory { meta.is_dir() } else { meta.is_file() && meta.len() <= MAX_RECORD }
}

fn load_record(path: &Path) -> Option<(String, Arc<Release>)> {
    let id = path.file_stem()?.to_str()?;
    let (source, suffix) = id.rsplit_once('-')?;
    let publisher = publisher(source)?;
    if path.extension()?.to_str()? != "json" || !lower_hex(suffix, 16) || !regular(path, false) {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path).ok()?.take(MAX_RECORD + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_RECORD { return None; }
    let release: Release = serde_json::from_slice(&bytes).ok()?;
    (release.id() == id && release.valid(publisher)).then(|| (id.to_owned(), Arc::new(release)))
}

fn restore(library: &Path) -> BTreeMap<String, Arc<Release>> {
    let cache = cache_path(library);
    if !regular(&cache, true) { return BTreeMap::new(); }
    let Ok(files) = fs::read_dir(cache) else { return BTreeMap::new(); };
    files.filter_map(Result::ok).filter_map(|item| load_record(&item.path())).take(MAX_RELEASES).collect()
}

#[derive(Default)]
pub(super) struct Updates {
    saved: Option<BTreeMap<String, Arc<Release>>>,
    errors: BTreeMap<String, String>,
    active: Option<(String, JoinHandle<Result<Release, String>>)>,
}

impl Updates {
    pub(super) fn busy(&self) -> bool {
        self.active.as_ref().is_some_and(|(_, worker)| !worker.is_finished())
    }

    pub(super) fn stop(&mut self) {
        if let Some((_, worker)) = self.active.take() { let _ = worker.join(); }
    }

    pub(super) fn reap(&mut self, library: &Path) {
        if self.busy() { return; }
        let saved = self.saved.get_or_insert_with(|| restore(library));
        let Some((id, worker)) = self.active.take() else { return; };
        match worker.join().unwrap_or_else(|_| Err("The publisher check ended unexpectedly.".into())) {
            Ok(release) => {
                saved.insert(release.id(), Arc::new(release));
                self.errors.remove(&id);
            }
            Err(error) => { self.errors.insert(id, error); }
        }
    }

    pub(super) fn entries(&self) -> Vec<Entry> {
        self.saved.iter().flat_map(|saved| saved.values()).filter_map(Release::entry).collect()
    }

    pub(super) fn entry(&self, library: &Path, id: &str) -> Option<Entry> {
        if let Some(release) = self.saved.as_ref().and_then(|saved| saved.get(id)) {
            return release.entry();
        }
        if id.len() > 64 || !id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
            return None;
        }
        let cache = cache_path(library);
        if !regular(&cache, true) { return None; }
        load_record(&cache.join(format!("{id}.json"))).and_then(|(_, release)| release.entry())
    }

    pub(super) fn summary(&self, publisher: &Publisher) -> serde_json::Value {
        let latest = self.saved.iter().flat_map(|saved| saved.values())
            .filter(|release| release.publisher_id == publisher.id)
            .max_by_key(|release| (version_key(publisher.version(&release.file_name).unwrap_or_default()), release.resolved_ns));
        let error = self.errors.get(&publisher.id);
        let checking = self.active.as_ref().is_some_and(|(id, _)| id == &publisher.id);
        let state = if checking { "checking" } else if error.is_some() { "failed" }
            else if latest.is_some() { "ready" } else { "idle" };
        let message = error.map(String::as_str).or_else(|| latest.filter(|release| release.fallback)
            .map(|_| "The current release could not be confirmed. The publisher's pinned release is available."));
        serde_json::json!({
            "id":publisher.id,"name":publisher.name,"edition":publisher.edition,"collection":publisher.collection,
            "verification":"Signed","sourceHost":publisher.media_hosts.first(),"state":state,
            "activeEntryId":latest.map(|release| release.id()),"message":message,
        })
    }

    pub(super) fn start(&mut self, library: &Path, publisher: &'static Publisher) -> Result<serde_json::Value, String> {
        self.reap(library);
        if self.active.is_some() { return Err("Wait for the current publisher check to finish.".into()); }
        let library = library.to_owned();
        let worker = std::thread::Builder::new().name("catalog-publisher".into()).spawn(move || {
            let release = resolve(publisher, &library)?;
            save(&library, &release)?;
            Ok(release)
        }).map_err(|_| "The publisher check could not start.".to_owned())?;
        self.errors.remove(&publisher.id);
        self.active = Some((publisher.id.clone(), worker));
        Ok(self.summary(publisher))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_sources_bind_major_candidates_to_numeric_publisher_filenames() {
        let sources = publishers().expect("valid publisher recipes");
        assert_eq!(sources.len(), 10);
        let ubuntu = publisher("ubuntu").expect("Ubuntu publisher");
        let old = "1".repeat(64);
        let newest = "2".repeat(64);
        let doc = format!("{old} *ubuntu-26.04.9-desktop-amd64.iso\n\
            {newest} *ubuntu-26.04.10-desktop-amd64.iso\n\
            {old} *ubuntu-99.00-server-amd64.iso\n");
        assert_eq!(manifest_entry(ubuntu, doc.as_bytes(), None).unwrap(),
            ("ubuntu-26.04.10-desktop-amd64.iso".into(), newest.clone()));
        let ambiguous = format!("{doc}{newest} *ubuntu-26.04.10-desktop-amd64.iso\n");
        assert!(manifest_entry(ubuntu, ambiguous.as_bytes(), None).is_err());
        assert!(manifest_entry(ubuntu, doc.as_bytes(), Some("../ubuntu-26.04.10-desktop-amd64.iso")).is_err());
        assert!(publisher("kali-linux").is_some());
        let parrot = publisher("parrot-security").expect("Parrot publisher");
        let parrot_name = "Parrot-security-7.4_amd64.iso";
        let mixed = format!("{}  {parrot_name}\n{newest} *{parrot_name}\n{}  {parrot_name}\n", "3".repeat(32), "4".repeat(128));
        assert_eq!(manifest_entry(parrot, mixed.as_bytes(), None).unwrap(), (parrot_name.into(), newest));
        assert!(publisher("metasploitable").is_none());
    }
}
