use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use svm_core::engine::GuestExecRequest;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub(super) enum Family { Debian, Fedora, Windows }

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub(super) enum Distro { Debian, Ubuntu, Kali, Parrot, Linuxmint, Fedora, Rocky, Almalinux, Windows }

impl Distro {
    fn family(self) -> Family {
        match self {
            Self::Debian | Self::Ubuntu | Self::Kali | Self::Parrot | Self::Linuxmint => Family::Debian,
            Self::Fedora | Self::Rocky | Self::Almalinux => Family::Fedora,
            Self::Windows => Family::Windows,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
enum Category { Security, Developer, #[serde(rename = "AI tools")] Ai, Everyday }

impl Category {
    fn name(self) -> &'static str {
        match self {
            Self::Security => "Security", Self::Developer => "Developer",
            Self::Ai => "AI tools", Self::Everyday => "Everyday",
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PublisherRepo { Docker, Microsoft }

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum Recipe {
    Apt { packages: Vec<String>, #[serde(default)] distros: Vec<Distro>,
          repository: Option<PublisherRepo>, fingerprint: Option<String> },
    Dnf { packages: Vec<String>, #[serde(default)] distros: Vec<Distro> },
    Winget { package: String },
    Image { image: String },
}

impl Recipe {
    fn label(&self) -> &'static str {
        match self {
            Self::Apt { repository: Some(_), .. } => "Signed",
            Self::Image { .. } => "Checksum",
            _ => "Distro",
        }
    }

    fn supports(&self, distro: Distro) -> bool {
        match self {
            Self::Apt { distros, .. } | Self::Dnf { distros, .. } =>
                distros.is_empty() || distros.contains(&distro),
            _ => true,
        }
    }

    fn public(&self) -> Value {
        match self {
            Self::Apt { distros, .. } | Self::Dnf { distros, .. } =>
                json!({"label": self.label(), "distros": distros}),
            Self::Winget { package } => json!({"label": self.label(), "packageId": package}),
            Self::Image { .. } => json!({"label": self.label(), "needsDocker": true}),
        }
    }

    fn check(&self, family: Family) -> bool {
        let packages_ok = |packages: &[String]| {
            !packages.is_empty() && packages.len() <= 8
                && packages.iter().all(|name| safe_name(name)
                    && name.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric))
        };
        let distros_ok = |distros: &[Distro]| distros.iter().all(|distro| distro.family() == family);
        match self {
            Self::Apt { packages, distros, repository, fingerprint } => family == Family::Debian
                && packages_ok(packages) && distros_ok(distros)
                && match (repository, fingerprint) {
                    (None, None) => true,
                    (Some(repo), Some(pin)) => hex(pin, 40) && pin == repo.fingerprint(),
                    _ => false,
                },
            Self::Dnf { packages, distros } => family == Family::Fedora
                && packages_ok(packages) && distros_ok(distros),
            Self::Winget { package } => family == Family::Windows && safe_name(package) && package.contains('.'),
            Self::Image { image } => family != Family::Windows
                && image.strip_prefix("docker.io/openwebui/open-webui@sha256:").is_some_and(|pin| hex(pin, 64)),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct App {
    pub(super) id: String,
    pub(super) name: String,
    category: Category,
    description: String,
    licence: String,
    publisher: String,
    homepage: String,
    note: Option<String>,
    recipes: BTreeMap<Family, Recipe>,
}

impl App {
    pub(super) fn public(&self) -> Value {
        let recipes: BTreeMap<_, _> = self.recipes.iter().map(|(family, recipe)| (family, recipe.public())).collect();
        json!({"id": self.id, "name": self.name, "category": self.category.name(),
            "description": self.description, "licence": self.licence, "publisher": self.publisher,
            "homepage": self.homepage, "note": self.note,
            "label": self.recipes.is_empty().then_some("Reference"), "recipes": recipes})
    }

    pub(super) fn may_use(&self, windows: bool) -> bool {
        self.recipes.keys().any(|family| (*family == Family::Windows) == windows)
    }

    pub(super) fn plan(&self, guest: Target, action: Action) -> Option<Vec<Step>> {
        let recipe = self.recipes.get(&guest.distro.family())?;
        if !recipe.supports(guest.distro) { return None; }
        let install = action == Action::Install;
        let mut steps = vec![Step { title: "Verify guest compatibility", command: guest.probe() }];
        match recipe {
            Recipe::Apt { packages, repository, fingerprint, .. } => {
                let packages = removable(packages, install);
                if install {
                    let sources = guest.apt_sources()?;
                    if repository.is_some() {
                        steps.push(apt_step("Prepare certificate and key tools", &sources, None,
                            &["ca-certificates".into(), "curl".into(), "gpg".into()]));
                    }
                    let publisher = match (repository, fingerprint) {
                        (Some(repo), Some(pin)) => Some((repo.source(guest)?, pin.as_str())),
                        (None, None) => None,
                        _ => return None,
                    };
                    steps.push(apt_step("Install packages", &sources, publisher, &packages));
                } else {
                    steps.push(linux_change("Remove packages", "/bin/sh", &[
                        "-eu".into(), "-c".into(), APT_REMOVE.into(), "marketplace".into()
                    ].into_iter().chain(packages).collect::<Vec<_>>(), 120));
                }
            }
            Recipe::Dnf { packages, .. } => {
                let repos: &[_] = if guest.distro == Distro::Fedora { &["fedora", "updates"] } else { &["baseos", "appstream", "extras"] };
                let mut args = vec!["-y".into()];
                if install {
                    for repo in repos {
                        args.extend([format!("--repo={repo}"), format!("--setopt={repo}.gpgcheck=1")]);
                    }
                    args.extend(["--refresh".into(), "install".into()]);
                } else {
                    let disable = if guest.distro == Distro::Fedora { "--disable-repo=*" } else { "--disablerepo=*" };
                    args.extend([disable.into(), "--setopt=clean_requirements_on_remove=False".into(), "remove".into()]);
                }
                args.extend(removable(packages, install));
                steps.push(linux_change(if install { "Install packages" } else { "Remove packages" }, "/usr/bin/dnf", &args, 120));
            }
            Recipe::Winget { package } => {
                let verb = if install { "install" } else { "uninstall" };
                let agreements = if install { " --accept-source-agreements --accept-package-agreements" } else { "" };
                let args = format!("{verb} --id {package} --exact --source winget --silent --disable-interactivity{agreements}");
                steps.push(Step { title: if install { "Install WinGet package" } else { "Uninstall WinGet package" },
                    command: winget(&format!(r#"
$start = [Diagnostics.ProcessStartInfo]::new($winget, '{args}')
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$child = [Diagnostics.Process]::Start($start)
if (!$child.WaitForExit(108000)) {{
    & "$env:SystemRoot\System32\taskkill.exe" /T /F /PID $child.Id
    [Console]::Error.WriteLine('WinGet timed out. Check the guest before retrying.')
    exit 124
}}
exit $child.ExitCode
"#), 120) });
            }
            Recipe::Image { image } => {
                steps.push(docker_probe());
                let args = docker_args(["image", if install { "pull" } else { "rm" }, image]);
                steps.push(linux_change(if install { "Pull pinned image" } else { "Remove image" }, "/usr/bin/docker", &args, 120));
            }
        }
        Some(steps)
    }

    pub(super) fn needs_docker(&self, target: Target) -> bool {
        matches!(self.recipes.get(&target.distro.family()), Some(Recipe::Image { .. }))
    }
}

fn removable(packages: &[String], install: bool) -> Vec<String> {
    // The base Python interpreter may be required by the distribution itself.
    packages.iter().filter(|name| install || *name != "python3").cloned().collect()
}

fn safe_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 96 && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".+-_".contains(&byte))
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn entries() -> Result<&'static [App], &'static str> {
    static ENTRIES: OnceLock<Result<Vec<App>, &'static str>> = OnceLock::new();
    ENTRIES.get_or_init(|| parse(include_str!("../catalog/apps.json"))).as_deref().map_err(|error| *error)
}

fn parse(data: &str) -> Result<Vec<App>, &'static str> {
    let apps: Vec<App> = serde_json::from_str(data).map_err(|_| "The bundled app catalog could not be read.")?;
    let mut ids = BTreeSet::new();
    for app in &apps {
        if !safe_name(&app.id) || !ids.insert(&app.id)
            || [&app.name, &app.description, &app.licence, &app.publisher].iter().any(|s| s.trim().is_empty())
            || !url::Url::parse(&app.homepage).is_ok_and(|u| u.scheme() == "https"
                && u.host_str().is_some() && u.username().is_empty() && u.password().is_none() && u.port().is_none())
            || app.recipes.iter().any(|(family, recipe)| !recipe.check(*family))
        {
            return Err("The bundled app catalog failed validation.");
        }
    }
    Ok(apps)
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Action { Install, Uninstall }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Target {
    distro: Distro,
    suite: &'static str,
    arm: bool,
}

impl Target {
    pub(super) fn from_probe(windows: bool, output: &str) -> Option<Self> {
        if windows { return Some(Self { distro: Distro::Windows, suite: "", arm: false }); }
        let field = |name: &str| output.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == name).then(|| value.trim_matches('"'))
        });
        let (distro, suite) = match field("ID")? {
            "debian" => (Distro::Debian, debian_suite(field("VERSION_CODENAME")?)?),
            "ubuntu" => (Distro::Ubuntu, ubuntu_suite(field("VERSION_CODENAME")?)?),
            "linuxmint" => (Distro::Linuxmint, ubuntu_suite(field("UBUNTU_CODENAME")?)?),
            "kali" if field("VERSION_CODENAME")? == "kali-rolling" => (Distro::Kali, "kali-rolling"),
            "parrot" if field("VERSION_CODENAME").is_some_and(|value| value.eq_ignore_ascii_case("echo"))
                || field("VERSION_ID").is_some_and(|value| value == "7" || value.starts_with("7.")) => (Distro::Parrot, "echo"),
            "fedora" => (Distro::Fedora, ""),
            "rocky" => (Distro::Rocky, ""),
            "almalinux" => (Distro::Almalinux, ""),
            _ => return None,
        };
        let arm = match field("SVM_MARKET_ARCH")? {
            "aarch64" => true, "x86_64" => false, _ => return None,
        };
        Some(Self { distro, suite, arm })
    }

    pub(super) fn probe(self) -> GuestExecRequest {
        probe(self.distro == Distro::Windows)
    }

    fn apt_sources(self) -> Option<String> {
        let mut sources = String::new();
        let mut add = |base: &str, suite: &str, key: &str, components: &str| {
            sources.push_str(&format!("deb [signed-by=/usr/share/keyrings/{key}] {base} {suite} {components}\n"));
        };
        let main = self.suite;
        match self.distro {
            Distro::Debian => {
                let base = "https://deb.debian.org/debian";
                let key = "debian-archive-keyring.gpg";
                add(base, main, key, "main");
                add(base, &format!("{main}-updates"), key, "main");
                add("https://security.debian.org/debian-security", &format!("{main}-security"), key, "main");
            }
            Distro::Ubuntu | Distro::Linuxmint => {
                let (base, security) = if self.arm {
                    ("https://ports.ubuntu.com/ubuntu-ports", "https://ports.ubuntu.com/ubuntu-ports")
                } else {
                    ("https://archive.ubuntu.com/ubuntu", "https://security.ubuntu.com/ubuntu")
                };
                let key = "ubuntu-archive-keyring.gpg";
                add(base, main, key, "main universe restricted multiverse");
                add(base, &format!("{main}-updates"), key, "main universe restricted multiverse");
                add(security, &format!("{main}-security"), key, "main universe restricted multiverse");
            }
            Distro::Kali => add("https://http.kali.org/kali", main, "kali-archive-keyring.gpg",
                "main contrib non-free non-free-firmware"),
            Distro::Parrot => {
                let key = "parrot-archive-keyring.gpg";
                let base = "https://deb.parrot.sh/parrot";
                add(base, main, key, "main contrib non-free non-free-firmware");
                add("https://deb.parrot.sh/direct/parrot", "echo-security", key, "main contrib non-free non-free-firmware");
            }
            _ => return None,
        }
        Some(sources)
    }
}

fn debian_suite(value: &str) -> Option<&'static str> {
    match value { "bookworm" => Some("bookworm"), "trixie" => Some("trixie"), _ => None }
}

fn ubuntu_suite(value: &str) -> Option<&'static str> {
    match value {
        "jammy" => Some("jammy"), "noble" => Some("noble"), "resolute" => Some("resolute"), _ => None,
    }
}

struct AptSource { key_url: String, base: String, suite: &'static str, component: &'static str, origin: &'static str }

impl PublisherRepo {
    fn fingerprint(self) -> &'static str {
        match self {
            Self::Docker => "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
            Self::Microsoft => "BC528686B50D79E339D3721CEB3E94ADBE1229CF",
        }
    }

    fn source(self, target: Target) -> Option<AptSource> {
        match self {
            Self::Docker => {
                let distro = match target.distro { Distro::Debian => "debian", Distro::Ubuntu => "ubuntu", _ => return None };
                let base = format!("https://download.docker.com/linux/{distro}");
                Some(AptSource { key_url: format!("{base}/gpg"), base, suite: target.suite,
                    component: "stable", origin: "download.docker.com" })
            }
            Self::Microsoft => Some(AptSource {
                key_url: "https://packages.microsoft.com/keys/microsoft.asc".into(),
                base: "https://packages.microsoft.com/repos/code".into(), suite: "stable",
                component: "main", origin: "packages.microsoft.com",
            }),
        }
    }
}

pub(super) struct Step {
    pub(super) title: &'static str,
    pub(super) command: GuestExecRequest,
}

impl Step {
    pub(super) fn preview(&self) -> Value {
        json!({"title": self.title, "argv": self.command.argv, "timeoutSec": self.command.timeout_sec})
    }
}

fn command(argv: Vec<String>, timeout_sec: u64) -> GuestExecRequest {
    GuestExecRequest { argv, timeout_sec, stdin: None }
}

pub(super) fn probe(windows: bool) -> GuestExecRequest {
    if windows {
        winget("Write-Output 'Microsoft community repository verified.'", 18)
    } else {
        command(["/usr/bin/timeout", "12s", "/bin/sh", "-ec",
            r#"cat /etc/os-release; printf 'SVM_MARKET_ARCH='; uname -m"#]
            .into_iter().map(str::to_owned).collect(), 18)
    }
}

pub(super) fn docker_probe() -> Step {
    linux_change("Check Docker inside the guest", "/usr/bin/docker",
        &docker_args(["info", "--format", "{{.ServerVersion}}"]), 24)
}

fn docker_args<const N: usize>(args: [&str; N]) -> Vec<String> {
    ["--host", "unix:///var/run/docker.sock"].into_iter().chain(args).map(str::to_owned).collect()
}

fn winget(script: &str, timeout: u64) -> GuestExecRequest {
    command(vec!["powershell.exe".into(), "-NoLogo".into(), "-NoProfile".into(), "-NonInteractive".into(),
        "-Command".into(), format!("{}{script}", include_str!("app_winget.ps1"))], timeout)
}

fn linux_change(title: &'static str, program: &str, args: &[String], timeout_sec: u64) -> Step {
    let limit = format!("{}s", timeout_sec - 11);
    let argv = ["/bin/sh", "-ec", LINUX_CHANGE, "marketplace", &limit, program]
        .into_iter().map(str::to_owned).chain(args.iter().cloned()).collect();
    Step { title, command: command(argv, timeout_sec) }
}

fn apt_step(title: &'static str, sources: &str, publisher: Option<(AptSource, &str)>, packages: &[String]) -> Step {
    let mut args = vec!["-eu".into(), "-c".into(), include_str!("app_apt.sh").into(), "marketplace".into(), sources.into()];
    if let Some((source, fingerprint)) = publisher {
        args.extend([source.key_url, fingerprint.into(), source.base, source.suite.into(),
            source.component.into(), source.origin.into()]);
    } else {
        args.extend(std::iter::repeat_n(String::new(), 6));
    }
    args.extend_from_slice(packages);
    linux_change(title, "/bin/sh", &args, 120)
}

const LINUX_CHANGE: &str = r#"
limit=$1
shift
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C DEBIAN_FRONTEND=noninteractive
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS_VERIFY DOCKER_CERT_PATH
if [ "$(/usr/bin/id -u)" -eq 0 ]; then
    exec /usr/bin/timeout --kill-after=5s "$limit" "$@"
fi
exec /usr/bin/sudo -n /usr/bin/env LC_ALL=C DEBIAN_FRONTEND=noninteractive /usr/bin/timeout --kill-after=5s "$limit" "$@"
"#;

const APT_REMOVE: &str = r#"
plan=$(apt-get -s remove -- "$@")
printf '%s\n' "$plan"
removing=$(printf '%s\n' "$plan" | awk '$1 == "Remv" {sub(/:.*/, "", $2); print $2}')
for package in $removing; do
    allowed=no
    for requested in "$@"; do
        if [ "$package" = "$requested" ]; then allowed=yes; fi
    done
    if [ "$allowed" = no ]; then
        printf '%s\n' 'Removing this app would also remove another package.' >&2
        exit 1
    fi
done
exec apt-get -y remove -- "$@"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str) -> &'static App {
        entries().unwrap().iter().find(|app| app.id == id).unwrap()
    }

    fn linux(id: &str, extra: &str) -> Target {
        Target::from_probe(false, &format!("ID={id}\n{extra}\nSVM_MARKET_ARCH=x86_64\n")).unwrap()
    }

    fn listing(steps: &[Step]) -> String {
        steps.iter().map(|step| step.command.argv.join(" ")).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn app_catalog_records_trust_and_validates_all_recipes() {
        let apps = entries().unwrap();
        let docs = include_str!("../../../DOWNLOADS.md");
        assert!(apps.len() >= 15);
        assert_eq!(apps.iter().map(|a| a.category.name()).collect::<BTreeSet<_>>().len(), 4);
        let mut signed = 0;
        for app in apps {
            for recipe in app.recipes.values() {
                if let Recipe::Apt { repository: Some(repo), fingerprint: Some(pin), .. } = recipe {
                    let source = match repo { PublisherRepo::Docker => "download.docker.com/linux/debian/gpg",
                        PublisherRepo::Microsoft => "packages.microsoft.com/keys/microsoft.asc" };
                    assert!(docs.lines().any(|line| line.contains(pin) && line.contains(source)));
                    signed += 1;
                }
            }
        }
        assert_eq!(signed, 2);
        assert_eq!(app("vscode").public()["recipes"]["windows"]["packageId"], "Microsoft.VisualStudioCode");
        assert_eq!(app("pytorch-cpu").public()["label"], "Reference");
        assert_eq!(app("open-webui").public()["recipes"]["debian"]["label"], "Checksum");
        let data = include_str!("../catalog/apps.json");
        for invalid in [
            data.replace("Git.Git", "Git.Git; whoami"),
            data.replace("9DC858229FC7DD38854AE2D88D81803C0EBFCD88", "0"),
            data.replace(r#""git"]"#, r#""git+"]"#),
            data.replace("docker.io/openwebui/open-webui@sha256:", "docker.io/other/image@sha256:"),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }

    #[test]
    fn commands_are_bounded_and_keep_signature_checks_enabled() {
        let targets = [
            linux("debian", "VERSION_CODENAME=trixie"), linux("ubuntu", "VERSION_CODENAME=noble"),
            linux("kali", "VERSION_CODENAME=kali-rolling"), linux("parrot", "VERSION_ID=7.4"),
            linux("linuxmint", "UBUNTU_CODENAME=noble"), linux("fedora", ""), linux("rocky", ""),
            linux("almalinux", ""), Target::from_probe(true, "").unwrap(),
        ];
        for app in entries().unwrap() {
            for target in targets {
                for action in [Action::Install, Action::Uninstall] {
                    let Some(steps) = app.plan(target, action) else { continue; };
                    for step in &steps {
                        assert!(step.command.check().is_ok());
                        assert!(step.command.stdin.is_none());
                    }
                    let commands = listing(&steps).to_ascii_lowercase();
                    for pattern in ["--allow-unauthenticated", "trusted=yes", "gpgcheck=0",
                        "--nogpgcheck", "--ignore-security-hash"] {
                        assert!(!commands.contains(pattern), "{} contains {pattern}", app.id);
                    }
                    for right in commands.split('|').skip(1).map(str::trim_start) {
                        assert!(!["sh", "bash", "/bin/sh", "/bin/bash", "sudo sh", "sudo bash"].iter()
                            .any(|shell| right.strip_prefix(shell).is_some_and(|tail| tail.is_empty() || tail.starts_with(char::is_whitespace))));
                    }
                }
            }
        }
    }

    #[test]
    fn recipes_select_the_guest_package_manager_and_supported_distribution() {
        let debian = linux("debian", "VERSION_CODENAME=trixie");
        let fedora = linux("fedora", "");
        let kali = linux("kali", "VERSION_CODENAME=kali-rolling");
        let windows = Target::from_probe(true, "").unwrap();
        let docker = listing(&app("docker-engine").plan(debian, Action::Install).unwrap());
        assert!(docker.contains("download.docker.com/linux/debian/gpg"));
        assert!(docker.contains("9DC858229FC7DD38854AE2D88D81803C0EBFCD88"));
        assert!(docker.contains("docker-ce docker-ce-cli"));
        assert!(app("docker-engine").plan(kali, Action::Install).is_none());
        assert!(app("metasploit").plan(debian, Action::Install).is_none());
        assert!(listing(&app("metasploit").plan(kali, Action::Uninstall).unwrap()).contains("metasploit-framework"));
        assert!(listing(&app("llama-cpp").plan(fedora, Action::Install).unwrap()).contains("--repo=fedora"));
        assert!(app("llama-cpp").plan(linux("rocky", ""), Action::Install).is_none());
        assert!(listing(&app("git").plan(windows, Action::Install).unwrap()).contains("install --id Git.Git --exact --source winget"));
        assert!(listing(&app("git").plan(windows, Action::Uninstall).unwrap()).contains("uninstall --id Git.Git --exact --source winget"));
        assert!(listing(&app("open-webui").plan(fedora, Action::Install).unwrap())
            .contains("docker --host unix:///var/run/docker.sock image pull docker.io/openwebui/open-webui@sha256:"));
        assert!(listing(&app("python").plan(debian, Action::Uninstall).unwrap()).contains("marketplace python3-venv"));
        assert!(app("burp-community").plan(windows, Action::Install).is_none());
        assert!(Target::from_probe(false, "ID=ubuntu\nVERSION_CODENAME=noble; sh\nSVM_MARKET_ARCH=x86_64").is_none());
    }
}
