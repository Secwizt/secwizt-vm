# Arguments are generated from the bundled catalog and fixed distro profiles.
sources=$1
key_url=$2
fingerprint=$3
base=$4
suite=$5
component=$6
origin=$7
shift 7

work=$(mktemp -d /run/secwiz-apps.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
chmod 0755 "$work"
printf '%s' "$sources" >"$work/sources.list"
: >"$work/preferences"
mkdir "$work/lists"

if [ -n "$key_url" ]; then
    printf '%s\n' 'Verifying the publisher repository key.'
    mkdir -m 0700 "$work/gnupg"
    curl -q --fail --silent --show-error --proto '=https' --max-time 20 \
        --max-filesize 16384 --output "$work/key.asc" "$key_url"
    gpg --no-options --batch --homedir "$work/gnupg" --with-colons --show-keys "$work/key.asc" >"$work/key-info"
    actual=$(awk -F: '
        $1 == "pub" { keys++; primary = 1; next }
        $1 == "sub" { primary = 0 }
        $1 == "fpr" && primary { print $10; primary = 0 }
        END { if (keys != 1) exit 1 }
    ' "$work/key-info")
    if [ "$actual" != "$fingerprint" ]; then
        printf '%s\n' 'The publisher signing key did not match the catalog fingerprint.' >&2
        exit 1
    fi
    gpg --no-options --batch --homedir "$work/gnupg" --dearmor --output "$work/publisher.gpg" "$work/key.asc"
    chmod 0644 "$work/publisher.gpg"
    printf 'deb [signed-by=%s/publisher.gpg] %s %s %s\n' "$work" "$base" "$suite" "$component" >>"$work/sources.list"
    for package in "$@"; do
        printf 'Package: %s\nPin: origin "%s"\nPin-Priority: 990\n\n' "$package" "$origin"
        printf 'Package: %s\nPin: version *\nPin-Priority: -1\n\n' "$package"
    done >"$work/preferences"
fi

market_apt() {
    apt-get -o "Dir::Etc::sourcelist=$work/sources.list" -o Dir::Etc::sourceparts=- \
        -o "Dir::Etc::preferences=$work/preferences" -o Dir::Etc::preferencesparts=- \
        -o "Dir::State::lists=$work/lists" -o Acquire::AllowInsecureRepositories=false \
        -o Acquire::AllowDowngradeToInsecureRepositories=false \
        -o APT::Get::AllowUnauthenticated=false "$@"
}

printf '%s\n' 'Refreshing and authenticating repository metadata.'
market_apt -o APT::Update::Error-Mode=any update
if [ "$origin" = packages.microsoft.com ]; then
    # Keep the package from enrolling its key through a separate, unpinned path.
    printf '%s\n' 'code code/add-microsoft-repo boolean false' >"$work/debconf"
    debconf-set-selections "$work/debconf"
fi
printf '%s\n' 'Installing the selected packages.'
market_apt --no-remove --no-install-recommends -y install -- "$@"
