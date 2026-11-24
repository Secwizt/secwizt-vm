set -eu
export LC_ALL=C
umask 077
op=$1
final=$2
stage=$3
token=$4
length=$5
checksum=$6

case "$token" in ''|*[!a-f0-9]*) exit 2;; esac
[ "${#token}" -eq 32 ]
parent=${final%/*}
[ "$stage" = "$parent/.svm-file-$token" ]
parent=${parent:-/}
[ "$(realpath -e -- "$parent")" = "$parent" ]
[ -d "$parent" ]
[ -x "$parent" ]

marker=$stage/owner
source=$stage/data.part
verified=$stage/verified.part
if [ "$op" = prepare ]; then
    if [ -e "$final" ] || [ -L "$final" ]; then exit 20; fi
    mkdir -m 700 -- "$stage"
    (set -C; printf '%s' "$token" > "$marker")
    exit 0
fi

if [ "$op" = clear ] && [ ! -e "$stage" ] && [ ! -L "$stage" ]; then exit 0; fi
[ -d "$stage" ] && [ ! -L "$stage" ] || exit 2
[ "$(stat -c '%a:%u' -- "$stage")" = "700:$(id -u)" ]
[ -f "$marker" ] && [ ! -L "$marker" ] || exit 2
[ "$(wc -c < "$marker")" -eq 32 ] && [ "$(cat -- "$marker")" = "$token" ] || exit 2

case "$op" in
    verify)
        [ -f "$source" ] && [ ! -L "$source" ] || exit 2
        # Guest Services may own the received file as root. Only publish a verified SSH-user-owned file.
        (set -C; cat -- "$source" > "$verified")
        actual=$(sha256sum < "$verified")
        [ "$(stat -c %s -- "$verified")" = "$length" ] && [ "${actual%% *}" = "$checksum" ] || exit 21
        ;;
    publish)
        [ -f "$verified" ] && [ ! -L "$verified" ] || exit 2
        # Link chooses exactly the final name and fails atomically when it already exists.
        if ! ln -T -- "$verified" "$final"; then
            if [ -e "$final" ] || [ -L "$final" ]; then exit 20; fi
            exit 2
        fi
        ;;
    clear)
        rm -f -- "$source" "$verified" "$marker"
        rmdir -- "$stage"
        ;;
    *) exit 2;;
esac
