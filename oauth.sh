#!/bin/bash

set -eCu -o pipefail

readonly AUDIENCE='https://www.googleapis.com/oauth2/v4/token'
readonly SCOPE='https://www.googleapis.com/auth/drive'

CONFIG=''
ISSUER=''

LIMIT=10
DELAY=0

function encode() {
    local input=${1:-$(tr -d '\0' </dev/stdin)}
    printf '%s' "$input" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n'
}

function sign() {
    local input=${1:-$(</dev/stdin)}
    local secret="$(<$CONFIG json -k 'private_key')"
    local key_path='/tmp/private.key'

    echo "$secret" > "$key_path" && printf '%s' "$input" | openssl dgst -binary -sha256 -sign "$key_path" && rm "$key_path"
}

function json() {
    local keys=()
    local index=0
    
    while getopts :k: OPT; do
	case $OPT in
	    k|+k)
		keys[index]="$OPTARG"
		index=+1
		;;
	    *)
		echo "usage: ${0##*/} [+-k} [--] ARGS..."
		exit 2
	esac
    done
    shift $(( OPTIND - 1 ))
    OPTIND=1

    if [[ "${#keys[@]}" -ne 0 ]]; then
	python -c "import sys,json; print json.load(sys.stdin)$(printf '.get(\"%s\")' ${keys[@]})"
    else
	python -c "import sys,json; print json.load(sys.stdin)"
    fi
}

function get_request_token() {
    local iat=$(date +%s)  # issue time
    local exp=$(( $iat + 3600 ))  # expiration time
    local issuer="$(<$CONFIG json -k client_email)"
    
    local header='{"alg":"RS256","typ":"JWT"}'
    local payload="{\"iss\":\"$issuer\",\"scope\":\"$SCOPE\",\"aud\":\"$AUDIENCE\",\"exp\":$exp,\"iat\":$iat}"

    body=$(printf '%s.%s' $(encode $header) $(encode $payload))
    signature=$(printf '%s' $body | sign | encode)

    printf '%s.%s\n' $body $signature
}

function get_access_token() {
    local input=${1:-$(</dev/stdin)}
    local grant_type='urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer'

    request=$(printf 'grant_type=%s&assertion=%s' "$grant_type" "$input")
    response=$(curl -sS -X POST -d "$request" "$AUDIENCE")

    if [[ "$?" -ne 0 ]]; then
	echo "Did not receive a proper response from $AUDIENCE" >&2
	exit 1
    else
	echo "$response"
    fi
}

while getopts :f:l:d: OPT; do
    case $OPT in
	f|+f)
	    if [[ -f "$OPTARG" ]]; then
		readonly CONFIG="$OPTARG"
	    fi
	    ;;
	l|+l)
	    readonly LIMIT=$OPTARG
	    ;;
	d|+d)
	    readonly DELAY=$OPTARG
	    ;;
	:)
	    echo "Missing option argument for -$OPTARG" >&2
	    exit 1
	    ;;
	*)
	    echo "Usage: ${0##*/} +-f ARG [+-l ARG] [+-d ARG] [--] ARGS..." >&2
	    exit 2
    esac
done
shift $(( OPTIND - 1 ))
OPTIND=1

if [[ ! "$CONFIG" ]]; then
    echo "Secrets file required. Usage: ${0##*/} +-f ARG [+-l ARG] [+-d ARG] [--] ARGS..." >&2
    exit 1
fi


# Authentication doesn't always work on the first try, so loop (with delay)
# until it does or until we reach the maximum retry limit... Yikes?!

declare error=''
declare index=0

until [[ "$error" == 'None' ]] || [[ $index -eq $LIMIT ]]; do
    declare response="$(get_request_token | get_access_token)"
    declare error=$(echo "$response" | json -k error)

    declare index=$(( $index + 1 ))
    
    sleep $(( $DELAY + $index ))
done

if [[ "$error" == "None" ]]; then
    echo "$response" | json -k access_token
    exit 0
else
    echo "$response" >&2
    exit 1
fi
