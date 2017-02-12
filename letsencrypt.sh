#!/bin/sh

#    letsencrypt.sh - a simple shell implementation for the acme protocol
#    Copyright (C) 2015 Gerhard Heift
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# temporary files to store input/output of curl or openssl

trap 'rm -f "$RESP_HEADER" "$RESP_BODY" "$LAST_NONCE" "$LAST_NONCE_FETCH" "$OPENSSL_CONFIG" "$OPENSSL_IN" "$OPENSSL_OUT" "$OPENSSL_ERR" "$TMP_SERVER_CSR"' 0 2 3 9 11 13 15

# file to store header of http request
RESP_HEADER="`mktemp -t le.$$.resp-header.XXXXXX`"
# file to store body of http request
RESP_BODY="`mktemp -t le.$$.resp-body.XXXXXX`"
# file with Replay-Nonce header of last request
LAST_NONCE="`mktemp -t le.$$.nonce.XXXXXX`"
# tmp file for new Replay-Nonce header
LAST_NONCE_FETCH="`mktemp -t le.$$.nonce-fetch.XXXXXX`"
# tmp config for openssl for addional domains
OPENSSL_CONFIG="`mktemp -t le.$$.openssl.cnf.XXXXXX`"
# file to store openssl output
OPENSSL_IN="`mktemp -t le.$$.openssl.in.XXXXXX`"
OPENSSL_OUT="`mktemp -t le.$$.openssl.out.XXXXXX`"
OPENSSL_ERR="`mktemp -t le.$$.openssl.err.XXXXXX`"
# file to store the CSR
TMP_SERVER_CSR="`mktemp -t le.$$.server.csr.XXXXXX`"

CA="https://acme-staging.api.letsencrypt.org"

# Prefix the following line with "# letsencrypt-production-server #", to use
# the staging server of letsencrypt. The staging server has lower rate limits,
# but does not issue valid certificates. To automatically remove the comment
# again on commiting the file, add the filter to your git config by running
#   git config filter.production-server.clean misc/filter-production-server

CA="https://acme-v01.api.letsencrypt.org"

# global variables:

# base64url encoded JSON nonce, generated from Replay-Nonce header
# see gen_protected()
PROTECTED=

# base64url encoded JSON request object
PAYLOAD=

# base64url encoded signature of PROTECTED and PAYLOAD
# see also gen_signature()
SIGNATURE=

# the account key used to send the requests and to verify the domain challenges
ACCOUNT_KEY=

# the JSON Web Key is the representation of the key as JSON object
ACCOUNT_JWK=

# the JSON object to specify the signature format
REQ_JWKS=

# the thumbprint is the checksum of the JWK and is used for the challenges
ACCOUNT_THUMB=

# the private key, which should be signed by the CA
SERVER_KEY=

# the certificate signing request, which sould be used
SERVER_CSR=

# the location, where the certificate should be stored
SERVER_CERT=

# the e-mail address to be used with the account key, only needed if account
# key is not yet registred
ACCOUNT_EMAIL=

# a list of domains, which should be assigned to the certificate
DOMAINS=

# a list of domains, challenge uri and token
DOMAIN_DATA=

# the directory, where to push the response
# $DOMAIN or ${DOMAIN} will be replaced with the actual domain
WEBDIR=

# the script to be called to push the response to a remote server
PUSH_TOKEN=

QUIET=

# utility functions

base64url() {
    openssl base64 | tr '+/' '-_' | tr -d '\r\n='
}

log() {
    if [ -z "$QUIET" ]; then
        echo "$@" > /dev/stderr
    fi
}

die() {
    [ -n "$1" ] && printf "%s\n" "$1" > /dev/stderr
    exit 1
}

validate_domain() {
    DOMAIN_IN="$1"
    if [ "$DOMAIN_IN" = _ ]; then
        return 1
    fi

    DOMAIN_OUT="`printf "%s\n" "$DOMAIN_IN" | sed -e 's/^...$/!/; s/^.\{254,\}$/!/; s/^\([a-zA-Z0-9]\([-a-zA-Z0-9]\{0,61\}[a-zA-Z0-9]\)\?\.\)\+[a-zA-Z]\{2,63\}$/_/;'`"

    if [ "$DOMAIN_OUT" = _ ]; then
        return 0
    else
        return 1
    fi
}

handle_curl_exit() {
    CURL_EXIT="$1"
    CURL_URI="$2"

    if [ "$CURL_EXIT" "!=" 0 ]; then
        echo "error while making a web request to \"$CURL_URI\"" > /dev/stderr
        echo "curl exit status: $CURL_EXIT" > /dev/stderr
        case "$CURL_EXIT" in
            # see man curl "EXIT CODES"
             3) echo "  malformed URI" > /dev/stderr;;
             6) echo "  could not resolve host" > /dev/stderr;;
             7) echo "  failed to connect" > /dev/stderr;;
            28) echo "  operation timeout" > /dev/stderr;;
            35) echo "  SSL connect error" > /dev/stderr;;
        esac

        exit 1
    fi
}

handle_openssl_exit() {
    OPENSSL_EXIT=$1
    OPENSSL_ACTION=$2

    if [ "$OPENSSL_EXIT" "!=" 0 ]; then
        echo "error while $OPENSSL_ACTION" > /dev/stderr
        echo "openssl exit status: $OPENSSL_EXIT" > /dev/stderr
        cat "$OPENSSL_ERR" > /dev/stderr
        exit 1
    fi
}

check_http_status() {
    fgrep -q "HTTP/1.1 $1 " "$RESP_HEADER"
}

unhandled_response() {
    echo "unhandled response while $1" > /dev/stderr
    echo > /dev/stderr

    cat "$RESP_HEADER" "$RESP_BODY" > /dev/stderr

    echo > /dev/stderr

    exit 1
}

show_error() {
    if [ -n "$1" ]; then
        echo "error while $1" > /dev/stderr
    fi

    ERR_TYPE="`sed -e 's/.*"type":"\([^"]*\)".*/\1/' "$RESP_BODY"`"
    ERR_DETAILS="`sed -e 's/.*"detail":"\([^"]*\)".*/\1/' "$RESP_BODY"`"

    echo "  $ERR_DETAILS ($ERR_TYPE)" > /dev/stderr
}

# generate the PROTECTED variable, which contains a nonce retrieved from the
# server in the Replay-Nonce header

gen_protected(){
    NONCE="`cat "$LAST_NONCE"`"
    if [ -z "$NONCE" ]; then
        # echo fetch new nonce > /dev/stderr
        curl -D "$LAST_NONCE_FETCH" -o /dev/null -s "$CA/directory"
        handle_curl_exit $? "$CA/directory"

        sed -e '/Replay-Nonce: / ! d; s/^Replay-Nonce: //' "$LAST_NONCE_FETCH" \
            | tr -d '\r\n' \
            > "$LAST_NONCE"

        NONCE="`cat "$LAST_NONCE"`"
        [ -n "$NONCE" ] || die "could not fetch new nonce"
    fi

    PROTECTED="`echo '{"nonce":"'"$NONCE"'"}' \
        | tr -d '\n\r' \
        | base64url`"

    echo | tr -d '\n\r' > "$LAST_NONCE"
}

# generate the signature for the request

gen_signature() {
    printf "%s" "$PROTECTED.$PAYLOAD" > "$OPENSSL_IN"
    openssl dgst -sha256 -binary -sign "$ACCOUNT_KEY" < "$OPENSSL_IN" > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit "$?" "signing request"
    SIGNATURE="`base64url < "$OPENSSL_OUT"`"
}

# helper functions to create the json web key object

key_get_modulus(){
    openssl rsa -in "$1" -modulus -noout > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "extracting account key modulus"

    sed -e 's/^Modulus=//' < "$OPENSSL_OUT" \
        | xxd -r -p \
        | base64url
}

key_get_exponent(){
    openssl pkey -inform perm -in "$1" -noout -text_pub > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "extracting account key exponent"

    sed -e '/Exponent: / ! d; s/Exponent: [0-9]*\s\+(\(\(0\)x\([0-9]\)\|0x\)\(\([0-9][0-9]\)*\))/\2\3\4/' \
        < "$OPENSSL_OUT" \
        | xxd -r -p \
        | base64url
}

# make a request to the specified URI
# the payload is signed by the ACCOUNT_KEY
# the response header is stored in the file $RESP_HEADER, the body in the file $RESP_BODY

send_req(){
    URI="$1"

    gen_protected
    PAYLOAD="`echo "$2" | base64url`"
    gen_signature

    DATA='{"header":'"$REQ_JWKS"',"protected":"'"$PROTECTED"'","payload":"'"$PAYLOAD"'","signature":"'"$SIGNATURE"'"}'

    curl -s -d "$DATA" -D "$RESP_HEADER" -o "$RESP_BODY" "$URI"
    handle_curl_exit $? "$URI"

    # store the nonce for the next request
    sed -e '/Replay-Nonce: / ! d; s/^Replay-Nonce: //' "$RESP_HEADER" | tr -d '\r\n' > "$LAST_NONCE"
}

# account key handling

load_account_key(){
    [ -n "$ACCOUNT_KEY" ] || die "no account key specified"
    [ -r "$ACCOUNT_KEY" ] || die "could not read account key"

    openssl rsa -in "$ACCOUNT_KEY" -noout > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "opening account key"

    ACCOUNT_JWK='{"e":"'"`key_get_exponent $ACCOUNT_KEY`"'","kty":"RSA","n":"'"`key_get_modulus $ACCOUNT_KEY`"'"}'
    REQ_JWKS='{"alg":"RS256","jwk":'"$ACCOUNT_JWK"'}'
    ACCOUNT_THUMB="`echo "$ACCOUNT_JWK" | tr -d '\r\n' | openssl dgst -sha256 -binary | base64url`"
}

register_account_key(){
    log "register account"

    NEW_REG='{"resource":"new-reg","contact":["mailto:'"$ACCOUNT_EMAIL"'"],"agreement":"https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf"}'
    send_req "$CA/acme/new-reg" "$NEW_REG"

    if check_http_status 201; then
        return
    elif check_http_status 409; then
        die "account already exists"
    else
        unhandled_response "registering account"
    fi
}

# This function returns the certificate request in base64url encoding
# arguments: domain ...
#   key: the private key, which is used for the domains
#   domain: a list of domains for which the certificate should be valid

request_challenge_domain(){
    log "request challenge for $DOMAIN"

    NEW_AUTHZ='{"resource":"new-authz","identifier":{"type":"dns","value":"'"$DOMAIN"'"}}'
    send_req "$CA/acme/new-authz" "$NEW_AUTHZ"

    if check_http_status 201; then
        DOMAIN_CHALLENGE="`sed -e '/"http-01"/ ! d; s/.*{\([^}]*"type":"http-01"[^}]*\)}.*/\1/' "$RESP_BODY"`"
        DOMAIN_TOKEN="`echo "$DOMAIN_CHALLENGE" | sed 's/.*"token":"\([^"]*\)".*/\1/'`"
        DOMAIN_URI="`echo "$DOMAIN_CHALLENGE" | sed 's/.*"uri":"\([^"]*\)".*/\1/'`"

        DOMAIN_DATA="$DOMAIN_DATA $DOMAIN $DOMAIN_URI $DOMAIN_TOKEN"
    elif check_http_status 400; then
        # account not registred?
        show_error "requesting challenge for $DOMAIN"
        exit 1
    elif check_http_status 403; then
        # account not registred?
        show_error "requesting challenge for $DOMAIN"
        exit 1
    else
        unhandled_response "requesting challenge for $DOMAIN"
    fi
}

request_challenge(){
    set -- $DOMAINS
    for DOMAIN do
        request_challenge_domain
    done
}

push_domain_response() {
    log "push response for $DOMAIN"

    # do something with DOMAIN, DOMAIN_TOKEN and DOMAIN_RESPONSE
    # echo "$DOMAIN_RESPONSE" > "/writeable/location/$DOMAIN/$DOMAIN_TOKEN"

    if [ -n "$WEBDIR" ]; then
        TOKEN_DIR="`printf "%s" $WEBDIR | sed -e 's/\$DOMAIN/'"$DOMAIN"'/g; s/${DOMAIN}/'"$DOMAIN"'/g'`"
        printf "%s\n" "$DOMAIN_TOKEN.$ACCOUNT_THUMB" > "$TOKEN_DIR/$DOMAIN_TOKEN" || exit 1
    elif [ -n "$PUSH_TOKEN" ]; then
        $PUSH_TOKEN install "$DOMAIN" "$DOMAIN_TOKEN" "$ACCOUNT_THUMB" || die "could not install token for $DOMAIN"
    fi

    return
}

remove_domain_response() {
    log "remove response for $DOMAIN"

    # do something with DOMAIN and DOMAIN_TOKEN
    # rm "/writeable/location/$DOMAIN/$DOMAIN_TOKEN"

    if [ -n "$WEBDIR" ]; then
        TOKEN_DIR="`printf "%s" $WEBDIR | sed -e 's/\$DOMAIN/'"$DOMAIN"'/g; s/${DOMAIN}/'"$DOMAIN"'/g'`"
        rm -f "$TOKEN_DIR/$DOMAIN_TOKEN"
    elif [ -n "$PUSH_TOKEN" ]; then
        $PUSH_TOKEN remove "$DOMAIN" "$DOMAIN_TOKEN" "$ACCOUNT_THUMB" || exit 1
    fi

    return
}

push_response() {
    set -- $DOMAIN_DATA
    while [ -n "$1" ]; do
        DOMAIN="$1"
        DOMAIN_URI="$2"
        DOMAIN_TOKEN="$3"

        shift 3
    
        push_domain_response
    done
}

request_domain_verification() {
    log request verification of $DOMAIN

    send_req $DOMAIN_URI '{"resource":"challenge","type":"http-01","keyAuthorization":"'"$DOMAIN_TOKEN.$ACCOUNT_THUMB"'","token":"'"$DOMAIN_TOKEN"'"}'

    if check_http_status 202; then
        printf ""
    else
        unhandled_response "requesting verification of challenge of $DOMAIN"
    fi
}

request_verification() {
    set -- $DOMAIN_DATA
    
    while [ -n "$1" ]; do
        DOMAIN="$1"
        DOMAIN_URI="$2"
        DOMAIN_TOKEN="$3"
    
        shift 3

        request_domain_verification
    done
}

check_verification() {
    ALL_VALID=true
    
    while [ -n "$DOMAIN_DATA" ]; do
        sleep 1
    
        set -- $DOMAIN_DATA
        DOMAIN_DATA=""
    
        while [ -n "$1" ]; do
            DOMAIN="$1"
            DOMAIN_URI="$2"
            DOMAIN_TOKEN="$3"
        
            shift 3
        
            log check verification of $DOMAIN

            curl -D "$RESP_HEADER" -o "$RESP_BODY" -s "$DOMAIN_URI"
            handle_curl_exit $? "$DOMAIN_URI"
        
            if check_http_status 202; then
                DOMAIN_STATUS="`sed -e 's/.*"status":"\(invalid\|valid\|pending\)".*/\1/' "$RESP_BODY"`"
                case "$DOMAIN_STATUS" in
                    valid)
                        log $DOMAIN is valid
                        remove_domain_response
                        ;;
                    invalid)
                        echo $DOMAIN: invalid > /dev/stderr
                        show_error
                        remove_domain_response

                        ALL_VALID=false
                        ;;
                    pending)
                        log $DOMAIN is pending
                        DOMAIN_DATA="$DOMAIN_DATA $DOMAIN $DOMAIN_URI $DOMAIN_TOKEN"
                        ;;
                    *)
                        unhandled_response "checking verification status of $DOMAIN"
                        ;;
                esac
            else
                unhandled_response "checking verification status of $DOMAIN"
            fi
        done
    done

    $ALL_VALID || exit 1
}

# this function generates the csr from the private server key and list of domains

gen_csr_with_private_key() {
    log generate certificate request

    set -- $DOMAINS

    ALT_NAME="subjectAltName=DNS:$1"
    shift

    while [ -n "$1" ]; do
        ALT_NAME="$ALT_NAME,DNS:$1"
        shift
    done

    cat /etc/ssl/openssl.cnf > "$OPENSSL_CONFIG"
    echo '[SAN]' >> "$OPENSSL_CONFIG"
    echo "$ALT_NAME" >> "$OPENSSL_CONFIG"


    openssl req -new -sha512 -key "$SERVER_KEY" -subj / -reqexts SAN -config $OPENSSL_CONFIG \
        > "$TMP_SERVER_CSR" \
        2> "$OPENSSL_ERR"
    handle_openssl_exit $? "creating certifacte request"
}

csr_extract_domains() {
    log "extract domains from certificate signing request"

    openssl req -in "$TMP_SERVER_CSR" -noout -text \
        > "$OPENSSL_OUT" \
        2> "$OPENSSL_ERR"
    handle_openssl_exit $? "reading certifacte signing request"

    DOMAINS="`sed -n '/X509v3 Subject Alternative Name:/ { n; s/^\s*DNS\s*:\s*//; s/\s*,\s*DNS\s*:\s*/ /g; p; q; }' "$OPENSSL_OUT"`"
}

gen_csr() {
    gen_csr_with_private_key
}

request_certificate(){
    log request certificate

    NEW_CERT="`
            sed -e 's/-----BEGIN CERTIFICATE REQUEST-----/{"resource":"new-cert","csr":"/; s/-----END CERTIFICATE REQUEST-----/"}/;s/+/-/g;s!/!_!g;s/=//g' \
                "$TMP_SERVER_CSR" \
            | tr -d '\r\n' \
    `"

    send_req "$CA/acme/new-cert" "$NEW_CERT"
    
    if check_http_status 201; then
        openssl x509 -inform der -outform pem -in "$RESP_BODY" -out "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
        handle_openssl_exit $? "converting certificate"
        cp -- "$OPENSSL_OUT" "$SERVER_CERT"
    elif check_http_status 429; then
        show_error "requesting certificate"
        exit 1
    else
        unhandled_response "requesting certificate"
    fi
}

usage() {
    cat << 'EOT'
letsencrypt.sh register [-p] -a account_key -e email
letsencrypt.sh thumbprint -a account_key
letsencrypt.sh sign -a account_key -k server_key -c signed_crt domain ...
letsencrypt.sh sign -a account_key -r server_csr -c signed_crt

    -a account_key    the private key
    -e email          the email address assigned to the account key during
                      the registration
    -k server_key     the private key of the server certificate
    -r server_csr     a certificate signing request, which includes the
                      domains, use e.g. gen-csr.sh to create one
    -c signed_crt     the location where to store the signed certificate
    -q                quiet operation

  sign:
    -w webdir         the directory, where the response should be stored
                      $DOMAIN will be replaced by the actual domain
                      the directory will not be created
    -P exec           the command to call to install the token on a remote
                      server
EOT
}

[ $# -gt 0 ] || die "no action given"

ACTION="$1"
shift

SHOW_THUMBPRINT=0

case "$ACTION" in
    register)
        while getopts :hqa:e:p name; do case "$name" in
            h) usage; exit 1;;
            q) QUIET=1;;
            p) SHOW_THUMBPRINT=1;;
            a) ACCOUNT_KEY="$OPTARG";;
            e) ACCOUNT_EMAIL="$OPTARG";;
            ?|:) echo "invalid arguments" > /dev/stderr; exit 1;;
        esac; done;;
    thumbprint)
        while getopts :hqa: name; do case "$name" in
            h) usage; exit 1;;
            q) QUIET=1;;
            a) ACCOUNT_KEY="$OPTARG";;
            ?|:) echo "invalid arguments" > /dev/stderr; exit 1;;
        esac; done;;
    sign)
        while getopts :hqa:k:r:c:w:P: name; do case "$name" in
            h) usage; exit 1;;
            q) QUIET=1;;
            a) ACCOUNT_KEY="$OPTARG";;
            k)
                if [ -n "$SERVER_CSR" ]; then
                    echo "server key and server certificate signing request are mutual exclusive" > /dev/stderr
                    exit 1
                fi
                SERVER_KEY="$OPTARG"
                ACTION=sign-key
                ;;
            r)
                if [ -n "$SERVER_KEY" ]; then
                    echo "server key and server certificate signing request are mutual exclusive" > /dev/stderr
                    exit 1
                fi
                SERVER_CSR="$OPTARG"
                ACTION=sign-csr
                ;;
            c) SERVER_CERT="$OPTARG";;
            w) WEBDIR="$OPTARG";;
            P) PUSH_TOKEN="$OPTARG";;
            ?|:) echo "invalid arguments" > /dev/stderr; exit 1;;
        esac; done;;
    -h|--help|-?)
        usage
        exit 1
        ;;
    *)
        die "invalid action: $ACTION";;
esac

shift $(($OPTIND - 1))

case "$ACTION" in
    register)
        load_account_key
        [ -z "$ACCOUNT_EMAIL" ] && echo "account email address not given" > /dev/stderr && exit 1
        register_account_key
        [ $SHOW_THUMBPRINT -eq 1 ] && printf "account thumbprint: %s\n" "$ACCOUNT_THUMB"
        exit 0;;

    thumbprint)
        load_account_key
        printf "account thumbprint: %s\n" "$ACCOUNT_THUMB"
        exit 0;;

    sign) die "neither server key nor server csr given";;

    sign-key)
        load_account_key
        [ -r "$SERVER_KEY" ] || die "could not read server key"
        [ -n "$SERVER_CERT" ] || die "no output file given"

        [ "$#" -gt 0 ] || die "domains needed"
        ;;

    sign-csr)
        load_account_key
        [ -r "$SERVER_CSR" ] || die "could not read certificate signing request"
        [ -n "$SERVER_CERT" ] || die "no output file given"

        [ "$#" -eq 0 ] || die "no domains needed"

        # load domains from csr
        cat "$SERVER_CSR" > "$TMP_SERVER_CSR" || die "could not copy csr"
        csr_extract_domains
        ;;

    *)
        die "invalid action: $ACTION";;
esac

while [ "$#" -gt 0 ]; do
    DOMAIN="$1"
    validate_domain "$DOMAIN" || die "invalid domain: $DOMAIN"
    DOMAINS="$DOMAINS $DOMAIN"
    shift
done
DOMAINS="`printf "%s" "$DOMAINS" | tr A-Z a-z`"

[ "$ACTION" != "sign-csr" ] && gen_csr

request_challenge
push_response
request_verification
check_verification
request_certificate
