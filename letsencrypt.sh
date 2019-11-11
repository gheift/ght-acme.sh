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

trap 'rm -f "$RESP_HEABOD $WGET_OUT $RESP_HEADER" "$RESP_BODY" "$OPENSSL_CONFIG" "$OPENSSL_IN" "$OPENSSL_OUT" "$OPENSSL_ERR" "$TMP_SERVER_CSR"' 0 2 3 9 11 13 15

# file to store header and body of http response
RESP_HEABOD="`mktemp -t le.$$.resp-heabod.XXXXXX`"
# file to store the output of the wget
WGET_OUT="`mktemp -t le.$$.resp-out.XXXXXX`"
# file to store header of http request
RESP_HEADER="`mktemp -t le.$$.resp-header.XXXXXX`"
# file to store body of http request
RESP_BODY="`mktemp -t le.$$.resp-body.XXXXXX`"
# tmp config for openssl for addional domains
OPENSSL_CONFIG="`mktemp -t le.$$.openssl.cnf.XXXXXX`"
# file to store openssl output
OPENSSL_IN="`mktemp -t le.$$.openssl.in.XXXXXX`"
OPENSSL_OUT="`mktemp -t le.$$.openssl.out.XXXXXX`"
OPENSSL_ERR="`mktemp -t le.$$.openssl.err.XXXXXX`"
# file to store the CSR
TMP_SERVER_CSR="`mktemp -t le.$$.server.csr.XXXXXX`"

CADIR="https://acme-staging-v02.api.letsencrypt.org/directory"

# Prefix the following line with "# letsencrypt-production-server #", to use
# the staging server of letsencrypt. The staging server has lower rate limits,
# but does not issue valid certificates. To automatically remove the comment
# again on commiting the file, add the filter to your git config by running
#   git config filter.production-server.clean misc/filter-production-server

CADIR="https://acme-v02.api.letsencrypt.org/directory"

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

# the script to be called to push the response to a remote server needs the commit feature
PUSH_TOKEN_COMMIT=

# set the option of the preferred IP family for connecting to the boulder server
IPV_OPTION=

# the challenge type, can be dns-01 or http-01 (default)
CHALLENGE_TYPE="http-01"

# the date of the that version
VERSION_DATE="2019-11-11"

# The meaningful User-Agent to help finding related log entries in the boulder server log
USER_AGENT="bruncsak/ght-acme.sh $VERSION_DATE"

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
    RETCODE="$?"
    [ -n "$2" ] && RETCODE="$2"
    [ -n "$1" ] && printf "%s\n" "$1" > /dev/stderr
    exit "$RETCODE"
}

validate_domain() {
    DOMAIN_IN="$1"
    if [ "$DOMAIN_IN" = _ ]; then
        return 1
    fi

    DOMAIN_OUT="`printf "%s\n" "$DOMAIN_IN" | sed -e 's/^...$/!/; s/^.\{254,\}$/!/; s/^\([a-zA-Z0-9]\([-a-zA-Z0-9]\{0,61\}[a-zA-Z0-9]\)\{0,1\}\.\)\{1,\}[a-zA-Z]\{2,63\}$/_/;'`"

    if [ "$DOMAIN_OUT" = _ ]; then
        return 0
    else
        return 1
    fi
}

fetch_location() {
sed -e '/^Location: / !d; s/Location: //' "$RESP_HEADER" | tr -d '\r\n'
}

handle_wget_exit() {
    WGET_EXIT="$1"
    WGET_URI="$2"

    if [ "$WGET_EXIT" "!=" 0 -o -s "$WGET_OUT" ]; then
        echo "error while making a web request to \"$WGET_URI\"" > /dev/stderr
        echo "wget exit status: $WGET_EXIT" > /dev/stderr
        case "$WGET_EXIT" in
        esac

        cat "$WGET_OUT" > /dev/stderr
        cat "$RESP_HEABOD" > /dev/stderr

        exit 1
    fi

    tr -d '\r' < "$RESP_HEABOD" | sed -e '/^$/,$d' > "$RESP_HEADER"
    tr -d '\r' < "$RESP_HEABOD" | sed -e '1,/^$/d' > "$RESP_BODY"
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
    egrep -s -q -e "^HTTP/[0-9.]+ $1 " "$RESP_HEADER"
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

# retrieve the nonce from the response header of the previous request for the forthcomming request

extract_nonce() {
    sed -e '/Replay-Nonce: / !d; s/^Replay-Nonce: //' "$RESP_HEADER" | tr -d '\r\n'
}

# generate the PROTECTED variable, which contains a nonce retrieved from the
# server in the Replay-Nonce header

gen_protected(){
    NONCE="`extract_nonce`"
    if [ -z "$NONCE" ]; then
        # echo fetch new nonce > /dev/stderr
        send_get_req "$NEWNONCEURL"

        NONCE="`extract_nonce`"
        [ -n "$NONCE" ] || die "could not fetch new nonce"
    fi

    if [ -z "$KID" ]; then
        echo '{"alg":"RS256","jwk":'"$ACCOUNT_JWK"',"nonce":"'"$NONCE"'","url":"'"$1"'"}'
    else
        echo '{"alg":"RS256","kid":"'"$KID"'","nonce":"'"$NONCE"'","url":"'"$1"'"}'
    fi
}

# generate the signature for the request

gen_signature() {
    printf "%s" "$PROTECTED.$PAYLOAD" > "$OPENSSL_IN"
    openssl dgst -sha256 -binary -sign "$ACCOUNT_KEY" < "$OPENSSL_IN" > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    # echo "$OPENSSL_OUT: " ; cat -t "$OPENSSL_OUT"
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
    openssl rsa -in "$1" -text -noout > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "extracting account key exponent"

    sed -e '/^publicExponent: / !d; s/^publicExponent: [0-9]* \{1,\}(\(.*\)).*$/\1/;s/^0x\([0-9a-fA-F]\)\(\([0-9a-fA-F][0-9a-fA-F]\)*\)$/0x0\1\2/;s/^0x\(\([0-9a-fA-F][0-9a-fA-F]\)*\)$/\1/' \
        < "$OPENSSL_OUT" \
        | xxd -r -p \
        | base64url
}

# make a request to the specified URI
# the payload is signed by the ACCOUNT_KEY
# the response header is stored in the file $RESP_HEADER, the body in the file $RESP_BODY

send_req_no_kid(){
    URI="$1"

      PAYLOAD="`         echo "$2" | tr -d '\n\r' | base64url`"
    PROTECTED="`gen_protected "$URI" | tr -d '\n\r' | base64url`"
    gen_signature

    DATA='{"protected":"'"$PROTECTED"'","payload":"'"$PAYLOAD"'","signature":"'"$SIGNATURE"'"}'

    if [ "$USE_WGET" != yes ] ;then
        curl -s $IPV_OPTION -A "$USER_AGENT" -D "$RESP_HEADER" -o "$RESP_BODY" -H "Content-type: application/jose+json" -d "$DATA" "$URI"
        handle_curl_exit $? "$URI"
    else
        wget -q --retry-connrefused   $IPV_OPTION -U "$USER_AGENT" --save-headers  -O "$RESP_HEABOD" --header="Content-type: application/jose+json" --post-data="$DATA" "$URI" > "$WGET_OUT" 2>& 1
        handle_wget_exit $? "$URI"
    fi

    if ! check_http_status 400; then
        return
    elif ! fgrep -q 'urn:ietf:params:acme:error:badNonce' "$RESP_BODY" ; then
        return
    fi
    echo "badNonce error: other than extrem load on the boulder server," > /dev/stderr
    echo "this is mostly due to multiple client egress IP addresses," > /dev/stderr
    echo "including working IPv4 and IPv6 addresses on dual family systems." > /dev/stderr
    echo "In that case as a workaround please try to restrict the egress" > /dev/stderr
    echo "IP address with the -4 or -6 command line option on the script." > /dev/stderr
    exit 1
}

send_req(){
    URI="$1"

    [ -z "$KID" ] && register_account_key retrieve_kid

    send_req_no_kid "$1" "$2"
}

send_get_req(){
    GET_URI="$1"

    if [ "$USE_WGET" != yes ] ;then
        curl -s $IPV_OPTION -A "$USER_AGENT" -D "$RESP_HEADER" -o "$RESP_BODY" "$GET_URI"
        handle_curl_exit $? "$GET_URI"
    else
        wget -q --retry-connrefused   $IPV_OPTION -U "$USER_AGENT" --save-headers  -O "$RESP_HEABOD" "$GET_URI" > "$WGET_OUT" 2>& 1
        handle_wget_exit $? "$GET_URI"
    fi
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

get_urls(){
    send_get_req "$CADIR"

    egrep -s -q -e '"newNonce"' "$RESP_BODY" &&
    NEWNONCEURL="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"newNonce":"\([^"]*\)".*/\1/')"

    egrep -s -q -e '"newAccount"' "$RESP_BODY" &&
    NEWACCOUNTURL="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"newAccount":"\([^"]*\)".*/\1/')"

    egrep -s -q -e '"newOrder"' "$RESP_BODY" &&
    NEWORDERURL="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"newOrder":"\([^"]*\)".*/\1/')"

    egrep -s -q -e '"revokeCert"' "$RESP_BODY" &&
    REVOKECERTURL="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"revokeCert":"\([^"]*\)".*/\1/')"

    egrep -s -q -e '"keyChange"' "$RESP_BODY" &&
    KEYCHANGEURL="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"keyChange":"\([^"]*\)".*/\1/')"
}

register_account_key(){

    [ -n "$NEWACCOUNTURL" ] || get_urls
    NEW_REG='{"termsOfServiceAgreed":true,"contact":["mailto:'"$ACCOUNT_EMAIL"'"]}'
    send_req_no_kid "$NEWACCOUNTURL" "$NEW_REG"

    if check_http_status 200; then
        KID="`fetch_location`"
        [ "$1" = "retrieve_kid" ] || echo "account already registered" > /dev/stderr
        return
    elif check_http_status 201; then
        KID="`fetch_location`"
        return
    elif check_http_status 409; then
        [ "$1" = "nodie" ] || die "account already exists"
    else
        unhandled_response "registering account"
    fi
}

delete_account_key(){
    log "delete account"

    REG='{"resource":"reg","delete":"true"}'
    send_req "$REGISTRATION_URI" "$REG"

    if check_http_status 200; then
        return
    else
        unhandled_response "deleting account"
    fi
}

# This function returns the certificate request in base64url encoding
# arguments: domain ...
#   key: the private key, which is used for the domains
#   domain: a list of domains for which the certificate should be valid

request_challenge_domain(){

    send_req "$DOMAIN_AUTHZ" ""

    if check_http_status 200; then
        DOMAIN="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e '/"status":"pending"/ !d; s/.*"identifier":{"type":"dns","value":"\([^"]*\)"}.*/\1/')"
        if [ -n "$DOMAIN" ] ;then
            DOMAIN_CHALLENGE="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e '/"'"$CHALLENGE_TYPE"'"/ !d; s/.*{\([^}]*"type":"'"$CHALLENGE_TYPE"'"[^}]*\)}.*/\1/')"
            DOMAIN_TOKEN="$(echo "$DOMAIN_CHALLENGE" | sed 's/.*"token":"\([^"]*\)".*/\1/')"
            DOMAIN_URI="$(echo "$DOMAIN_CHALLENGE" | sed 's/.*"url":"\([^"]*\)".*/\1/')"

            DOMAIN_DATA="$DOMAIN_DATA $DOMAIN $DOMAIN_URI $DOMAIN_TOKEN $DOMAIN_AUTHZ"
            log "retrieve challenge for $DOMAIN"
        fi
    elif check_http_status 400; then
        # account not registred?
        show_error "retrieve challenge for URL: $DOMAIN_AUTHZ"
        exit 1
    elif check_http_status 403; then
        # account not registred?
        show_error "retrieve challenge for URL: $DOMAIN_AUTHZ"
        exit 1
    else
        unhandled_response "retrieve challenge for URL: $DOMAIN_AUTHZ"
    fi
}

request_challenge(){
    log "creating new order"

    set -- $DOMAINS
    for DOMAIN do
         [ -n "$DOMAIN_ORDERS" ] && DOMAIN_ORDERS="$DOMAIN_ORDERS,"
         DOMAIN_ORDERS="$DOMAIN_ORDERS"'{"type":"dns","value":"'"$DOMAIN"'"}'
    done

    NEW_ORDER='{"identifiers":['"$DOMAIN_ORDERS"']}'
    send_req "$NEWORDERURL" "$NEW_ORDER"
    if check_http_status 201; then
        DOMAIN_AUTHZ_LIST="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/^.*"authorizations":\[\([^]]*\)\].*$/\1/' | tr -d '"' | tr ',' ' ')"
        FINALIZE="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/^.*"finalize":"\([^"]*\).*$/\1/')"
    else
        unhandled_response "requesting new order for $DOMAINS"
    fi
    set -- $DOMAIN_AUTHZ_LIST
    for DOMAIN_AUTHZ do
        request_challenge_domain
    done

}

domain_commit() {
    if [ -n "$PUSH_TOKEN" ] && [ -n "$PUSH_TOKEN_COMMIT" ]; then
        log "calling $PUSH_TOKEN commit"
        $PUSH_TOKEN commit || die "$PUSH_TOKEN could not commit"
        # We cannot know how long the execution of an external command will take.
        # Safer to force fetching a new nonce to avoid fatal badNonce error due to nonce validity timeout.
        > "$RESP_HEADER"
    fi
}

domain_dns_challenge() {
    DNS_CHALLENGE="`printf "%s\n" "$DOMAIN_TOKEN.$ACCOUNT_THUMB" | tr -d '\r\n' | openssl dgst -sha256 -binary | base64url`"
    if [ -n "$PUSH_TOKEN" ]; then
        $PUSH_TOKEN "$1" _acme-challenge."$DOMAIN" "$DNS_CHALLENGE" || die "Could not $1 $CHALLENGE_TYPE type challenge token with value $DNS_CHALLENGE for domain $DOMAIN via $PUSH_TOKEN"
    else
        printf 'update %s _acme-challenge.%s. 300 IN TXT "%s"\n\n' "$1" "$DOMAIN" "$DNS_CHALLENGE" |
            nsupdate || die "Could not $1 $CHALLENGE_TYPE type challenge token with value $DNS_CHALLENGE for domain $DOMAIN via nsupdate"
    fi
}

push_domain_response() {
    log "push response for $DOMAIN"

    # do something with DOMAIN, DOMAIN_TOKEN and DOMAIN_RESPONSE
    # echo "$DOMAIN_RESPONSE" > "/writeable/location/$DOMAIN/$DOMAIN_TOKEN"

    if [ "$CHALLENGE_TYPE" = "http-01" ]; then
        if [ -n "$WEBDIR" ]; then
            TOKEN_DIR="`printf "%s" $WEBDIR | sed -e 's/\$DOMAIN/'"$DOMAIN"'/g; s/${DOMAIN}/'"$DOMAIN"'/g'`"
            printf "%s\n" "$DOMAIN_TOKEN.$ACCOUNT_THUMB" > "$TOKEN_DIR/$DOMAIN_TOKEN" || exit 1
        elif [ -n "$PUSH_TOKEN" ]; then
            $PUSH_TOKEN install "$DOMAIN" "$DOMAIN_TOKEN" "$ACCOUNT_THUMB" || die "could not install token for $DOMAIN"
        fi
    elif [ "$CHALLENGE_TYPE" = "dns-01" ]; then
        domain_dns_challenge "add"
    else
        # May be tls-sni-02?
        echo "unsupported challenge type for install (but in progress): $CHALLENGE_TYPE" > /dev/stderr; exit 1
    fi

    return
}

remove_domain_response() {
    log "remove response for $DOMAIN"

    # do something with DOMAIN and DOMAIN_TOKEN
    # rm "/writeable/location/$DOMAIN/$DOMAIN_TOKEN"

    if [ "$CHALLENGE_TYPE" = "http-01" ]; then
        if [ -n "$WEBDIR" ]; then
            TOKEN_DIR="`printf "%s" $WEBDIR | sed -e 's/\$DOMAIN/'"$DOMAIN"'/g; s/${DOMAIN}/'"$DOMAIN"'/g'`"
            rm -f "$TOKEN_DIR/$DOMAIN_TOKEN"
        elif [ -n "$PUSH_TOKEN" ]; then
            $PUSH_TOKEN remove "$DOMAIN" "$DOMAIN_TOKEN" "$ACCOUNT_THUMB" || exit 1
        fi
    elif [ "$CHALLENGE_TYPE" = "dns-01" ]; then
        domain_dns_challenge "delete"
    else
        # May be tls-sni-02?
        echo "unsupported challenge type for remove (but in progress): $CHALLENGE_TYPE" > /dev/stderr; exit 1
    fi

    return
}

push_response() {
    set -- $DOMAIN_DATA
    while [ -n "$1" ]; do
        DOMAIN="$1"
        DOMAIN_URI="$2"
        DOMAIN_TOKEN="$3"
        DOMAIN_AUTHZ="$4"

        shift 4
    
        push_domain_response
    done
    domain_commit
}

request_domain_verification() {
    log request verification of $DOMAIN

    send_req $DOMAIN_URI '{}'

    if check_http_status 200; then
        return
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
        DOMAIN_AUTHZ="$4"
    
        shift 4

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
            DOMAIN_AUTHZ="$4"
        
            shift 4
        
            log check verification of $DOMAIN

            send_req "$DOMAIN_AUTHZ" ""
        
            if check_http_status 200; then
                DOMAIN_STATUS="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"type":"'"$CHALLENGE_TYPE"'","status":"\([^"]*\)".*/\1/')"
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
                        DOMAIN_DATA="$DOMAIN_DATA $DOMAIN $DOMAIN_URI $DOMAIN_TOKEN $DOMAIN_AUTHZ"
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
    domain_commit

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

    if [ -r /etc/ssl/openssl.cnf ]; then
        cat /etc/ssl/openssl.cnf > "$OPENSSL_CONFIG"
    else
        cat /etc/pki/tls/openssl.cnf > "$OPENSSL_CONFIG"
    fi
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

    DOMAINS="`sed -n '/X509v3 Subject Alternative Name:/ { n; s/^[	 ]*DNS[	 ]*:[	 ]*//; s/[	 ]*,[	 ]*DNS[	 ]*:[	 ]*/ /g; p; q; }' "$OPENSSL_OUT"`"
    # echo "$DOMAINS"; exit
    if [ -z "$DOMAINS" ]; then
        DOMAINS="`sed -n '/Subject:/ {s/^.*CN=//; s/,*[	 ]*$//; p}' "$OPENSSL_OUT"`"
    fi
}

gen_csr() {
    gen_csr_with_private_key
}

request_certificate(){
    log finalize order

    NEW_CERT="$(
            sed -e 's/-----BEGIN\( NEW\)\{0,1\} CERTIFICATE REQUEST-----/{"csr":"/; s/-----END\( NEW\)\{0,1\} CERTIFICATE REQUEST-----/"}/;s/+/-/g;s!/!_!g;s/=//g' \
                "$TMP_SERVER_CSR" \
            | tr -d '\r\n' \
    )"
    while : ;do
        send_req "$FINALIZE" "$NEW_CERT"
    
        if check_http_status 200; then
            ORDER_STATUS="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"status":"\([^"]*\)".*/\1/')"
            case "$ORDER_STATUS" in
                valid)
                    log order is valid
                    CERTIFICATE="$(tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"certificate":"\([^"]*\)".*/\1/')"
                    break
                    ;;
                processing)
                    echo order: "$ORDER_STATUS" > /dev/stderr
                    sleep 1
                    continue
                    ;;
                invalid|pending|ready)
                    echo order: "$ORDER_STATUS" > /dev/stderr
                    exit 1
                    ;;
                *)
                    unhandled_response "checking verification status of order"
                    ;;
            esac
        else
            unhandled_response "requesting order finalization"
        fi
    done
    log request certificate
    send_req "$CERTIFICATE" ""
    if check_http_status 200; then
        sed -e '/^$/,$d' "$RESP_BODY" > "$SERVER_CERT"
        sed -e '1,/^$/d' "$RESP_BODY" > "$SERVER_CERT"_chain
    else
        unhandled_response "retrieveing certificate"
    fi
}

usage() {
    cat << 'EOT'
letsencrypt.sh register [-4|-6] [-p] -a account_key -e email
letsencrypt.sh delete [-4|-6] -a account_key
letsencrypt.sh thumbprint -a account_key
letsencrypt.sh sign [-4|-6] -a account_key -k server_key -c signed_crt domain ...
letsencrypt.sh sign [-4|-6] -a account_key -r server_csr -c signed_crt

    -a account_key    the private key
    -e email          the email address assigned to the account key during
                      the registration
    -k server_key     the private key of the server certificate
    -r server_csr     a certificate signing request, which includes the
                      domains, use e.g. gen-csr.sh to create one
    -c signed_crt     the location where to store the signed certificate
    -l challenge_type can be dns-01 or http-01 (default)
    -q                quiet operation
    -4                the connection to the server should use IPv4
    -6                the connection to the server should use IPv6

  sign:
    -w webdir         the directory, where the response should be stored
                      $DOMAIN will be replaced by the actual domain
                      the directory will not be created
    -P exec           the command to call to install the token on a remote
                      server
    -C                the command to call to install the token on a remote
                      server needs the commit feature
EOT
}

[ $# -gt 0 ] || die "no action given"

ACTION="$1"
shift

SHOW_THUMBPRINT=0

case "$ACTION" in
    delete)
        while getopts :hq46a: name; do case "$name" in
            h) usage; exit 1;;
            q) QUIET=1;;
            4) IPV_OPTION="-4";;
            6) IPV_OPTION="-6";;
            a) ACCOUNT_KEY="$OPTARG";;
            ?|:) echo "invalid arguments" > /dev/stderr; exit 1;;
        esac; done;;
    register)
        while getopts :hq46a:e:p name; do case "$name" in
            h) usage; exit 1;;
            q) QUIET=1;;
            4) IPV_OPTION="-4";;
            6) IPV_OPTION="-6";;
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
        while getopts :hq46Ca:k:r:c:w:P:l: name; do case "$name" in
            h) usage; exit 1;;
            q) QUIET=1;;
            4) IPV_OPTION="-4";;
            6) IPV_OPTION="-6";;
            C) PUSH_TOKEN_COMMIT=1;;
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
            l) CHALLENGE_TYPE="$OPTARG";;
            ?|:) echo "invalid arguments" > /dev/stderr; exit 1;;
        esac; done;;
    -h|--help|-?)
        usage
        exit 1
        ;;
    *)
        die "invalid action: $ACTION" 1 ;;
esac

shift $(($OPTIND - 1))

case "$CHALLENGE_TYPE" in
  http-01) ;;
  dns-01)  ;;
  tls-sni-02)  ;;
  *) echo "unsupported challenge type: $CHALLENGE_TYPE" > /dev/stderr; exit 1;;
esac

case "$ACTION" in
    delete)
        load_account_key
        register_account_key nodie
        REGISTRATION_URI="`fetch_location`"
        delete_account_key
        exit 0;;

    register)
        load_account_key
        [ -z "$ACCOUNT_EMAIL" ] && echo "account email address not given" > /dev/stderr && exit 1
        log "register account"
        register_account_key
        [ $SHOW_THUMBPRINT -eq 1 ] && printf "account thumbprint: %s\n" "$ACCOUNT_THUMB"
        exit 0;;

    thumbprint)
        load_account_key
        printf "account thumbprint: %s\n" "$ACCOUNT_THUMB"
        exit 0;;

    sign) die "neither server key nor server csr given" 1 ;;

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
        die "invalid action: $ACTION" 1 ;;
esac

while [ "$#" -gt 0 ]; do
    DOMAIN="$1"
    validate_domain "$DOMAIN" || die "invalid domain: $DOMAIN"
    DOMAINS="$DOMAINS $DOMAIN"
    shift
done
DOMAINS="`printf "%s" "$DOMAINS" | tr A-Z a-z`"

[ "$ACTION" != "sign-csr" ] && gen_csr

get_urls
request_challenge
push_response
request_verification
check_verification
request_certificate
