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

trap 'rm -f "$OPENSSL_CONFIG" "$OPENSSL_IN" "$OPENSSL_OUT" "$OPENSSL_ERR"' 0 2 3 9 11 13 15

# tmp config for openssl for addional domains
OPENSSL_CONFIG="`mktemp -t gen-csr.$$.openssl.cnf.XXXXXX`"
# file to store openssl output
OPENSSL_IN="`mktemp -t gen-csr.$$.openssl.in.XXXXXX`"
OPENSSL_OUT="`mktemp -t gen-csr.$$.openssl.out.XXXXXX`"
OPENSSL_ERR="`mktemp -t gen-csr.$$.openssl.err.XXXXXX`"

# global variables:

# the private key, which should be signed by the CA
SERVER_KEY=

# the location, where the certificate signing request should be stored
SERVER_CSR=

# a list of domains, which should be assigned to the certificate
DOMAINS=

QUIET=

# utility functions

base64url() {
    openssl base64 | tr '+/' '-_' | tr -d '\r\n='
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

log() {
    if [ -z "$QUIET" ]; then
        echo "$@" > /dev/stderr
    fi
}

# this function generates the csr from the private server key and a list of domains

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
        > "$OPENSSL_OUT" \
        2> "$OPENSSL_ERR"
    handle_openssl_exit $? "creating certifacte request"
}

usage() {
    cat << EOT
gen-csr.sh [-q] -k server_key [-R server_csr] domain ...
    -q                quiet operation
    -k server_key     the private key of the server certificate
    -R server_csr     the location where to store the certificate request
                      if not specified, printed to stdout
                      if not writeable, printed to stderr
EOT
}

DO_REGISTER=
PRINT_THUMB=

while getopts hqk:R: name; do
    case "$name" in
        h) usage; exit;;
        q) QUIET=1;;
        k) SERVER_KEY="$OPTARG";;
        R) SERVER_CSR="$OPTARG";;
    esac
done

shift $(($OPTIND - 1))

if [ -z "$SERVER_KEY" ]; then
    echo no server key specified > /dev/stderr
    exit 1
fi

if [ '!' -r "$SERVER_KEY" ]; then
    echo could not read server key > /dev/stderr
    exit 1
fi

if [ -z "$1" ]; then
    echo "need at least on domain" > /dev/stderr
    exit 1
fi

while [ -n "$1" ]; do
    DOMAIN="$1"
    if validate_domain "$DOMAIN"; then true; else
        echo invalid domain: $DOMAIN > /dev/stderr
        exit 1
    fi
    DOMAINS="$DOMAINS $DOMAIN"
    shift
done
DOMAINS="`printf "%s" "$DOMAINS" | tr A-Z a-z`"

# CSR will be stored in OPENSSL_OUT
gen_csr_with_private_key

if [ -z "$SERVER_CSR" ]; then
    cat "$OPENSSL_OUT"
else
    mv "$OPENSSL_OUT" "$SERVER_CSR"
    if [ "$?" '!=' 0 ]; then
        [ -r "$OPENSSL_OUT" ] && cat "$OPENSSL_OUT" > /dev/stderr
    fi
fi
