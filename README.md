# letsencrypt.sh

This script is used to run the required steps to let letsencrypt sign a server
certificate for certain domains.

For the most basic workflow an account key must be created and the private key
of the server must be available.  The following example is for a nginx server,
because it is the easiest to setup.

## Create an Account 

letsencrypt needs an account key for verification of domains and requesting the
signed certificate. If such a key already exists and is registered, the
following steps can be skipped.

create an account key:

`# umask 0177`  
`# openssl genrsa -out account.key 4096`  
`# umask 0022`

register the account key to the letsencrypt service

`# ./letsencrypt.sh register -a account.key -e webmaster@example.org`

## Setup Challenge Response

To verify a domain the letsencrypt service gives you a challenge, to which a
response must be stored under this domain.

The response is a simple concatenation of a challenge token, a dot ".", and the
thumbprint of the account with which the verification request was made. This
must be stored at a well known location.

The thumbprint of the private account key can be obtained with this command:

`# ./letsencrypt.sh thumbprint -a account.key`

With this thumbprint nginx can be configured to create a valid response
dynamically. The following configuration must be added to the server section of
each domain to be validated:

```
location ~ "^/\.well-known/acme-challenge/([-_a-zA-Z0-9]*)$" {
    default_type text/plain;
    return 200 "$1.ACCOUNT_THUMBPRINT";
}
```

The string ACCOUNT_THUMBPRINT in the return statement must be replaced by the
actual thumbprint of the account key. Please note that the verification service
of letsencrypt asks for the response over a HTTP and not over a HTTPS
connection. Do not forget to reload the configuration.

## Request a Signed Certificate

When every domain for which the certificate should be used is setup,
the signing of the certificate can be requested:

`# /.letsencrypt.sh sign -a account.key -k server.key -c server.pem www.example.org www1.example.org example.org`

If the script runs successfully the signed certificate is stored in the file
server.pem and can be used with the server. Please note that the file only
contains the signed server certificate and not the complete chain, which might
be needed by some servers.

## Renew a Certificates

This is done like the first signing request:

`# /.letsencrypt.sh sign account.key -k server.key -c server.pem www.example.org www1.example.org example.org`
