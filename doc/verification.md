# Domain Verification

## Dynamic Response Creation

The easiest way to serve the response for the challenge is to create it dynamcly.
With the http-01 verification the service asks for a file under the location
 http://www.example.com/.well-known/acme-challenge/random-token whereby the
random-token part is provided by the service. The content of this file is a
concatenation of the token, a dot ".", and the thumbprint of the account key,
which requested the verification.

If the account key does not change, which should be the normal case, the
response can be generated on the fly without knowing the private key of the
account or the server. There are a vew ways do configure the server to create
such a response.

### nginx

The easiest way to serve the responses for the challenges is by using nginx.
For each server section in the configuration file, for which vaild responses
should be served, the following section must be added. The THUMBPRINT part in
the return statement must be replaced by the thumbprint of the account key,
which is used to request validation.

```
location ~ "^/\.well-known/acme-challenge/([-_a-zA-Z0-9]*)$" {
    default_type text/plain;
    return 200 "$1.THUMBPRINT";
}
```

### apache

*This is not yet tested! Only to give a slightly idea how this could be implemented.*

For apache httpd server, an additional script is needed, which generates the
response. This could be either a SSI file, a PHP script, a CGI-BIN script or
any other script.

This script must prefix the THUMBPRINT of the account key with the token used
in the URI to request the response. Example scripts for this are located in the
contrib directory.

In the apache configuration a rewrite has to be added, to call the script for
the challenge.

```
AliasMatch "^/\.well-known/acme-challenge/" "/path/to/script/"
<Directory /path/to/script/>
    RewriteEngine On
    RewriteBase /.well-known/acme-challenge/
    RewriteRule "^([-_a-zA-Z0-9]+)$" script-name [E=ACME_TOKEN:$1]
</Directory>
```

The script only has to output the token concatenated with the account key thumbprint.

`<? header('Content-Type: text/plain'); echo $_ENV['ACME_TOKEN'] ?>.THUMBPRINT`

