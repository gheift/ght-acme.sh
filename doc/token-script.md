# Token Publishing

If the server, which needs to publish the token for verification is neither
setup to generate the reponses dynamicly or accessable by a local path, in
which the letsencrypt.sh script can write to, it can be setup to call a script
for every domain, which needs a verification.

The script can be specified with the -P option of the letsencrypt.sh tool:

`letsencrypt.sh -P path/to/script ...`

The script itself is called with 4 arguments

`script action domain token thumbprint`

which can be used to publish the response on the correct server.

  action      either install or remove, based when the script is called
  domain      the domain for which the response should be added or removed
  token       the token under which the response is expected
  thumbprint  the thumbprint of the account key
