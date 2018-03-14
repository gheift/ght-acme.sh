# Token Publishing

If the server, which needs to publish the token for verification is neither
setup to generate the reponses dynamicly or accessable by a local path, in
which the letsencrypt.sh script can write to, it can be setup to call a script
for every domain, which needs a verification.

The script can be specified with the -P option of the letsencrypt.sh tool:

`letsencrypt.sh [-l {dns-01|http-01}] [-C] -P path/to/script ...`

With the -l option it is possible to select the challenge type
between dns-01 or http-01 (default).

The -C option permits the use of the commit feature for the script.
At the commit call the script is supposed to execute
the result of the accomulated previous calls in a batch.
In that case the script will be called with one argument
having the value "commit" at the appropriate check-point:

`script commit`

Usefull especially for the dns-01 challenge type
if there are many records to handle in the same DNS zone.

http-01 challenge type:

The script itself is called with 4 arguments

`script action domain token thumbprint`

which can be used to publish the response on the correct server.

  action      either install or remove, based when the script is called
  domain      the domain for which the response should be added or removed
  token       the token under which the response is expected
  thumbprint  the thumbprint of the account key

dns-01 challenge type:

The script itself is called with 3 arguments

`script action domain challenge`

which can be used to update the response on the DNS server.

  action      either add or delete, based when the script is called
  domain      the domain for which the DNS record should be added or deleted
  challenge   the value of the TXT type record for which the response is expected
