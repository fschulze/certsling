Changelog
=========

0.9.2 - Unreleased
------------------

* Updates for new root certificates.
  [fschulze]

* Output more info for failed authorizations.
  [fschulze]


0.9.1 - 2020-08-23
------------------

* Accept return code 200 for nonce request.
  [witsch]


0.9.0 - 2020-06-14
------------------

* Switch to ACME Version 2 aka RFC 8555 protocol.
  [fschulze]

* Enable ``-h`` for command line help output.
  [fschulze]

* Add option to disable HTTP challenge.
  [fschulze]

* Only start servers for enabled challenges.
  [fschulze]

* Drop Python 3.4 support.
  Python 3.5 support will end at it's EOL in September 2020.
  [fschulze]

* Exit when no domain was provided.
  [fschulze]

* Add ``-y`` option to automatically answer yes for any question.


0.8.0 - 2017-01-04
------------------

* Add new ``--update`` (``-u``) option to avoid having to remember the settings
  for each domain.
  [fschulze]

* Ask to repeat csr and crt generation on failure.
  [solidgoldbomb]

* Switch to dnspython after it merged with dnspython3.
  [fschulze]


0.7.0 - 2016-12-30
------------------

* Renamed to ``certsling``.
  [fschulze]

* Use symmetric difference in ``verify_domains``. This catches problems due to
  typos in domain names and some other cases.
  [solidgoldbomb]

* Update list of issuer names checked in ``verify_crt``.
  [solidgoldbomb (Stacey Sheldon)]

* More detailed error reporting.
  [fschulze]

* Ask to agree to terms of use of letsencrypt and allow updating the registration.
  [fschulze]


0.6.0 - 2016-05-09
------------------

* Upgrade to new X3 authority.
  [fschulze]


0.5.0 - 2016-02-12
------------------

* Allow selection of letsencrypt.org staging server with ``-s`` option.
  [fschulze]


0.4.1 - 2016-01-29
------------------

* Fix issue that the ``-chained.crt`` file wasn't updated.
  [fschulze]


0.4.0 - 2016-01-12
------------------

* Initial release
  [fschulze]
