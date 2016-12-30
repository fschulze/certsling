Changelog
=========

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
