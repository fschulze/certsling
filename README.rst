letsencrypt-remote
==================

.. warning::
    letsencrypt-remote has been renamed to `certsling`_.
    Install that package for further updates.

An opinionated script to sign tls keys via `letsencrypt`_ on your local computer by forwarding the HTTP challenge via ssh.

.. _certsling: https://pypi.python.org/pypi/certsling
.. _letsencrypt: https://letsencrypt.org


Installation
------------

Best installed via `pipsi`_::

    % pipsi install letsencrypt-remote

Or some other way to install a python package with included scripts.

.. _pipsi: https://pypi.python.org/pypi/pipsi


Requirements
------------

You need an ``openssl`` executable in your path for key generation and signing.


Testing with staging server
---------------------------

With the ``-s`` option you can use the staging server of `letsencrypt`_.
This is advised, so you don't run into quota limits or similar until your setup works.
The resulting certificate won't validate, but otherwise has the same content as a regular certificate.


Basic usage
-----------

Create a directory with the email address as the name, which you want to use for authentication with letsencrypt.
For example ``webmaster@example.com``::

    % mkdir webmaster@example.com

Create a ssh connection to your server which forwards a remote port to the local port ``8080``::

    % ssh root@example.com -R 8080:localhost:8080

On your server the webserver needs to proxy requests to ``example.com:80/.well-known/acme-challenge/*`` to that forwarded port.
An example for nginx::

        location /.well-known/acme-challenge/ {
            proxy_pass http://localhost:8080;
        }

From the directory you created earlier, invoke the ``letsencrypt-remote`` script with for example::

    % cd webmaster@example.com
    % letsencrypt-remote example.com www.example.com

On first run, you are asked whether to create a ``user.key`` for authorization with letsencrypt.

After that, challenges for the selected domains are created and a server is started on port ``8080`` to provide responses.
Your remote web server proxies them through the ssh connection to the locally running server.

If all went well, you get a server key and certificate in a new ``example.com`` folder::

    % ls example.com
    ...
    example.com-chained.crt
    example.com.crt
    example.com.key

The ``example.com-chained.crt`` file contains the full chain of you certificate together with the letsencrypt certificate.


Advanced usage
--------------

To use DNS based authentication, you need to have ``socat`` on your server.
Additionally you need to setup your DNS, so it delegates ``_acme-challenge`` requests to your server.
For that you can add something similar to this to your zone file or equivalent::

    _acme-challenge IN NS www
    _acme-challenge.www IN NS www

For the forwarding, you need to add port ``8053``::
Create a ssh connection to your server which forwards a remote port to the local port ``8080``::

    % ssh root@example.com -R 8080:localhost:8080 -R 8053:localhost:8053

Then in that ssh session, run the following to forward UDP port ``53`` to TCP on port ``8053``::

    # socat -T15 udp4-recvfrom:53,reuseaddr,fork tcp:localhost:8053

For ``letsencrypt-remote`` you need to add the `--dns`` option::

    % letsencrypt-remote --dns example.com www.example.com

It will then first try the HTTP challenge and if that fails it will try the DNS challenge.
