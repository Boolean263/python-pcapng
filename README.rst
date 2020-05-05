Python-pcapng
#############

Python library to parse the pcap-ng format used by newer versions
of dumpcap & similar tools (wireshark, winpcap, ...).


Documentation
=============

If you prefer the RTD theme, or want documentation for any version
other than the latest, head here:

http://python-pcapng.readthedocs.org/en/latest/

If you prefer the more comfortable, page-wide, default sphinx theme,
a documentation mirror is hosted on GitHub pages:

http://rshk.github.io/python-pcapng/


CI build status
===============

+----------+--------------------------------------------------------------------------+
| Branch   | Status                                                                   |
+==========+==========================================================================+
| master   | .. image:: https://travis-ci.org/rshk/python-pcapng.svg?branch=master    |
|          |     :target: https://travis-ci.org/rshk/python-pcapng                    |
+----------+--------------------------------------------------------------------------+
| develop  | .. image:: https://travis-ci.org/rshk/python-pcapng.svg?branch=develop   |
|          |     :target: https://travis-ci.org/rshk/python-pcapng                    |
+----------+--------------------------------------------------------------------------+


Source code
===========

Source, issue tracker etc. on GitHub: https://github.com/rshk/python-pcapng

Get the source from git::

    git clone https://github.com/rshk/python-pcapng

Download zip of the latest version:

https://github.com/rshk/python-pcapng/archive/master.zip

Install from pypi::

    pip install python-pcapng


PyPI status
===========

The official page on the Python Package Index is: https://pypi.python.org/pypi/python-pcapng

.. image:: https://img.shields.io/pypi/v/python-pcapng.svg
    :target: https://pypi.python.org/pypi/python-pcapng
    :alt: Latest PyPI version

.. image:: https://img.shields.io/pypi/dm/python-pcapng.svg
    :target: https://github.com/rshk/python-pcapng.git
    :alt: Number of PyPI downloads

.. image:: https://img.shields.io/pypi/pyversions/python-pcapng.svg
    :target: https://pypi.python.org/pypi/python-pcapng/
    :alt: Supported Python versions

.. image:: https://img.shields.io/pypi/status/python-pcapng.svg
    :target: https://pypi.python.org/pypi/python-pcapng/
    :alt: Development Status

.. image:: https://img.shields.io/pypi/l/python-pcapng.svg
    :target: https://pypi.python.org/pypi/python-pcapng/
    :alt: License

..
   .. image:: https://pypip.in/wheel/python-pcapng/badge.svg
       :target: https://pypi.python.org/pypi/python-pcapng/
       :alt: Wheel Status

   .. image:: https://pypip.in/egg/python-pcapng/badge.svg
       :target: https://pypi.python.org/pypi/python-pcapng/
       :alt: Egg Status

   .. image:: https://pypip.in/format/python-pcapng/badge.svg
       :target: https://pypi.python.org/pypi/python-pcapng/
       :alt: Download format



Why this library?
=================

- I need to decently extract some information from a bunch of pcap-ng
  files, but apparently tcpdump has some problems reading those files,

  I couldn't find other nice tools nor Python bindings to a library
  able to parse this format, so..

- In general, it appears there are (quite a bunch of!) Python modules
  to parse the old (much simpler) format, but nothing for the new one.

- And, they usually completely lack any form of documentation.


Isn't it slow?
==============

Yes, I guess it would be much slower than something written in C,
but I'm much better at Python than C.

..and I need to get things done, and CPU time is not that expensive :)

(Maybe I'll give a try porting the thing to Cython to speed it up, but
anyways, pure-Python libraries are always useful, eg. for PyPy).


How do I use it?
================

Basic usage is as simple as:

.. code-block:: python

    from pcapng import FileScanner

    with open('/tmp/mycapture.pcap', 'rb') as fp:
        scanner = FileScanner(fp)
        for block in scanner:
            pass  # do something with the block...

Have a look at the blocks documentation to see what they do; also, the
``examples`` directory contains some example scripts using the library.


Hacking
=======

Format specification is here:

https://github.com/pcapng/pcapng/

Contributions are welcome, please contact me if you're planning to do
some big change, so that we can sort out the best way to integrate it.

Or even better, open an issue so the whole world can participate in
the discussion :)


Pcap-ng write support
=====================

The original author (rshk) had some ideas on how to add write support
but never added it because they didn't need it. There is discussion on
the topic here:

https://github.com/rshk/python-pcapng/issues/14

The repository you're currently looking at (Boolean263/python-pcapng)
took the changes from @tannewt's patch in those comments as a starting
point, and I'm working from that to add full write support.

Current status on that front:

* Able to read a pcapng file and write out a new file and have the new
  file work

* Able to create new block objects in pure python and write them out

  - ``SectionHeader`` has a ``new_member()`` method to make it easier to
    create blocks and associate them with their section

* Able to add options to a block (new or existing) and write them out

  - Adding strings is reasonably well tested so far

  - Other options and option types need more testing

* Write support for NRBs

  - NRB records return/accept a list of names as per the pcapng spec,
    even if the list contains only one entry

* Write support for SPBs

  - API compatibility with EPB and PB

* Configurable strictness checking when writing out a file

  - When creating questionable data, either do nothing, warn about it,
    fix it (if possible), or raise an error, with the strictest being the
    default

  - Currently checked:

    * Adding multiples of a non-repeatable option to a block

    * Adding a SPB to a file with more than one interface

    * Writing a PB (PBs are obsolete and not to be used in new files)

* API tweaks so creating blocks programmatically is nicer (still in progress)

  - specifying payload data to a packet and having it automatically
    update the ``captured_len`` property

  - if the ``packet_len`` field (the original length of a packet) isn't set,
    assume it's equal to the ``captured_len`` (the amount of the packet that
    got captured)

