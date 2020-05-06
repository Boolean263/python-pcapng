"""
Python-version-independent structs and stuff
"""

try:
    from collections.abc import Mapping, Iterable
except ImportError:
    from collections import Mapping, Iterable


# version-portable namedtuple with defaults, adapted from
# https://stackoverflow.com/a/18348004/6692652
from collections import namedtuple as _namedtuple
def namedtuple(typename, field_names, defaults=None):
    if not defaults:
        # No defaults given or needed
        return _namedtuple(typename, field_names)
    try:
        # Python 3.7+
        return _namedtuple(typename, field_names, defaults=defaults)
    except TypeError:
        T = _namedtuple(typename, field_names)
        try:
            # Python 2.7, up to 3.6
            T.__new__.__defaults__ = defaults
        except AttributeError:
            # Older Python 2.x
            T.__new__.func_defaults = defaults
        return T



