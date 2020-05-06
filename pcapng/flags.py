"""
Module to wrap an integer in bitwise flag/field accessors.
"""

from collections import OrderedDict

from pcapng.ngsix import namedtuple, Iterable

class FlagBase(object):
    """\
    Base class for flag types to be used in a Flags object.
    Handles the bitwise math so subclasses don't have to worry about it.
    """

    def __init__(self, owner, offset, size, extra=None):
        if size < 1:
            raise TypeError('Flag must be at least 1 bit wide')
        if size > owner._nbits:
            raise TypeError('Flag must fit into owner size')
        self.owner = owner
        self.offset = offset
        self.size = size
        self.extra = extra
        self.mask = ((1 << self.size)-1) << self.offset

    def get_bits(self):
        return (self.owner._value & self.mask) >> self.offset

    def set_bits(self, val):
        val &= (1 << self.size) - 1
        self.owner._value &= ~self.mask
        self.owner._value |= (val << self.offset)

    def __repr__(self):
        return '<{n} offset={o} size={s} mask=0x{m:08x} shift=0x{h:08x}'.format(
                n=self.__class__.__name__, o=self.offset, s=self.size,
                m=self.mask)


class FlagBool(FlagBase):
    """FlagBase representing a single boolean flag"""

    def __init__(self, owner, offset, size, extra=None):
        if size != 1:
            raise TypeError('FlagBool can only be 1 bit in size')
        super(FlagBool, self).__init__(owner, offset, size)

    def get(self):
        return bool(self.get_bits())

    def set(self, val):
        self.set_bits(int(bool(val)))


class FlagUInt(FlagBase):
    """FlagBase representing an unsigned integer of the given size"""

    def get(self):
        return self.get_bits()

    def set(self, val):
        self.set_bits(val)


class FlagEnum(FlagBase):
    """FlagBase representing a range of values"""

    def __init__(self, owner, offset, size, extra=None):
        if size < 2:
            raise TypeError('FlagEnum must be at least 2 bits in size')
        if not isinstance(extra, Iterable):
            raise TypeError('FlagEnum needs an iterable of values')
        super(FlagEnum, self).__init__(owner, offset, size, extra)

    def get(self):
        val = self.get_bits()
        try:
            return self.extra[val]
        except IndexError:
            return '[invalid value]'

    def set(self, val):
        if val in self.extra:
            self.set_bits(self.extra.index(val))
        elif isinstance(val, int):
            self.set_bits(val)
        else:
            raise TypeError('Invalid value {0} for FlagEnum'.format(val))


# Class representing a single flag schema for FlagWord.
# 'nbits' defaults to 1, and 'extra' defaults to None.
FlagField = namedtuple('FlagField', ('name', 'ftype', 'nbits', 'extra'),
        defaults=(1, None))


class FlagWord(object):
    """\
    Class to wrap an integer in bitwise flag/field accessors.
    """

    def __init__(self, schema, nbits=32, initial=0):
        """
        :param schema:
            A list of FlagField objects representing the values to be packed
            into this object, in order from LSB to MSB of the underlying int

        :param nbits:
            An integer representing the total number of bits used for flags

        :param initial:
            The initial integer value of the flags field
        """

        self._nbits = nbits
        self._value = initial
        self._schema = OrderedDict()

        bitn = 0
        for item in schema:
            if not issubclass(item.ftype, FlagBase):
                raise TypeError('Expected FlagBase, got {}'.format(item.ftype))
            self._schema[item.name] = item.ftype(self, bitn, item.nbits, item.extra)
            bitn += item.nbits

    def __int__(self):
        return self._value

    def __repr__(self):
        rv = '<{0} (value={1})'.format(self.__class__.__name__, self._value)
        for k, v in self._schema.items():
            rv += ' {0}={1}'.format(k, v.get())
        return rv+'>'

    def __getattr__(self, name):
        if name[0] == '_':
            return self.__dict__[name]
        try:
            v = self._schema[name]
        except KeyError:
            raise AttributeError(name)
        return v.get()

    def __setattr__(self, name, val):
        if name[0] == '_':
            self.__dict__[name] = val
            return val
        try:
            v = self._schema[name]
        except KeyError:
            raise AttributeError(name)
        return v.set(val)


if __name__ == '__main__':
    f = FlagWord([
            FlagField('inout', FlagEnum, 2, ('NA', 'inbound', 'outbound')),
            FlagField('casttype', FlagEnum, 3, ('NA', 'unicast', 'multicast', 'broadcast', 'promiscuous')),
            FlagField('fcslen', FlagUInt, 4),
            FlagField('reserved', FlagUInt, 7),
            FlagField('err_16', FlagBool),
            FlagField('err_17', FlagBool),
            FlagField('err_18', FlagBool),
            FlagField('err_19', FlagBool),
            FlagField('err_20', FlagBool),
            FlagField('err_21', FlagBool),
            FlagField('err_22', FlagBool),
            FlagField('err_23', FlagBool),
            FlagField('err_crc', FlagBool),
            FlagField('err_long', FlagBool),
            FlagField('err_short', FlagBool),
            FlagField('err_frame_gap', FlagBool),
            FlagField('err_frame_align', FlagBool),
            FlagField('err_frame_delim', FlagBool),
            FlagField('err_preamble', FlagBool),
            FlagField('err_symbol', FlagBool),
        ])

    f.fcslen = 12
    print(f)
    print(int(f))

