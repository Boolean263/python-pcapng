"""
Module containing the definition of known / supported "blocks" of the
pcap-ng format.

Each block is a struct-like object with some fields and possibly
a variable amount of "items" (usually options).

They can optionally expose some other properties, used eg. to provide
better access to decoded information, ...
"""


import io
import itertools

import six

import pcapng.strictness as strictness
import pcapng.exceptions as exceptions
from pcapng.structs import (
    write_bytes_padded, write_int,
    IntField, OptionsField, PacketBytes,
    Options, Option, ListField, NameResolutionRecordField)
from pcapng.constants import link_types
from pcapng.utils import unpack_timestamp_resolution


KNOWN_BLOCKS = {}


class Block(object):
    """Base class for blocks"""

    schema = []
    readonly_fields = set()

    def __init__(self, **kwargs):
        if 'raw' in kwargs:
            self._raw = kwargs['raw']
            self._decoded = None
        else:
            self._decoded = {}
            for key, packed_type, default in self.schema:
                if key == 'options':
                    self._decoded[key] = Options(schema=packed_type.options_schema, data={}, endianness='=')
                else:
                    self._decoded[key] = default
            for aky, avl in kwargs.items():
                if aky == 'options':
                    for oky, ovl in avl.items():
                        self.options[oky] = ovl
                else:
                    self.__setattr__(aky, avl)

    def _decode(self):
        """Decodes the raw data of this block into its fields"""
        self._decoded = {}
        stream = six.BytesIO(self._raw)
        for name, field, default in self.schema:
            if isinstance(field, PacketBytes):
                field.captured_len = self.captured_len
            self._decoded[name] = field.load(stream, endianness=self.section.endianness)
        del self._raw

    def write(self, outstream):
        """Writes this block into the given output stream"""
        encoded_block = six.BytesIO()
        self._encode(encoded_block)
        encoded_block = encoded_block.getvalue()
        subblock_length = len(encoded_block)
        block_length = 12 + subblock_length
        if subblock_length % 4 != 0:
            block_length += (4 - (subblock_length % 4))
        write_int(self.magic_number, outstream, 32)
        write_int(block_length, outstream, 32)
        write_bytes_padded(outstream, encoded_block)
        write_int(block_length, outstream, 32)

    def _encode(self, outstream):
        """Encodes the fields of this block into raw data"""
        for name, field, default in self.schema:
            field.encode(getattr(self, name), outstream, endianness=self.section.endianness)

    def __getattr__(self, name):
        if not any([name == key for key, value, default in self.schema]):
            return self.__dict__[name]
        if self._decoded is None:
            self._decode()
        try:
            return self._decoded[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        if name in self.readonly_fields:
            raise exceptions.PcapngException("can't set read-only property '{prop}' on {cls}".format(prop=name, cls=self.__class__.__name__))
        if not any([name == key for key, value, default in self.schema]):
            self.__dict__[name] = value
            return
        if "_decoded" not in self.__dict__ or self.__dict__["_decoded"] is None:
            self._decoded = {}
            for key, packed_type, default in self.schema:
                self._decoded[key] = None
        self._decoded[name] = value

    def __repr__(self):
        args = []
        for item in self.schema:
            name = item[0]
            value = getattr(self, name)
            try:
                value = repr(value)
            except:
                value = '<{0} (repr failed)>'.format(type(value).__name__)
            args.append('{0}={1}'.format(name, value))
        return '<{0} {1}>'.format(self.__class__.__name__, ' '.join(args))


class SectionMemberBlock(Block):
    """Block which must be a member of a section"""
    def __init__(self, section, **kwargs):
        super(SectionMemberBlock, self).__init__(**kwargs)
        self.section = section

def register_block(block):
    """Handy decorator to register a new known block type"""
    KNOWN_BLOCKS[block.magic_number] = block
    return block


@register_block
class SectionHeader(Block):
    """
    "The Section Header Block (SHB) is mandatory. It identifies the beginning
    of a section of the capture file. The Section Header Block does not contain
    data but it rather identifies a list of blocks (interfaces, packets) that
    are logically correlated."
    - pcapng spec, section 4.1. Other quoted citations are from this section
    unless otherwise noted.
    """
    magic_number = 0x0a0d0d0a
    schema = [
        ('version_major', IntField(16, False), 1),
        ('version_minor', IntField(16, False), 0),
        ('section_length', IntField(64, True), -1),
        ('options', OptionsField([
            Option(2, 'shb_hardware', 'string'),
            Option(3, 'shb_os', 'string'),
            Option(4, 'shb_userappl', 'string'),
        ]), None)]

    def __init__(self, endianness="<", **kwargs):
        super(SectionHeader, self).__init__(**kwargs)
        self.endianness = endianness
        self._interfaces_id = itertools.count(0)
        self.interfaces = {}
        self.interface_stats = {}

    def _encode(self, outstream):
        write_int(0x1A2B3C4D, outstream, 32, endianness=self.endianness)
        super(SectionHeader, self)._encode(outstream)

    def new_member(self, cls, **kwargs):
        """Helper method to create a block that's a member of this section"""
        assert issubclass(cls, SectionMemberBlock)
        blk = cls(section=self, **kwargs)
        # Some blocks (eg. SPB) don't have options
        if any([x[0] == 'options' for x in blk.schema]):
            blk.options.endianness = self.endianness
        if isinstance(blk, InterfaceDescription):
            self.register_interface(blk)
        elif isinstance(blk, InterfaceStatistics):
            self.add_interface_stats(blk)
        return blk

    def register_interface(self, interface):
        """Helper method to register an interface within this section"""
        assert isinstance(interface, InterfaceDescription)
        interface_id = next(self._interfaces_id)
        interface.interface_id = interface_id
        self.interfaces[interface_id] = interface

    def add_interface_stats(self, interface_stats):
        """Helper method to register interface stats within this section"""
        assert isinstance(interface_stats, InterfaceStatistics)
        self.interface_stats[interface_stats.interface_id] = interface_stats

    @property
    def version(self):
        return (self.version_major, self.version_minor)

    @property
    def length(self):
        return self.section_length

    # Block.decode() assumes all blocks have sections -- technically true...
    @property
    def section(self):
        return self

    def __repr__(self):
        return ('<{name} version={version} endianness={endianness} '
                'length={length} options={options}>').format(
            name=self.__class__.__name__,
            version='.'.join(str(x) for x in self.version),
            endianness=repr(self.endianness),
            length=self.length,
            options=repr(self.options))


@register_block
class InterfaceDescription(SectionMemberBlock):
    """
    "An Interface Description Block (IDB) is the container for information
    describing an interface on which packet data is captured."
    - pcapng spec, section 4.2. Other quoted citations are from this section
    unless otherwise noted.
    """
    magic_number = 0x00000001
    schema = [
        ('link_type', IntField(16, False), 0),  # todo: enc/decode
        ('reserved', IntField(16, False), 0),
        ('snaplen', IntField(32, False), 0),
        ('options', OptionsField([
            Option(2, 'if_name', 'string'),
            Option(3, 'if_description', 'string'),
            Option(4, 'if_IPv4addr', 'ipv4+mask', multiple=True),
            Option(5, 'if_IPv6addr', 'ipv6+prefix', multiple=True),
            Option(6, 'if_MACaddr', 'macaddr'),
            Option(7, 'if_EUIaddr', 'euiaddr'),
            Option(8, 'if_speed', 'u64'),
            Option(9, 'if_tsresol'),  # Just keep the raw data
            Option(10, 'if_tzone', 'u32'),
            Option(11, 'if_filter', 'type+bytes'),
            Option(12, 'if_os', 'string'),
            Option(13, 'if_fcslen', 'u8'),
            Option(14, 'if_tsoffset', 'i64'),
            Option(15, 'if_hardware', 'string'),
        ]), None)]

    @property  # todo: cache this property
    def timestamp_resolution(self):
        # ------------------------------------------------------------
        # Resolution of timestamps. If the Most Significant Bit is
        # equal to zero, the remaining bits indicates the resolution
        # of the timestamp as as a negative power of 10 (e.g. 6 means
        # microsecond resolution, timestamps are the number of
        # microseconds since 1/1/1970). If the Most Significant Bit is
        # equal to one, the remaining bits indicates the resolution as
        # as negative power of 2 (e.g. 10 means 1/1024 of second). If
        # this option is not present, a resolution of 10^-6 is assumed
        # (i.e. timestamps have the same resolution of the standard
        # 'libpcap' timestamps).
        # ------------------------------------------------------------

        if 'if_tsresol' in self.options:
            return unpack_timestamp_resolution(self.options['if_tsresol'])

        return 1e-6

    @property
    def statistics(self):
        # todo: ensure we always have an interface id -> how??
        return self.section.interface_stats.get(self.interface_id)

    @property
    def link_type_description(self):
        try:
            return link_types.LINKTYPE_DESCRIPTIONS[self.link_type]
        except KeyError:
            return 'Unknown link type: 0x{0:04x}'.format(self.link_type)


class BlockWithTimestampMixin(object):
    """
    Block mixin adding properties to better access timestamps
    of blocks that provide one.
    """

    @property
    def timestamp(self):
        # First, get the accuracy from the ts_resol option
        return (((self.timestamp_high << 32) + self.timestamp_low)
                * self.timestamp_resolution)

    @property
    def timestamp_resolution(self):
        return self.interface.timestamp_resolution

    # todo: add some property returning a datetime() with timezone..


class BlockWithInterfaceMixin(object):
    """
    Block mixin for blocks that have/require an interface.
    This includes all packet blocks as well as InterfaceStatistics.
    """

    @property
    def interface(self):
        # We need to get the correct interface from the section
        # by looking up the interface_id
        return self.section.interfaces[self.interface_id]

    def write(self, outstream):
        if len(self.section.interfaces) < 1:
            strictness.problem("writing {cls} for section with no interfaces".format(cls=self.__class__.__name__))
            if strictness.should_fix():
                # Only way to "fix" is to not write the block
                return
        super(BlockWithInterfaceMixin, self).write(outstream)


class BasePacketBlock(
        SectionMemberBlock,
        BlockWithInterfaceMixin):
    """
    Base class for blocks with packet data.
    They must have these fields in their schema:

    * ``packet_len`` is the original amount of data that was "on the wire"
        (this can differ from ``captured_len``)
    * ``packet_data`` is the actual binary packet data (of course)

    This class makes the ``captured_len`` a read-only property returning
    the current length of the packet data.
    """

    def __init__(self, **kwargs):
        super(BasePacketBlock, self).__init__(**kwargs)
        # captured_len is the length of our packet data
        self.readonly_fields.add('captured_len')

    @property
    def captured_len(self):
        return len(self.packet_data)

    # Helper function. If the user hasn't explicitly set an original packet
    # length, use the length of the captured packet data.
    @property
    def packet_len(self):
        plen = self.__getattr__('packet_len') # this call prevents recursion
        return plen or len(self.packet_data)


@register_block
class EnhancedPacket(BasePacketBlock, BlockWithTimestampMixin):
    """
    "An Enhanced Packet Block (EPB) is the standard container for storing the
    packets coming from the network."
    - pcapng spec, section 4.3. Other quoted citations are from this section
    unless otherwise noted.
    """
    magic_number = 0x00000006
    schema = [
        ('interface_id', IntField(32, False), 0),
        ('timestamp_high', IntField(32, False), 0),
        ('timestamp_low', IntField(32, False), 0),
        ('captured_len', IntField(32, False), 0),
        ('packet_len', IntField(32, False), 0),
        ('packet_data', PacketBytes(), b''),
        ('options', OptionsField([
            Option(2, 'epb_flags', 'u32'),
            Option(3, 'epb_hash', 'type+bytes', multiple=True),  # todo: process the hash value
            Option(4, 'epb_dropcount', 'u64'),
        ]), None)
    ]


@register_block
class SimplePacket(BasePacketBlock):
    """
    "The Simple Packet Block (SPB) is a lightweight container for storing the
    packets coming from the network."
    - pcapng spec, section 4.4. Other quoted citations are from this section
    unless otherwise noted.
    """
    magic_number = 0x00000003
    schema = [
        ('packet_len', IntField(32, False), 0), # NOT the captured length
        ('packet_data', PacketBytes(), b''),
    ]

    def __init__(self, **kwargs):
        super(SimplePacket, self).__init__(**kwargs)
        self.readonly_fields.add('interface_id')

    @property
    def interface_id(self):
        """
        "The Simple Packet Block does not contain the Interface ID field.
        Therefore, it MUST be assumed that all the Simple Packet Blocks have
        been captured on the interface previously specified in the first
        Interface Description Block."
        """
        return 0

    @property
    def captured_len(self):
        """
        "...the SnapLen value MUST be used to determine the size of the Packet
        Data field length."
        """
        snap_len = self.interface.snaplen
        if snap_len == 0: # unlimited
            return self.packet_len
        else:
            return min(snap_len, self.packet_len)

    def write(self, outstream):
        if len(self.section.interfaces) > 1:
            # Spec is a bit ambiguous here. Section 4.4 says "it MUST
            # be assumed that all the Simple Packet Blocks have been captured
            # on the interface previously specified in the first Interface
            # Description Block." but later adds "A Simple Packet Block cannot
            # be present in a Section that has more than one interface because
            # of the impossibility to refer to the correct one (it does not
            # contain any Interface ID field)." Why would it say "the first"
            # IDB and not "the only" IDB if this was really forbidden?
            strictness.problem("writing SimplePacket for section with multiple interfaces")
            if strictness.should_fix():
                # Can't fix this. The IDBs have already been written.
                pass
        super(SimplePacket, self).write(outstream)


@register_block
class ObsoletePacket(BasePacketBlock, BlockWithTimestampMixin):
    """
    "The Packet Block is obsolete, and MUST NOT be used in new files. [...] A
    Packet Block was a container for storing packets coming from the network."
    - pcapng spec, Appendix A. Other quoted citations are from this appendix
    unless otherwise noted.
    """
    magic_number = 0x00000002
    schema = [
        ('interface_id', IntField(16, False), 0),
        ('drops_count', IntField(16, False), 0),
        ('timestamp_high', IntField(32, False), 0),
        ('timestamp_low', IntField(32, False), 0),
        ('captured_len', IntField(32, False), 0),
        ('packet_len', IntField(32, False), 0),
        ('packet_data', PacketBytes(), b''),
        ('options', OptionsField([
            Option(2, 'pack_flags', 'u32'),       # Same definition as epb_flags
            Option(3, 'pack_hash', 'type+bytes', multiple=True), # Same definition as epb_hash
        ]), None)
    ]

    def enhanced(self):
        """Return an EnhancedPacket with this block's attributes."""
        opts_dict = dict(self.options)
        opts_dict['epb_dropcount'] = self.drops_count
        for a in ('flags', 'hash'):
            try:
                opts_dict['epb_'+a] = opts_dict.pop('pack_'+a)
            except KeyError:
                pass
        return self.section.new_member(EnhancedPacket,
                interface_id=self.interface_id,
                timestamp_high=self.timestamp_high,
                timestamp_low=self.timestamp_low,
                packet_len=self.packet_len,
                packet_data=self.packet_data,
                options=opts_dict)

    def write(self, outstream):
        strictness.problem("Packet Block is obsolete and must not be used")
        if strictness.should_fix():
            self.enhanced().write(outstream)
        else:
            super(ObsoletePacket, self).write(outstream)


@register_block
class NameResolution(SectionMemberBlock):
    """
    "The Name Resolution Block (NRB) is used to support the correlation of
    numeric addresses (present in the captured packets) and their corresponding
    canonical names [...]. Having the literal names saved in the file prevents
    the need for performing name resolution at a later time, when the
    association between names and addresses may be different from the one in
    use at capture time."
    - pcapng spec, section 4.5. Other quoted citations are from this section
    unless otherwise noted.
    """
    magic_number = 0x00000004
    schema = [
        ('records', ListField(NameResolutionRecordField()), []),
        ('options', OptionsField([
            Option(2, 'ns_dnsname', 'string'),
            Option(3, 'ns_dnsIP4addr', 'ipv4'),
            Option(4, 'ns_dnsIP6addr', 'ipv6'),
        ]), None),
    ]


@register_block
class InterfaceStatistics(SectionMemberBlock, BlockWithTimestampMixin,
                          BlockWithInterfaceMixin):
    """
    "The Interface Statistics Block (ISB) contains the capture statistics for a
    given interface [...]. The statistics are referred to the interface defined
    in the current Section identified by the Interface ID field."
    - pcapng spec, section 4.6. Other quoted citations are from this section
    unless otherwise noted.
    """
    magic_number = 0x00000005
    schema = [
        ('interface_id', IntField(32, False), 0),
        ('timestamp_high', IntField(32, False), 0),
        ('timestamp_low', IntField(32, False), 0),
        ('options', OptionsField([
            Option(2, 'isb_starttime', 'u64'),  # todo: consider resolution
            Option(3, 'isb_endtime', 'u64'),
            Option(4, 'isb_ifrecv', 'u64'),
            Option(5, 'isb_ifdrop', 'u64'),
            Option(6, 'isb_filteraccept', 'u64'),
            Option(7, 'isb_osdrop', 'u64'),
            Option(8, 'isb_usrdeliv', 'u64'),
        ]), None),
    ]


class UnknownBlock(Block):
    """
    Class used to represent an unknown block.

    Its block type and raw data will be stored directly with no further
    processing.
    """

    def __init__(self, block_type, data):
        self.block_type = block_type
        self.data = data

    def __repr__(self):
        return ('UnknownBlock(0x{0:08X}, {1!r})'
                .format(self.block_type, self.data))
