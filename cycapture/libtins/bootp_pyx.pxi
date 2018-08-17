# -*- coding: utf-8 -*-

cdef class BootP(PDU):
    """
    BootP packet
    """
    pdu_flag = PDU.BOOTP
    pdu_type = PDU.BOOTP

    OpCodes = make_enum('BootPOpCodes', 'OpCodes', 'The different opcodes BootP messages', {
        'BOOTREQUEST': BOOTP_BOOTREQUEST,
        'BOOTREPLY': BOOTP_BOOTREPLY
    })

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != BootP:
            return

        self.ptr = new cppBootP()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppBootP* p = <cppBootP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    @property
    def opcode(self):
        """
        OpCode field getter (`int`)
        """
        return int(self.ptr.opcode())

    @opcode.setter
    def opcode(self, value):
        """
        OpCode field setter (uint8_t`)
        """
        self.ptr.opcode(<uint8_t> int(value))


    @property
    def htype(self):
        """
        htype field getter (`int`)
        """
        return int(self.ptr.htype())

    @htype.setter
    def htype(self, value):
        """
        htype field setter (`uint8_t`)
        """
        self.ptr.htype(<uint8_t> int(value))


    @property
    def hlen(self):
        """
        hlen field getter (`int`)
        """
        return int(self.ptr.hlen())

    @hlen.setter
    def hlen(self, value):
        """
        hlen field setter (`uint8_t`)
        """
        self.ptr.hlen(<uint8_t> int(value))


    @property
    def hops(self):
        """
        hops field getter (`int`)
        """
        return int(self.ptr.hops())

    @hops.setter
    def hops(self, value):
        """
        hops field setter (`uint8_t`)
        """
        self.ptr.hops(<uint8_t> int(value))

    
    @property
    def xid(self):
        """
        xid field getter (`int`)
        """
        return int(self.ptr.xid())

    @xid.setter
    def xid(self, value):
        """
        xid field (`uint32_t`)
        """
        self.ptr.xid(<uint32_t> int(value))

    
    @property
    def secs(self):
        """
        secs field getter (`int`)
        """
        return int(self.ptr.secs())

    @secs.setter
    def secs(self, value):
        """
        secs field setter (`uint16_t`)
        """
        self.ptr.secs(<uint16_t> int(value))


    @property
    def padding(self):
        """
        padding field getter (`int`)
        """
        return int(self.ptr.padding())

    @padding.setter
    def padding(self, value):
        """
        padding field setter (`uint16_t`)
        """
        self.ptr.padding(<uint16_t> int(value))

    
    @property
    def ciaddr(self):
        """
        ciaddr field  getter (:py:class:`~.IPv4Address`)
        """
        return IPv4Address(<bytes> (self.ptr.ciaddr().to_string()))

    @ciaddr.setter
    def ciaddr(self, value):
        """
        ciaddr field setter (:py:class:`~.IPv4Address`)
        """
        if not isinstance(value, IPv4Address):
            value = IPv4Address(value)
        self.ptr.ciaddr((<IPv4Address> value).ptr[0])

    @property
    def yiaddr(self):
        """
        yiaddr field getter (:py:class:`~.IPv4Address`)
        """
        return IPv4Address(<bytes> (self.ptr.yiaddr().to_string()))

    @yiaddr.setter
    def yiaddr(self, value):
        """
        yiaddr field setter (:py:class:`~.IPv4Address`)
        """
        if not isinstance(value, IPv4Address):
            value = IPv4Address(value)
        self.ptr.yiaddr((<IPv4Address> value).ptr[0])

    
    @property
    def siaddr(self):
        """
        siaddr field getter (:py:class:`~.IPv4Address`)
        """
        return IPv4Address(<bytes> (self.ptr.siaddr().to_string()))

    @siaddr.setter
    def siaddr(self, value):
        """
        siaddr field setter (:py:class:`~.IPv4Address`)
        """
        if not isinstance(value, IPv4Address):
            value = IPv4Address(value)
        self.ptr.siaddr((<IPv4Address> value).ptr[0])

    
    @property
    def giaddr(self):
        """
        giaddr field getter (:py:class:`~.IPv4Address`)
        """
        return IPv4Address(<bytes> (self.ptr.giaddr().to_string()))

    @giaddr.setter
    def giaddr(self, value):
        """
        giaddr field setter (:py:class:`~.IPv4Address`)
        """
        if not isinstance(value, IPv4Address):
            value = IPv4Address(value)
        self.ptr.giaddr((<IPv4Address> value).ptr[0])


    @property
    def chaddr(self):
        """
        chaddr field getter (`bytes` like ``b"00:01:02:03:04:05:06:07:08:09:10:11:12:13:14:ff"``)
        """
        return <bytes> (self.ptr.chaddr().to_string())

    @chaddr.setter
    def chaddr(self, value):
        """
        chaddr field setter (`bytes` like ``b"00:01:02:03:04:05:06:07:08:09:10:11:12:13:14:ff"``)
        """
        l = bytes(value).split(':')
        if len(l) > 16:
            raise ValueError
        if any([int(s, 16) > 255 for s in l]):
            raise ValueError
        value = ":".join([s.zfill(2) for s in l])
        bootp_set_chaddr(self.ptr[0], cppHWAddress16(<string> value))


    @property
    def sname(self):
        """
        sname field getter (`bytes` with length <= 64)
        """
        return <bytes> (self.ptr.sname()[:64])

    @sname.setter
    def sname(self, value):
        """
        sname field setter (`bytes` with length <= 64)
        """
        value = (bytes(value)[:64]).ljust(64, '\x00')
        self.ptr.sname(<uint8_t*> value)


    @property
    def file(self):
        """
        file field getter (`bytes` with length <= 128)
        """
        return <bytes> (self.ptr.file()[:128])

    @file.setter
    def file(self, value):
        """
        file field setter (`bytes` with length <= 128)
        """
        value = (bytes(value)[:128]).ljust(128, '\x00')
        self.ptr.file(<uint8_t*> value)


    @property
    def vend(self):
        """
        vend field getter (`bytes`)
        """
        cdef vector[uint8_t] v = <vector[uint8_t]> ((<const cppBootP*> self.ptr).vend())
        return <bytes> ((&(v[0]))[:v.size()])

    @vend.setter
    def vend(self, value):
        """
        vend field setter (`bytes`)
        """
        value = bytes(value)
        cdef string s = value
        cdef vector[uint8_t] v
        v.assign(s.c_str(), s.c_str() + s.size())
        self.ptr.vend(v)


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppBootP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppBootP*> ptr
