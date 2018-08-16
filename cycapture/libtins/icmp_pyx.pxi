# -*- coding: utf-8 -*-
"""
ICMP packet python class
"""

cdef class ICMP(PDU):
    """
    ICMP packet.

    Instances of this class must be sent over a level 3 PDU.
    """
    pdu_flag = PDU.ICMP
    pdu_type = PDU.ICMP

    Flags = make_enum('ICMP_Flags', 'Flags', 'ICMP flags', {
        'ECHO_REPLY': ICMP_ECHO_REPLY,
        'DEST_UNREACHABLE': ICMP_DEST_UNREACHABLE,
        'SOURCE_QUENCH': ICMP_SOURCE_QUENCH,
        'REDIRECT': ICMP_REDIRECT,
        'ECHO_REQUEST': ICMP_ECHO_REQUEST,
        'TIME_EXCEEDED': ICMP_TIME_EXCEEDED,
        'PARAM_PROBLEM': ICMP_PARAM_PROBLEM,
        'TIMESTAMP_REQUEST': ICMP_TIMESTAMP_REQUEST,
        'TIMESTAMP_REPLY': ICMP_TIMESTAMP_REPLY,
        'INFO_REQUEST': ICMP_INFO_REQUEST,
        'INFO_REPLY': ICMP_INFO_REPLY,
        'ADDRESS_MASK_REQUEST': ICMP_ADDRESS_MASK_REQUEST,
        'ADDRESS_MASK_REPLY': ICMP_ADDRESS_MASK_REPLY
    })


    def __cinit__(self, flag=None, _raw=False):
        if _raw:
            return

        if flag is None:
            self.ptr = new cppICMP()
        else:
            self.ptr = new cppICMP(ICMP.Flags(int(flag)))

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, flag=None):
        """
        __init__(flag=None)
        Parameters
        ----------
        flag: int or :py:class:`~.ICMP.Flags`
            The type flag which will be set (`ECHO_REQUEST` if none provided)
        """

    @property
    def checksum(self):
        """
        The checksum field getter ('int')
        """
        return self.ptr.checksum()


    @property
    def code(self):
        """
        Code field getter ('int')
        """
        return self.ptr.code()

    @code.setter
    def code(self, value):
        """
        Code field setter ('int')
        """
        self.ptr.code(<uint8_t> int(value))


    @property
    def type(self):
        """
        Type field getter (:py:class:`~.ICMP.Flags`)
        """
        return self.ptr.get_type()

    @type.setter
    def type(self, value):
        """
        Type field setter (:py:class:`~.ICMP.Flags`)
        """
        value = ICMP.Flags(value)
        self.ptr.set_type(<ICMP_Flags>value)


    @property
    def id(self):
        """
        Id field getter ('int')
        """
        return self.ptr.ident()

    @id.setter
    def id(self, value):
        """
        Id field setter ('int')
        """
        self.ptr.ident(<uint16_t> value)


    @property
    def sequence(self):
        """
        Sequence field getter ('int')
        """
        return self.ptr.sequence()

    @sequence.setter
    def sequence(self, value):
        """
        Sequence field setter ('int')
        """
        self.ptr.sequence(<uint16_t> value)


    @property
    def mtu(self):
        """
        MTU field getter ('int')
        """
        return self.ptr.mtu()

    @mtu.setter
    def mtu(self, value):
        """
        MTU field setter ('int')
        """
        self.ptr.mtu(<uint16_t> value)


    @property
    def pointer(self):
        """
        Pointer field getter ('int')
        """
        return self.ptr.pointer()

    @pointer.setter
    def pointer(self, value):
        """
        Pointer field setter ('int')
        """
        self.ptr.pointer(<uint8_t> value)


    @property
    def original_timestamp(self):
        """
        Original timestamp field getter ('int')
        """
        return self.ptr.original_timestamp()

    @original_timestamp.setter
    def original_timestamp(self, value):
        """
        Original timestamp field setter ('int')
        """
        self.ptr.original_timestamp(<uint32_t> value)


    @property
    def receive_timestamp(self):
        """
        Receive timestamp field getter ('int')
        """
        return self.ptr.receive_timestamp()

    @receive_timestamp.setter
    def receive_timestamp(self, value):
        """
        Receive timestamp field setter ('int')
        """
        self.ptr.receive_timestamp(<uint32_t> value)


    @property
    def transmit_timestamp(self):
        """
        Transmit timestamp field getter ('int')
        """
        return self.ptr.transmit_timestamp()

    @transmit_timestamp.setter
    def transmit_timestamp(self, value):
        """
        Transmit timestamp field setter ('int')
        """
        self.ptr.transmit_timestamp(<uint32_t> value)


    @property
    def gateway(self):
        """
        Gateway field getter (:py:class:`~.IPv4Address`)
        """
        cdef cppIPv4Address g = self.ptr.gateway()
        return IPv4Address.factory(&g)

    @gateway.setter
    def gateway(self, value):
        """
        Gateway field setter (:py:class:`~.IPv4Address`)
        """
        addr = IPv4Address(value)
        self.ptr.gateway(<cppIPv4Address>(addr.ptr[0]))


    @property
    def address_mask(self):
        """
        Address mask field getter (:py:class:`~.IPv4Address`)
        """
        cdef cppIPv4Address mask = self.ptr.address_mask()
        return IPv4Address.factory(&mask)

    @address_mask.setter
    def address_mask(self, value):
        """
        Address mask field setter (:py:class:`~.IPv4Address`)
        """
        addr = IPv4Address(value)
        self.ptr.address_mask(<cppIPv4Address>(addr.ptr[0]))


    cpdef set_dest_unreachable(self):
        """
        set_dest_unreachable()
        Sets `destination unreachable` for this PDU.
        """
        self.ptr.set_dest_unreachable()

    cpdef set_source_quench(self):
        self.ptr.set_source_quench()

    cpdef set_time_exceeded(self, flag=True):
        cdef cpp_bool b = 1 if flag else 0
        self.ptr.set_time_exceeded(b)

    cpdef set_param_problem(self, set_pointer=False, int bad_octet=0):
        cdef cpp_bool b = 1 if set_pointer else 0
        self.ptr.set_param_problem(b, <uint8_t> bad_octet)

    cpdef set_echo_request(self, int ident, int seq):
        self.ptr.set_echo_request(<uint16_t> ident, <uint16_t> seq)

    cpdef set_echo_reply(self, int ident, int seq):
        self.ptr.set_echo_reply(<uint16_t> ident, <uint16_t> seq)

    cpdef set_info_request(self, int ident, int seq):
        self.ptr.set_info_request(<uint16_t> ident, <uint16_t> seq)

    cpdef set_info_reply(self, int ident, int seq):
        self.ptr.set_info_reply(<uint16_t> ident, <uint16_t> seq)

    cpdef set_redirect(self, int code, address):
        addr = IPv4Address(address)
        self.ptr.set_redirect(<uint8_t> code, <cppIPv4Address>(addr.ptr[0]))



    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppICMP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppICMP*> ptr
