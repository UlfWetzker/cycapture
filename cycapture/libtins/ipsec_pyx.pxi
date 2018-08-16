# -*- coding: utf-8 -*-

cdef class IPSecAH(PDU):
    """
    IPSec Authentication Header
    """
    pdu_flag = PDU.IPSEC_AH
    pdu_type = PDU.IPSEC_AH

    def __cinit__(self, _raw=False):
        if _raw or type(self) != IPSecAH:
            return

        self.ptr = new cppIPSecAH()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppIPSecAH* p = <cppIPSecAH*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()

        The ICV field is initialized with four 0 bytes. The length field is initialized appropriately.
        """


    @property 
    def next_header(self):
        """
        Next header field getter ('int')
        """
        return int(self.ptr.next_header())

    @next_header.setter
    def next_header(self, value):
        """
        Next header field setter ('int')
        """
        self.ptr.next_header(<uint8_t> int(value))


    @property
    def length(self):
        """
        Length field getter ('int')
        """
        return int(self.ptr.length())

    @length.setter
    def length(self, value):
        """
        Length field setter ('int')
        """
        self.ptr.length(<uint8_t> int(value))


    @property
    def spi(self):
        """
        Security Parameters Index field getter ('int')
        """
        return int(self.ptr.spi())

    @spi.setter
    def spi(self, value):
        """
        Security Parameters Index field setter ('int')
        """
        self.ptr.spi(<uint32_t> int(value))


    @property
    def seq_number(self):
        """
        Sequence number field getter ('int')
        """
        return int(self.ptr.seq_number())

    @seq_number.setter
    def seq_number(self, value):
        """
        Sequence number field setter ('int')
        """
        self.ptr.seq_number(<uint32_t> int(value))


    @property
    def icv(self):
        """
        ICV field getter ('bytes')
        """
        cdef vector[uint8_t] v = self.ptr.icv()
        cdef uint8_t* p = &v[0]
        return <bytes> (p[:v.size()])

    @icv.setter
    def icv(self, value):
        """
        ICV field setter ('bytes')
        """
        value = bytes(value)
        cdef uint8_t* p = <uint8_t*> value
        cdef vector[uint8_t] v
        v.assign(p, p + len(value))
        self.ptr.icv(v)


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppIPSecAH(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppIPSecAH*> ptr


cdef class IPSecESP(PDU):
    """
    IPSEC Encapsulating Security Payload
    """
    pdu_flag = PDU.IPSEC_ESP
    pdu_type = PDU.IPSEC_ESP

    def __cinit__(self, _raw=False):
        if _raw or type(self) != IPSecESP:
            return

        self.ptr = new cppIPSecESP()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppIPSecESP* p = <cppIPSecESP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    @property
    def spi(self):
        """
        Security Parameters Index field getter ('int')
        """
        return int(self.ptr.spi())

    @spi.setter
    def spi(self, value):
        """
        Security Parameters Index field setter ('int')
        """
        self.ptr.spi(<uint32_t> int(value))


    @property
    def seq_number(self):
        """
        Sequence number field getter ('int')
        """
        return int(self.ptr.seq_number())

    @seq_number.setter
    def seq_number(self, value):
        """
        Sequence number field setter ('int')
        """
        self.ptr.seq_number(<uint32_t> int(value))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppIPSecESP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppIPSecESP*> ptr


IPSECAH = IPSecAH
IPSEC_AH = IPSecAH
IPSECESP = IPSecESP
IPSEC_ESP = IPSecESP
