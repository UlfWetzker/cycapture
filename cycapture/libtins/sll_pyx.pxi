# -*- coding: utf-8 -*-

cdef class SLL(PDU):
    """
    Linux cooked-mode capture (SLL) PDU
    """
    pdu_flag = PDU.SLL
    pdu_type = PDU.SLL

    def __cinit__(self, _raw=False):
        if _raw:
            return
        if type(self) != SLL:
            return

        self.ptr = new cppSLL()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppSLL* p = <cppSLL*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    @property
    def packet_type(self):
        """
        Packet Type field getter ('int')
        """
        return int(self.ptr.packet_type())

    @packet_type.setter
    def packet_type(self, value):
        """
        Packet Type field setter ('int')
        """
        self.ptr.packet_type(<uint16_t> int(value))


    @property
    def lladdr_type(self):
        """
        LLADDR Type field getter ('int')
        """
        return int(self.ptr.lladdr_type())

    @lladdr_type.setter
    def lladdr_type(self, value):
        """
        LLADDR Type field setter ('int')
        """
        self.ptr.lladdr_type(<uint16_t> int(value))


    @property
    def lladdr_len(self):
        """
        LLADDR Length field getter ('int')
        """
        return int(self.ptr.lladdr_len())

    @lladdr_len.setter
    def lladdr_len(self, value):
        """
        LLADDR Length field setter ('int')
        """
        self.ptr.lladdr_len(<uint16_t> int(value))


    @property
    def protocol(self):
        """
        Protocol field getter ('int')
        """
        return int(self.ptr.protocol())

    @protocol.setter
    def protocol(self, value):
        """
        Protocol field setter ('int')
        """
        self.ptr.protocol(<uint16_t> int(value))


    @property
    def address(self):
        """
        Address field getter ('bytes' like ``b"00:01:02:03:04:05:06:07"``)
        """
        return <bytes> (self.ptr.address().to_string())

    @address.setter
    def address(self, value):
        """
        Address field ('bytes' like ``b"00:01:02:03:04:05:06:07"``)
        """
        cdef string v = bytes(value)
        self.ptr.address(cppHWAddress8(v))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppSLL(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppSLL*> ptr
