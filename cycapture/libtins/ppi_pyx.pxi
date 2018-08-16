# -*- coding: utf-8 -*-

cdef class PPI(PDU):
    """
    Per-Packet Information PDU

    This type of packet can't be costructed directly, and can't be serialized. It is useful only for sniffing.
    """
    pdu_flag = PDU.PPI
    pdu_type = PDU.PPI

    def __cinit__(self, _raw=False):
        if _raw is True:
            return
        raise ValueError("can't instantiate a PPI PDU")

    def __dealloc__(self):
        cdef cppPPI* p = <cppPPI*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        raise ValueError("can't instantiate a PPI PDU")


    @property
    def version(self):
        """
        Version field getter ('int')
        """
        return int(self.ptr.version())


    @property
    def flags(self):
        """
        Flags field getter ('int')
        """
        return int(self.ptr.flags())


    @property
    def length(self):
        """
        Length field getter ('int')
        """
        return int(self.ptr.length())


    @property
    def dlt(self):
        """
        Data Link Type field getter ('int')
        """
        return int(self.ptr.dlt())


    cpdef serialize(self):
        raise NotImplementedError

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppPPI(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppPPI*> ptr
