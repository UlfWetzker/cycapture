# -*- coding: utf-8 -*-

cdef class SNAP(PDU):
    """
    SNAP frame.

    Note that this PDU contains the 802.3 LLC structure + SNAP frame. So far only unnumbered information structure is
    supported.
    """
    pdu_flag = PDU.SNAP
    pdu_type = PDU.SNAP

    def __cinit__(self, _raw=False):
        if _raw or type(self) != SNAP:
            return

        self.ptr = new cppSNAP()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppSNAP* p = <cppSNAP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()

        The constructor sets the `dsap` and `ssap` fields to ``0xaa``, and the `id` field to ``3``.
        """

    @property
    def org_code(self):
        """
        Organization Code field getter ('int')
        """
        return int(<uint32_t> self.ptr.org_code())

    @org_code.setter
    def org_code(self, value):
        """
        Organization Code field setter ('int')
        """
        self.ptr.org_code(small_uint24(<uint32_t> int(value)))


    @property
    def eth_type(self):
        """
        Ethernet Type field getter ('int')
        """
        return int(self.ptr.eth_type())

    @eth_type.setter
    def eth_type(self, value):
        """
        Ethernet Type field setter ('int')
        """
        self.ptr.eth_type(<uint16_t> int(value))


    @property
    def control(self):
        """
        Control field getter ('int')
        """
        return int(self.ptr.control())

    @control.setter
    def control(self, value):
        """
        Control field setter ('int')
        """
        self.ptr.control(<uint8_t> int(value))


    @property
    def dsap(self):
        """
        DSAP field getter ('int')
        """
        return int(self.ptr.dsap())


    @property
    def ssap(self):
        """
        SSAP field getter ('int')
        """
        return int(self.ptr.ssap())


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppSNAP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppSNAP*> ptr
