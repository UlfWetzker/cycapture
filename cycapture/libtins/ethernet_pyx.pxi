# -*- coding: utf-8 -*-

cdef class EthernetII(PDU):
    """
    Ethernet packet
    """
    pdu_flag = PDU.ETHERNET_II
    pdu_type = PDU.ETHERNET_II
    broadcast = HWAddress.broadcast
    datalink_type = DLT_EN10MB

    def __cinit__(self, dst_addr=None, src_addr=None, _raw=False):
        if _raw:
            return

        if not isinstance(src_addr, HWAddress):
            src_addr = HWAddress(src_addr)
        if not isinstance(dst_addr, HWAddress):
            dst_addr = HWAddress(dst_addr)

        self.ptr = new cppEthernetII(<cppHWAddress6> ((<HWAddress> dst_addr).ptr[0]), <cppHWAddress6> ((<HWAddress> src_addr).ptr[0]))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dst_addr=None, src_addr=None):
        """
        __init__(dst_addr=None, src_addr=None)

        Parameters
        ----------
        dst_addr: bytes or :py:class:`~.HWAddress`
            destination address of the ethernet packet
        src_addr: bytes or :py:class:`~.HWAddress`
            source address of the ethernet packet
        """

    @property
    def src_addr(self):
        """
        Source address getter (property)
        """
        return HWAddress(<bytes> (self.ptr.src_addr().to_string()))

    @src_addr.setter
    def src_addr(self, value):
        """
        Source address setter (property)
        """
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        self.ptr.src_addr(<cppHWAddress6>((<HWAddress> value).ptr[0]))

    @property
    def dst_addr(self):
        """
        Destination address getter (property)
        """
        return HWAddress(<bytes> (self.ptr.dst_addr().to_string()))

    @dst_addr.setter
    def dst_addr(self, value):
        """
        Destination address setter (property)
        """
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        self.ptr.dst_addr(<cppHWAddress6>((<HWAddress> value).ptr[0]))

    @property
    def payload_type(self):
        """
        Payload type getter (`uint16_t`)
        """
        return int(self.ptr.payload_type())

    @payload_type.setter
    def payload_type(self, value):
        """
        Payload type setter(`uint16_t`)
        """
        self.ptr.payload_type(<uint16_t> int(value))

    cpdef send(self, PacketSender sender, NetworkInterface iface):
        if sender is None:
            raise ValueError("sender can't be None")
        if iface is None:
            raise ValueError("iface can't be None")
        self.ptr.send((<PacketSender> sender).ptr[0], (<NetworkInterface> iface).interface)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppEthernetII(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppEthernetII*> ptr

Ethernet = EthernetII
