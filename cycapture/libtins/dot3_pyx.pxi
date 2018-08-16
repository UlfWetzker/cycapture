# -*- coding: utf-8 -*-

cdef class Dot3(PDU):
    """
    Dot3 (IEEE 802.3) packet
    """
    pdu_flag = PDU.IEEE802_3
    pdu_type = PDU.IEEE802_3
    broadcast = HWAddress.broadcast
    datalink_type = DLT_EN10MB

    def __cinit__(self, dst_addr=None, src_addr=None, _raw=False):
        if _raw is True or type(self) != Dot3:
            return

        if not isinstance(src_addr, HWAddress):
            src_addr = HWAddress(src_addr)
        if not isinstance(dst_addr, HWAddress):
            dst_addr = HWAddress(dst_addr)

        self.ptr = new cppDot3(<cppHWAddress6> ((<HWAddress> dst_addr).ptr[0]), <cppHWAddress6> ((<HWAddress> src_addr).ptr[0]))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr != NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dst_addr=None, src_addr=None):
        """
        __init__(dst_addr=None, src_addr=None)

        Parameters
        ----------
        dst_addr: `bytes` or :py:class:`~.HWAddress`
            The destination hardware address
        src_addr: `bytes` or :py:class:`~.HWAddress`
            The source hardware address
        """

    @property
    def src_addr(self):
        """
        Source address getter (:py:class:`~.HWAddress`)
        """
        cdef cppHWAddress6 src = self.ptr.src_addr()
        return HWAddress(src.to_string())

    @src_addr.setter
    def src_addr(self, value):
        """
        Source address setter (:py:class:`~.HWAddress`)
        """
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        self.ptr.src_addr(<cppHWAddress6>((<HWAddress> value).ptr[0]))


    @property
    def dst_addr(self):
        """
        Destination address getter (:py:class:`~.HWAddress`)
        """
        cdef cppHWAddress6 dst = self.ptr.dst_addr()
        return HWAddress(dst.to_string())

    @dst_addr.setter
    def dst_addr(self, value):
        """
        Destination address setter (:py:class:`~.HWAddress`)
        """
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        self.ptr.dst_addr(<cppHWAddress6>((<HWAddress> value).ptr[0]))


    @property
    def length(self):
        """
        Length field getter (`uint16_t`)
        """
        return self.ptr.length()

    @length.setter
    def length(self, value):
        """
        Length field setter (`uint16_t`)
        """
        self.ptr.length(<uint16_t> int(value))


    cpdef send(self, PacketSender sender, NetworkInterface iface):
        if sender is None:
            raise ValueError("sender can't be None")
        if iface is None:
            raise ValueError("iface can't be None")
        self.ptr.send((<PacketSender> sender).ptr[0], (<NetworkInterface> iface).interface)


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot3(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot3*> ptr

DOT3 = Dot3
