# -*- coding: utf-8 -*-

cdef class Dot1Q(PDU):
    """
    IEEE 802.1q PDU class
    """
    pdu_flag = PDU.DOT1Q
    pdu_type = PDU.DOT1Q

    def __cinit__(self, tag_id=0, append_pad=True, _raw=False):
        if _raw is True or type(self) != Dot1Q:
            return

        tag_id = int(tag_id)
        append_pad = bool(append_pad)

        self.ptr = new cppDot1Q(small_uint12(<uint16_t> tag_id), <cpp_bool> append_pad)
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot1Q* p = <cppDot1Q*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, tag_id=0, append_pad=True):
        """
        __init__(tag_id=0, append_pad=True)

        Parameters
        ----------
        tag_id: uint16_t
            Tag VLAN ID
        append_pad: bool
            flag indicating whether padding will be appended at the end of this packet
        """


    @property
    def priority(self):
        """
        Priority field getter (`uint8_t`)
        """
        return int(<uint8_t> self.ptr.priority())

    @priority.setter
    def priority(self, value):
        """
        Priority field setter (`uint8_t`)
        """
        value = int(value)
        self.ptr.priority(small_uint3(<uint8_t> value))


    @property
    def cfi(self):
        """
        Canonical Format Identifie getter (`uint8_t`)
        """
        return int(<uint8_t> self.ptr.cfi())

    @cfi.setter
    def cfi(self, value):
        """
        Canonical Format Identifie field setter (`uint8_t`)
        """
        value = 1 if value else 0
        self.ptr.cfi(small_uint1(<uint8_t> value))


    @property
    def id(self):
        """
        VLAN Id (read-write, `uint16_t`)
        """
        return int(<uint16_t> self.ptr.id())

    @id.setter
    def id(self, value):
        """
        VLAN Id (read-write, `uint16_t`)
        """
        self.ptr.id(small_uint12(<uint16_t> int(value)))


    @property
    def payload_type(self):
        """
        Payload type field getter (`uint16_t`)
        """
        return int(self.ptr.payload_type())

    @payload_type.setter
    def payload_type(self, value):
        """
        Payload type field setter (`uint16_t`)
        """
        self.ptr.payload_type(<uint16_t> int(value))


    @property
    def append_padding(self):
        """
        Getter for the flag that indicats whether the appropriate padding will be at the end of the packet (`bool`).

        The flag could be set to ``False`` when two or more contiguous Dot1Q
        PDUs are added to a packet. In that case, only the Dot1Q that is
        closer to the link layer should add a padding at the end.
        """
        return bool(self.ptr.append_padding())

    @append_padding.setter
    def append_padding(self, value):
        """
        Setter for the flag that indicats whether the appropriate padding will be at the end of the packet (`bool`).

        The flag could be set to ``False`` when two or more contiguous Dot1Q
        PDUs are added to a packet. In that case, only the Dot1Q that is
        closer to the link layer should add a padding at the end.
        """
        value = bool(value)
        self.ptr.append_padding(<cpp_bool> value)


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot1Q(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot1Q*> ptr

DOT1Q = Dot1Q
