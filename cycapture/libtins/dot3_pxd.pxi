# -*- coding: utf-8 -*-

cdef extern from "tins/dot3.h" namespace "Tins" nogil:
    # noinspection PyUnresolvedReferences
    PDUType dot3_pdu_flag "Tins::Dot3::pdu_flag"
    cppHWAddress6 dot3_BROADCAST "Tins::Dot3::BROADCAST"

    cdef cppclass cppDot3 "Tins::Dot3" (cppPDU):
        cppDot3()
        cppDot3(const cppHWAddress6 &dst_hw_addr) except +custom_exception_handler
        cppDot3(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr) except +custom_exception_handler
        cppDot3(const unsigned char *buf, uint32_t total_sz) except +custom_exception_handler

        void send(cppPacketSender &sender, const cppNetworkInterface &iface) except +custom_exception_handler

        cppHWAddress6 dst_addr() const
        cppHWAddress6 src_addr() const
        uint16_t length() const
        void dst_addr(const cppHWAddress6 &new_dst_addr)
        void src_addr(const cppHWAddress6 &new_src_addr)
        void length(uint16_t new_length)


cdef class Dot3(PDU):
    cdef cppDot3* ptr

    cpdef send(self, PacketSender sender, NetworkInterface iface)
