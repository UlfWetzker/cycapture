# -*- coding: utf-8 -*-

"""
TCP packet python class
"""

cdef class TCP(PDU):
    """
    TCP packet

    When sending TCP PDUs, the checksum is calculated automatically every time you send the packet.

    While sniffing, the payload sent in each packet will be wrapped in a RAW PDU::

        >>> from cycapture.libtins import TCP, RAW
        >>> buf = ...
        >>> pdu = TCP.from_buffer(buf)
        >>> raw = pdu.rfind_pdu(RAW)
        >>> payload = raw.payload
    """
    pdu_flag = PDU.TCP
    pdu_type = PDU.TCP

    Flags = make_enum('TCP_Flags', 'Flags', 'Flags supported by the TCP PDU.', {
        'FIN': TCP_FIN,
        'SYN': TCP_SYN,
        'RST': TCP_RST,
        'PSH': TCP_PSH,
        'ACK': TCP_ACK,
        'URG': TCP_URG,
        'ECE': TCP_ECE,
        'CWR': TCP_CWR
    })

    OptionTypes = make_enum('TCP_OptionTypes', 'OptionTypes', 'Option types supported by TCP PDU', {
        'EOL': TCP_EOL,
        'NOP': TCP_NOP,
        'MSS': TCP_MSS,
        'WSCALE': TCP_WSCALE,
        'SACK_OK': TCP_SACK_OK,
        'SACK': TCP_SACK,
        'TSOPT': TCP_TSOPT,
        'ALTCHK': TCP_ALTCHK
    })

    AltChecksums = make_enum('TCP_AltChecksums', 'AltChecksums', 'Alternate checksum enum', {
        'CHK_TCP': TCP_CHK_TCP,
        'CHK_8FLETCHER': TCP_CHK_8FLETCHER,
        'CHK_16FLETCHER': TCP_CHK_16FLETCHER
    })

    def __cinit__(self, dest=0, src=0, _raw=False):
        if _raw:
            return

        if src is None:
            src = 0
        if dest is None:
            dest = 0
        self.ptr = new cppTCP(<uint16_t> int(dest), <uint16_t> int(src))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dest=0, src=0):
        """
        __init__(dest=0, src=0)

        Parameters
        ----------
        dest: uint16_t
            destination port
        src: uint16_t
            source port
        """
        pass

    @property
    def sport(self):
        """
        Source port getter ('int')
        """
        return int(self.ptr.sport())

    @sport.setter
    def sport(self, value):
        """
        Source port setter ('int')
        """
        if value is None:
            value = 0
        self.ptr.sport(<uint16_t> int(value))


    @property
    def dport(self):
        """
        Destination port getter ('int')
        """
        return int(self.ptr.dport())

    @dport.setter
    def dport(self, value):
        """
        Destination port setter ('int')
        """
        if value is None:
            value = 0
        self.ptr.dport(<uint16_t> int(value))


    @property
    def seq(self):
        """
        Sequence number field getter ('int')
        """
        return int(self.ptr.seq())

    @seq.setter
    def seq(self, value):
        """
        Sequence number field setter ('int')
        """
        if value is None:
            value = 0
        self.ptr.seq(<uint32_t> int(value))


    @property
    def ack_seq(self):
        """
        Acknowledge number field getter ('int')
        """
        return int(self.ptr.ack_seq())

    @ack_seq.setter
    def ack_seq(self, value):
        """
        Acknowledge number field setter ('int')
        """
        if value is None:
            value = 0
        self.ptr.ack_seq(<uint32_t> int(value))


    @property
    def window(self):
        """
        Window size field getter ('int')
        """
        return int(self.ptr.window())

    @window.setter
    def window(self, value):
        """
        Window size field setter ('int')
        """
        if value is None:
            value = 32678
        self.ptr.window(<uint16_t>int(value))


    @property
    def checksum(self):
        """
        The checksum field getter ('int')
        """
        return int(self.ptr.checksum())


    @property
    def urg_ptr(self):
        """
        Urgent pointer field getter ('int')
        """
        return int(self.ptr.urg_ptr())

    @urg_ptr.setter
    def urg_ptr(self, value):
        """
        Urgent pointer field setter ('int')
        """
        if value is None:
            value = 0
        self.ptr.urg_ptr(<uint16_t>int(value))


    @property
    def data_offset(self):
        """
        Data offset field getter ('int')
        """
        cdef small_uint4 offset = self.ptr.data_offset()
        return <uint8_t> offset

    @data_offset.setter
    def data_offset(self, value):
        """
        Data offset field setter ('int')
        """
        cdef small_uint4 offset
        if value is None:
            pass            # ???
        offset = small_uint4(<uint8_t>int(value))
        self.ptr.data_offset(offset)

    # flags
    cpdef get_flag(self, flag):
        """
        get_flag(flag)
        Gets the value of a flag.

        Parameters
        ----------
        flag: :py:class:`~.TCP.Flags`

        Returns
        -------
        flag: bool
        """
        flag = TCP.Flags(flag)
        return bool(<uint8_t> self.ptr.get_flag(<TcpFlags> flag))

    cpdef set_flag(self, flag, value):
        """
        set_flag(flag, value)
        Sets a TCP flag value.

        Parameters
        ----------
        flag: :py:class:`~.TCP.Flags`
        value: bool
        """
        flag = TCP.Flags(flag)
        self.ptr.set_flag(<TcpFlags> flag, small_uint1(<uint8_t>1 if value else <uint8_t>0))


    @property
    def fin_flag(self):
        """
        Fin flag getter ('bool')
        """
        return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.FIN))

    @fin_flag.setter
    def fin_flag(self, value):
        """
        Fin flag setter ('int')
        """
        self.ptr.set_flag(TCP.Flags.FIN, small_uint1(<uint8_t>1 if value else <uint8_t>0))


    @property
    def syn_flag(self):
        """
        Syn flag getter ('bool')
        """
        return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.SYN))

    @syn_flag.setter
    def syn_flag(self, value):
        """
        Syn flag setter ('int')
        """
        self.ptr.set_flag(TCP.Flags.SYN, small_uint1(<uint8_t>1 if value else <uint8_t>0))


    @property
    def rst_flag(self):
        """
        Rst flag getter ('bool')
        """
        return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.RST))

    @rst_flag.setter
    def rst_flag(self, value):
        """
        Rst flag setter ('int')
        """
        self.ptr.set_flag(TCP.Flags.RST, small_uint1(<uint8_t>1 if value else <uint8_t>0))


    @property
    def psh_flag(self):
        """
        Psh flag getter ('bool')
        """
        return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.PSH))

    @psh_flag.setter
    def psh_flag(self, value):
        """
        Psh flag setter ('int')
        """
        self.ptr.set_flag(TCP.Flags.PSH, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    @property
    def ack_flag(self):
        """
        Ack flag getter ('bool')
        """
        return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.ACK))

    @ack_flag.setter
    def ack_flag(self, value):
        """
        Ack flag setter ('int')
        """
        self.ptr.set_flag(TCP.Flags.ACK, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    @property
    def urg_flag(self):
        """
        Urg flag getter ('bool')
        """
        return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.URG))

    @urg_flag.setter
    def urg_flag(self, value):
        """
        Urg flag setter ('int')
        """
        self.ptr.set_flag(TCP.Flags.URG, small_uint1(<uint8_t>1 if value else <uint8_t>0))


    @property
    def ece_flag(self):
        """
        Ece flag getter ('bool')
        """
        return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.ECE))

    @ece_flag.setter
    def ece_flag(self, value):
        """
        Ece flag setter ('int')
        """
        self.ptr.set_flag(TCP.Flags.ECE, small_uint1(<uint8_t>1 if value else <uint8_t>0))


    @property
    def cwr_flag(self):
        """
        Cwr flag getter (`boot`)
        """
        return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.CWR))

    @cwr_flag.setter
    def cwr_flag(self, value):
        """
        Cwr flag setter ('int')
        """
        self.ptr.set_flag(TCP.Flags.CWR, small_uint1(<uint8_t>1 if value else <uint8_t>0))


    @property
    def flags(self):
        """
        Flags getter ('int')
        """
        return <uint16_t> self.ptr.flags()

    @flags.setter
    def flags(self, value):
        """
        Flags setter ('int')
        """
        self.ptr.flags(small_uint12(<uint16_t>int(value)))


    # option
    @property
    def mss(self):
        """
        Mss getter ('int')
        """
        cdef uint16_t opt
        try:
            opt = self.ptr.mss()
        except OptionNotFound:
            return None
        return int(opt)

    @mss.setter
    def mss(self, value):
        """
        Mss setter ('int')
        """
        cdef tcp_pdu_option* mss_opt
        if value is None:       # back to default value
            value = 536
        self.ptr.mss(<uint16_t>int(value))


    # option
    @property
    def winscale(self):
        """
        Winscale field getter ('int')
        """
        cdef uint8_t opt
        try:
            opt = self.ptr.winscale()
        except OptionNotFound:
            return None
        return int(opt)

    @winscale.setter
    def winscale(self, value):
        """
        Winscale field setter ('int')
        """
        if value is None:
            pass            # ???
        self.ptr.winscale(<uint8_t>int(value))


    @property
    def altchecksum(self):
        """
        Altchecksum getter
        """
        try:
            return TCP.AltChecksums(self.ptr.altchecksum())
        except OptionNotFound:
            return None

    @altchecksum.setter
    def altchecksum(self, value):
        """
        Altchecksum setter
        """
        value = TCP.AltChecksums(value)
        self.ptr.altchecksum(<TcpAltChecksums> value)

    # option
    @property
    def sack_permitted(self):
        """
        SACK permitted getter ('bool')
        """
        return True if self.ptr.has_sack_permitted() else False

    # option
    cpdef set_sack_permitted(self):
        self.ptr.sack_permitted()


    @property
    def sack(self):
        """
        SACK getter
        """
        try:
            return <list> (self.ptr.sack())
        except OptionNotFound:
            return None

    @sack.setter
    def sack(self, value):
        """
        SACK setter
        """
        if not PySequence_Check(value):
            raise TypeError
        cdef vector[uint32_t] v
        for i in value:
            v.push_back(<uint32_t> int(i))
        self.ptr.sack(v)


    @property
    def timestamp(self):
        """
        Timestamp getter ('int')
        """
        cdef pair[uint32_t, uint32_t] p
        try:
            p = self.ptr.timestamp()
        except OptionNotFound:
            return None
        return int(p.first), int(p.second)

    @timestamp.setter
    def timestamp(self, value):
        """
        Timestamp setter ('int')
        """
        val, rep = value
        self.ptr.timestamp(<uint32_t> int(val), <uint32_t> int(rep))


    cpdef options(self):
        result = []
        cdef vector[tcp_pdu_option] opts = self.ptr.options()
        cdef tcp_pdu_option opt
        for opt in opts:
            opt_length = int(opt.length_field())
            data_size = int(opt.data_size())
            data = b''
            if data_size > 0:
                data = <bytes>((<tcp_pdu_option>opt).data_ptr()[:data_size])
            result.append({
                'type': int(opt.option()),
                'length': opt_length,
                'data_size': data_size,
                'data': data
            })

        return result


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppTCP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppTCP*> ptr
