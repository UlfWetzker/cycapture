# -*- coding: utf-8 -*-

"""
Base Dot11 packet python class
"""

fh_params = namedtuple('fh_params', ['dwell_time', 'hop_set', 'hop_pattern', 'hop_index'])
cf_params = namedtuple('cf_params', ['cfp_count', 'cfp_period', 'cfp_max_duration', 'cfp_dur_remaining'])
dfs_params = namedtuple('dfs_params', ['dfs_owner', 'recovery_interval', 'channel_map'])
country_params = namedtuple('country_params', ['country', 'first_channel', 'number_channels', 'max_transmit_power'])
fh_pattern = namedtuple('fh_pattern', ['flag', 'number_of_sets', 'modulus', 'offset', 'random_table'])
channel_switch_t = namedtuple('channel_switch_t', ['switch_mode', 'new_channel', 'count'])
quiet_t = namedtuple('quiet_t', ['quiet_count', 'quiet_period', 'quiet_duration', 'quiet_offset'])
bss_load_t = namedtuple('bss_load_t', ['station_count', 'channel_utilization', 'available_capacity'])
tim_t = namedtuple('tim_t', ['dtim_count', 'dtim_period', 'bitmap_control', 'partial_virtual_bitmap'])
vendor_specific_t = namedtuple('vendor_specific_t', ['oui', 'data'])

cdef class Dot11(PDU):
    '''
    Base Dot11 packet
    '''
    pdu_flag = PDU.DOT11
    pdu_type = PDU.DOT11
    datalink_type = DLT_IEEE802_11

    Types = make_enum("Dot11_Types", 'Types', 'the different types of 802.11 frames', {
        'MANAGEMENT':   D11_T_MANAGEMENT,
        'CONTROL':      D11_T_CONTROL,
        'DATA':         D11_T_DATA
    })

    OptionTypes = make_enum('Dot11_OptionTypes', 'OptionTypes', 'the different types of tagged options', {
        "SSID": D11_SSID,
        "SUPPORTED_RATES": D11_SUPPORTED_RATES,
        "FH_SET": D11_FH_SET,
        "DS_SET": D11_DS_SET,
        "CF_SET": D11_CF_SET,
        "TIM": D11_TIM,
        "IBSS_SET": D11_IBSS_SET,
        "COUNTRY": D11_COUNTRY,
        "HOPPING_PATTERN_PARAMS": D11_HOPPING_PATTERN_PARAMS,
        "HOPPING_PATTERN_TABLE": D11_HOPPING_PATTERN_TABLE,
        "REQUEST_INFORMATION": D11_REQUEST_INFORMATION,
        "BSS_LOAD": D11_BSS_LOAD,
        "EDCA": D11_EDCA,
        "TSPEC": D11_TSPEC,
        "TCLAS": D11_TCLAS,
        "SCHEDULE": D11_SCHEDULE,
        "CHALLENGE_TEXT": D11_CHALLENGE_TEXT,
        "POWER_CONSTRAINT": D11_POWER_CONSTRAINT,
        "POWER_CAPABILITY": D11_POWER_CAPABILITY,
        "TPC_REQUEST": D11_TPC_REQUEST,
        "TPC_REPORT": D11_TPC_REPORT,
        "SUPPORTED_CHANNELS": D11_SUPPORTED_CHANNELS,
        "CHANNEL_SWITCH": D11_CHANNEL_SWITCH,
        "MEASUREMENT_REQUEST": D11_MEASUREMENT_REQUEST,
        "MEASUREMENT_REPORT": D11_MEASUREMENT_REPORT,
        "QUIET": D11_QUIET,
        "IBSS_DFS": D11_IBSS_DFS,
        "ERP_INFORMATION": D11_ERP_INFORMATION,
        "TS_DELAY": D11_TS_DELAY,
        "TCLAS_PROCESSING": D11_TCLAS_PROCESSING,
        "QOS_CAPABILITY": D11_QOS_CAPABILITY,
        "RSN": D11_RSN,
        "EXT_SUPPORTED_RATES": D11_EXT_SUPPORTED_RATES,
        "VENDOR_SPECIFIC": D11_VENDOR_SPECIFIC
    })

    ManagementSubtypes = make_enum('Dot11_ManagementSubtypes', 'ManagementSubtypes', 'the different subtypes of 802.11 management frames', {
        "ASSOC_REQ": D11_ASSOC_REQ,
        "ASSOC_RESP": D11_ASSOC_RESP,
        "REASSOC_REQ": D11_REASSOC_REQ,
        "REASSOC_RESP": D11_REASSOC_RESP,
        "PROBE_REQ": D11_PROBE_REQ,
        "PROBE_RESP": D11_PROBE_RESP,
        "BEACON": D11_BEACON,
        "ATIM": D11_ATIM,
        "DISASSOC": D11_DISASSOC,
        "AUTH": D11_AUTH,
        "DEAUTH": D11_DEAUTH
    })

    ControlSubtypes = make_enum('Dot11_ControlSubtypes', 'ControlSubtypes', 'the different subtypes of 802.11 control frames', {
        "BLOCK_ACK_REQ": D11_BLOCK_ACK_REQ,
        "BLOCK_ACK": D11_BLOCK_ACK,
        "PS": D11_PS,
        "RTS": D11_RTS,
        "CTS": D11_CTS,
        "ACK": D11_ACK,
        "CF_END": D11_CF_END,
        "CF_END_ACK": D11_CF_END_ACK
    })

    DataSubtypes = make_enum('Dot11DataSubtypes', 'DataSubtypes', 'the different subtypes of 802.11 data frames', {
        "DATA_DATA": D11_DATA_DATA,
        "DATA_CF_ACK": D11_DATA_CF_ACK,
        "DATA_CF_POLL": D11_DATA_CF_POLL,
        "DATA_CF_ACK_POLL": D11_DATA_CF_ACK_POLL,
        "DATA_NULL": D11_DATA_NULL,
        "CF_ACK": D11_CF_ACK,
        "CF_POLL": D11_CF_POLL,
        "CF_ACK_POLL": D11_CF_ACK_POLL,
        "QOS_DATA_DATA": D11_QOS_DATA_DATA,
        "QOS_DATA_CF_ACK": D11_QOS_DATA_CF_ACK,
        "QOS_DATA_CF_POLL": D11_QOS_DATA_CF_POLL,
        "QOS_DATA_CF_ACK_POLL": D11_QOS_DATA_CF_ACK_POLL,
        "QOS_DATA_NULL": D11_QOS_DATA_NULL
    })

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        # src is in signature just for inheritance
        self.ptr = new cppDot11(<cppHWAddress6> ((<HWAddress> dst_hw_addr).ptr[0]))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr
            not used
        '''

    def __dealloc__(self):
        cdef cppDot11* p = <cppDot11*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL
        self.parent = None


    @property
    def protocol(self):
        '''
        protocol version field getter ('int')
        '''
        return <uint8_t> self.ptr.protocol()

    @protocol.setter
    def protocol(self, value):
        '''
        protocol version field setter ('int')
        '''
        self.ptr.protocol(small_uint2(<uint8_t> value))


    @property
    def type(self):
        '''
        type field getter ('int')
        '''
        return <uint8_t> self.ptr.type()

    @type.setter
    def type(self, value):
        '''
        type field setter ('int')
        '''
        self.ptr.type(small_uint2(<uint8_t> value))


    @property
    def subtype(self):
        '''
        subtype field getter ('int')
        '''
        return <uint8_t> self.ptr.subtype()

    @subtype.setter
    def subtype(self, value):
        '''
        subtype field setter ('int')
        '''
        self.ptr.subtype(small_uint4(<uint8_t> value))


    @property
    def to_ds(self):
        '''
        To-DS field getter ('bool')
        '''
        return bool(<uint8_t> self.ptr.to_ds())

    @to_ds.setter
    def to_ds(self, value):
        '''
        To-DS field setter ('bool')
        '''
        value = 1 if value else 0
        self.ptr.to_ds(small_uint1(<uint8_t> value))


    @property
    def from_ds(self):
        '''
        From-DS field getter ('bool')
        '''
        return bool(<uint8_t> self.ptr.from_ds())

    @from_ds.setter
    def from_ds(self, value):
        '''
        From-DS field setter ('bool')
        '''
        value = 1 if value else 0
        self.ptr.from_ds(small_uint1(<uint8_t> value))


    @property
    def more_frag(self):
        '''
        More-Frag field getter ('bool')
        '''
        return bool(<uint8_t> self.ptr.more_frag())

    @more_frag.setter
    def more_frag(self, value):
        '''
        More-Frag field setter ('bool')
        '''
        value = 1 if value else 0
        self.ptr.more_frag(small_uint1(<uint8_t> value))


    @property
    def retry(self):
        '''
        Retry field getter ('bool')
        '''
        return bool(<uint8_t> self.ptr.retry())

    @retry.setter
    def retry(self, value):
        '''
        Retry field setter ('bool')
        '''
        value = 1 if value else 0
        self.ptr.retry(small_uint1(<uint8_t> value))


    @property
    def power_mgmt(self):
        '''
        Power-Management field getter ('bool')
        '''
        return bool(<uint8_t> self.ptr.power_mgmt())

    @power_mgmt.setter
    def power_mgmt(self, value):
        '''
        Power-Management field setter ('bool')
        '''
        value = 1 if value else 0
        self.ptr.power_mgmt(small_uint1(<uint8_t> value))


    @property
    def wep(self):
        '''
        WEP field getter ('bool')
        '''
        return bool(<uint8_t> self.ptr.wep())

    @wep.setter
    def wep(self, value):
        '''
        WEP field setter ('bool')
        '''
        value = 1 if value else 0
        self.ptr.wep(small_uint1(<uint8_t> value))


    @property
    def order(self):
        '''
        Order field getter ('bool')
        '''
        return bool(<uint8_t> self.ptr.order())

    @order.setter
    def order(self, value):
        '''
        Order field setter ('bool')
        '''
        value = 1 if value else 0
        self.ptr.order(small_uint1(<uint8_t> value))


    @property
    def duration_id(self):
        '''
        Duration-ID field getter ('int')
        '''
        return <uint16_t> self.ptr.duration_id()

    @duration_id.setter
    def duration_id(self, value):
        '''
        Duration-ID field setter ('int')
        '''
        self.ptr.duration_id(<uint16_t> value)


    @property
    def addr1(self):
        '''
        First address getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes>(self.ptr.addr1().to_string()))

    @addr1.setter
    def addr1(self, value):
        '''
        First address setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        self.ptr.addr1((<HWAddress>value).ptr[0])


    cpdef send(self, PacketSender sender, NetworkInterface iface):
        if sender is None:
            raise ValueError("sender can't be None")
        if iface is None:
            raise ValueError("iface can't be None")
        self.ptr.send((<PacketSender> sender).ptr[0], (<NetworkInterface> iface).interface)

    @staticmethod
    def from_bytes(buf):
        '''
        from_bytes(buf)
        Static. Allocates an Dot11 PDU from a buffer.

        Instantiate the appropriate subclass of Dot11 from the given buffer. The type of the allocated class
        will be figured out from the the buffer.

        Parameters
        ----------
        buf: bytes or bytearray or memoryview

        Returns
        -------
        pdu: :py:class:`~._tins.Dot11`
        '''
        if buf is None:
            return Dot11()
        cdef uint8_t* buf_addr
        cdef uint32_t size
        PDU.prepare_buf_arg(buf, &buf_addr, &size)
        return Dot11.c_from_bytes(buf_addr, size)

    @staticmethod
    cdef c_from_bytes(uint8_t* buf_addr, uint32_t size):
        '''
        c_from_bytes(uint8_t* buf_addr, uint32_t size)
        Static. Allocates an Dot11 PDU from a buffer.

        Parameters
        ----------
        buf_addr: uint8_t*
        size: uint32_t

        Returns
        -------
        pdu: :py:class:`~._tins.Dot11`
        '''
        if buf_addr is NULL or size == 0:
            return Dot11()
        cdef cppDot11* p = dot11_from_bytes(buf_addr, size)         # equivalent to new
        if p is NULL:
            raise MalformedPacket
        return PDU.from_ptr(p, parent=None)

    cpdef add_option(self, identifier, data=None):
        '''
        add_option(identifier, data=None)
        Adds a new option to this Dot11 PDU.

        Parameters
        ----------
        identifier: int or :py:class:`~.Dot11.OptionTypes`
        data: bytes
        '''
        cdef dot11_pdu_option opt
        identifier = int(identifier)
        if data is None:
            opt = dot11_pdu_option(<uint8_t> identifier)
        else:
            data = bytes(data)
            opt = dot11_pdu_option(<uint8_t> identifier, len(data), <uint8_t*> data)
        (<cppDot11*> self.ptr).add_option(opt)

    cpdef search_option(self, identifier):
        '''
        search_option(identifier)
        Look up a tagged option in the option list. Returns ``None`` if the option is not found.

        Parameters
        ----------
        identifier: int or :py:class:`~.Dot11.OptionTypes`

        Returns
        -------
        option: bytes
        '''
        identifier = int(identifier)
        cdef dot11_pdu_option* opt = <dot11_pdu_option*> ((<cppDot11*> self.ptr).search_option(<D11_OptionTypes> identifier))
        if opt is NULL:
            return None
        cdef int length = opt.data_size()
        if not length:
            return ""
        return <bytes> ((opt.data_ptr())[:length])

    cpdef options(self):
        '''
        options()
        Returns the list of options

        Returns
        -------
        l: list of (int, bytes)
        '''
        cdef vector[dot11_pdu_option] l = (<cppDot11*> self.ptr).options()
        return [
            (
                int(opt.option()),
                (<bytes> (opt.data_ptr()[:opt.data_size()])) if opt.data_size() > 0 else b''
            )
            for opt in l
        ]

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11*> ptr


cdef class Dot11Data(Dot11):
    '''
    802.11 Data frame
    '''
    pdu_flag = PDU.DOT11_DATA
    pdu_type = PDU.DOT11_DATA

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11Data:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11Data((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(self, dst_hw_addr=None, src=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11.__init__(self, dst_hw_addr, src_hw_addr)

    def __dealloc__(self):
        cdef cppDot11Data* p = <cppDot11Data*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL
        self.parent = None


    @property
    def addr2(self):
        '''
        the second address getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes>((<cppDot11Data*> self.ptr).addr2().to_string()))

    @addr2.setter
    def addr2(self, value):
        '''
        the second address setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11Data*> self.ptr).addr2((<HWAddress> value).ptr[0])


    @property
    def addr3(self):
        '''
        the third address setter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes>((<cppDot11Data*> self.ptr).addr3().to_string()))

    @addr3.setter
    def addr3(self, value):
        '''
        the third address getter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11Data*> self.ptr).addr3((<HWAddress> value).ptr[0])


    @property
    def addr4(self):
        '''
        the fourth address getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes>((<cppDot11Data*> self.ptr).addr4().to_string()))

    @addr4.setter
    def addr4(self, value):
        '''
        the fourth address getter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11Data*> self.ptr).addr4((<HWAddress> value).ptr[0])


    @property
    def frag_num(self):
        '''
        the fragment number field getter (`uint8_t`)
        '''
        return <uint8_t> ((<cppDot11Data*> self.ptr).frag_num())

    @frag_num.setter
    def frag_num(self, value):
        '''
        the fragment number field setter (`uint8_t`)
        '''
        (<cppDot11Data*> self.ptr).frag_num(small_uint4(<uint8_t> value))


    @property
    def seq_num(self):
        '''
        the sequence number field getter (`uint16_t`)
        '''
        return <uint16_t> ((<cppDot11Data*> self.ptr).seq_num())

    @seq_num.setter
    def seq_num(self, value):
        '''
        the sequence number field setter (`uint16_t`)
        '''
        (<cppDot11Data*> self.ptr).seq_num(small_uint12(<uint16_t> value))


    @property
    def srd_addr(self):
        '''
        getter for the frame's source address (:py:class:`~.HWAddress`)
        It is a wrapper over the `addr*` methods that takes into account the value of the FromDS and ToDS bits.
        If ``FromDS == ToDS == 1``, ``None`` is returned.
        '''
        if self.from_ds and self.to_ds:
            return None
        return HWAddress(<bytes>((<cppDot11Data*> self.ptr).src_addr().to_string()))

    @property
    def dst_addr(self):
        '''
        Getter for the frame's destination address (:py:class:`~.HWAddress`)
        It is a wrapper over the `addr*` methods that takes into account the value of the FromDS and ToDS bits.
        If ``FromDS == ToDS == 1``, ``None`` is returned.
        '''
        if self.from_ds and self.to_ds:
            return None
        return HWAddress(<bytes>((<cppDot11Data*> self.ptr).dst_addr().to_string()))

    @property
    def bssid_addr(self):
        '''
        Getter for the frame's BSSID address (:py:class:`~.HWAddress`)
        It is a wrapper over the `addr*` methods that takes into account the value of the FromDS and ToDS bits.
        If ``FromDS == ToDS == 1``, ``None`` is returned.
        '''
        if self.from_ds and self.to_ds:
            return None
        return HWAddress(<bytes>((<cppDot11Data*> self.ptr).bssid_addr().to_string()))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11Data(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11Data*> ptr


cdef class Dot11QoSData(Dot11Data):
    '''
    802.11 QoS Data frame
    '''
    pdu_flag = PDU.DOT11_QOS_DATA
    pdu_type = PDU.DOT11_QOS_DATA

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11QoSData:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11QoSData((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11Data.__init__(self, dst_hw_addr, src_hw_addr)

    def __dealloc__(self):
        cdef cppDot11QoSData* p = <cppDot11QoSData*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL
        self.parent = None

    @property
    def qos_control(self):
        '''
        QOS Control field getter ('int')
        '''
        return int((<cppDot11QoSData*> self.ptr).qos_control())

    @qos_control.setter
    def qos_control(self, value):
        '''
        QOS Control field setter ('int')
        '''
        (<cppDot11QoSData*> self.ptr).qos_control(<uint16_t> int(value))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11QoSData(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11QoSData*> ptr


cdef class Dot11ManagementFrame(Dot11):
    '''
    Abstract class for all Management frames in the 802.11 family.
    '''
    pdu_flag = PDU.DOT11_MANAGEMENT
    pdu_type = PDU.DOT11_MANAGEMENT

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if type(self) == Dot11ManagementFrame:
            raise NotImplementedError

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Raises
        ------
        exception: NotImplementedError
        '''
        Dot11.__init__(self, dst_hw_addr, src_hw_addr)

    def __dealloc__(self):
        pass

    ReasonCodes = make_enum('Dot11_ReasonCodes', 'ReasonCodes', 'Reason codes', {
        'UNSPECIFIED': D11MGMT_UNSPECIFIED,
        'PREV_AUTH_NOT_VALID': D11MGMT_PREV_AUTH_NOT_VALID,
        'STA_LEAVING_IBSS_ESS': D11MGMT_STA_LEAVING_IBSS_ESS,
        'INACTIVITY': D11MGMT_INACTIVITY,
        'CANT_HANDLE_STA': D11MGMT_CANT_HANDLE_STA,
        'CLASS2_FROM_NO_AUTH': D11MGMT_CLASS2_FROM_NO_AUTH,
        'CLASS3_FROM_NO_AUTH': D11MGMT_CLASS3_FROM_NO_AUTH,
        'STA_LEAVING_BSS': D11MGMT_STA_LEAVING_BSS,
        'STA_NOT_AUTH_WITH_STA': D11MGMT_STA_NOT_AUTH_WITH_STA,
        'POW_CAP_NOT_VALID': D11MGMT_POW_CAP_NOT_VALID,
        'SUPPORTED_CHANN_NOT_VALID': D11MGMT_SUPPORTED_CHANN_NOT_VALID,
        'INVALID_CONTENT': D11MGMT_INVALID_CONTENT,
        'MIC_FAIL': D11MGMT_MIC_FAIL,
        'HANDSHAKE_TIMEOUT': D11MGMT_HANDSHAKE_TIMEOUT,
        'GROUP_KEY_TIMEOUT': D11MGMT_GROUP_KEY_TIMEOUT,
        'WRONG_HANDSHAKE': D11MGMT_WRONG_HANDSHAKE,
        'INVALID_GROUP_CIPHER': D11MGMT_INVALID_GROUP_CIPHER,
        'INVALID_PAIRWISE_CIPHER': D11MGMT_INVALID_PAIRWISE_CIPHER,
        'INVALID_AKMP': D11MGMT_INVALID_AKMP,
        'UNSOPPORTED_RSN_VERSION': D11MGMT_UNSOPPORTED_RSN_VERSION,
        'INVALID_RSN_CAPABILITIES': D11MGMT_INVALID_RSN_CAPABILITIES,
        'AUTH_FAILED': D11MGMT_AUTH_FAILED,
        'CIPHER_SUITE_REJECTED': D11MGMT_CIPHER_SUITE_REJECTED,
        'UNSPECIFIED_QOS_REASON': D11MGMT_UNSPECIFIED_QOS_REASON,
        'NOT_ENOUGH_BANDWITH': D11MGMT_NOT_ENOUGH_BANDWITH,
        'POOR_CHANNEL': D11MGMT_POOR_CHANNEL,
        'STA_OUT_OF_LIMITS': D11MGMT_STA_OUT_OF_LIMITS,
        'REQUESTED_BY_STA_LEAVING': D11MGMT_REQUESTED_BY_STA_LEAVING,
        'REQUESTED_BY_STA_REJECT_MECHANISM': D11MGMT_REQUESTED_BY_STA_REJECT_MECHANISM,
        'REQUESTED_BY_STA_REJECT_SETUP': D11MGMT_REQUESTED_BY_STA_REJECT_SETUP,
        'REQUESTED_BY_STA_TIMEOUT': D11MGMT_REQUESTED_BY_STA_TIMEOUT,
        'PEER_STA_NOT_SUPPORT_CIPHER': D11MGMT_PEER_STA_NOT_SUPPORT_CIPHER
    })

    @property
    def frag_num(self):
        '''
        Fragment number field getter ('uint8')
        '''
        return <uint8_t> ((<cppDot11ManagementFrame*> self.ptr).frag_num())

    @frag_num.setter
    def frag_num(self, value):
        '''
        Fragment number field setter ('uint8')
        '''
        (<cppDot11ManagementFrame*> self.ptr).frag_num(small_uint4(<uint8_t> value))


    @property
    def seq_num(self):
        '''
        Sequence number field getter (`uint16_t`)
        '''
        return <uint16_t> ((<cppDot11ManagementFrame*> self.ptr).seq_num())

    @seq_num.setter
    def seq_num(self, value):
        '''
        Sequence number field setter (`uint16_t`)
        '''
        (<cppDot11ManagementFrame*> self.ptr).seq_num(small_uint12(<uint16_t> value))


    @property
    def addr2(self):
        '''
        Second address getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes>((<cppDot11ManagementFrame*> self.ptr).addr2().to_string()))

    @addr2.setter
    def addr2(self, value):
        '''
        Second address setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11ManagementFrame*> self.ptr).addr2((<HWAddress> value).ptr[0])


    @property
    def addr3(self):
        '''
        Third address getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes>((<cppDot11ManagementFrame*> self.ptr).addr3().to_string()))

    @addr3.setter
    def addr3(self, value):
        '''
        Third address setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11ManagementFrame*> self.ptr).addr3((<HWAddress> value).ptr[0])


    @property
    def addr4(self):
        '''
        Fourth address getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes>((<cppDot11ManagementFrame*> self.ptr).addr4().to_string()))

    @addr4.setter
    def addr4(self, value):
        '''
        Fourth address setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11ManagementFrame*> self.ptr).addr4((<HWAddress> value).ptr[0])


    @property
    def ssid(self):
        '''
        SSID field getter (`bytes`)
        '''
        try:
            return <bytes> ((<cppDot11ManagementFrame*> self.ptr).ssid())
        except OptionNotFound:
            return None

    @ssid.setter
    def ssid(self, value):
        '''
        SSID field setter (`bytes`)
        '''
        if value is None:
            pass    # todo: delete option
        value = bytes(value)
        (<cppDot11ManagementFrame*> self.ptr).ssid(<string> value)


    @property
    def rsn_information(self):
        '''
        RSN information option getter (:py:class:`~.RSNInformation`)
        '''
        cdef cppRSNInformation info
        try:
            info = (<cppDot11ManagementFrame*> self.ptr).rsn_information()
        except OptionNotFound:
            return None
        return RSNInformation.factory(&info)

    @rsn_information.setter
    def rsn_information(self, info):
        '''
        RSN information option setter (:py:class:`~.RSNInformation`)
        '''
        if not isinstance(info, RSNInformation):
            info = RSNInformation.from_buffer(info)
        (<cppDot11ManagementFrame*> self.ptr).rsn_information((<RSNInformation> info).ptr[0])


    @property
    def supported_rates(self):
        '''
        Supported rates getter (`list of floats`)
        '''
        try:
            return list((<cppDot11ManagementFrame*> self.ptr).supported_rates())
        except OptionNotFound:
            return None

    @supported_rates.setter
    def supported_rates(self, values):
        '''
        Supported rates setter (`list of floats`)
        '''
        cdef vector[float] rates = [float(rate) for rate in values]
        (<cppDot11ManagementFrame*> self.ptr).supported_rates(rates)


    @property
    def extended_supported_rates(self):
        '''
        Extended supported rates getter (`list of floats`)
        '''
        try:
            return list((<cppDot11ManagementFrame*> self.ptr).extended_supported_rates())
        except OptionNotFound:
            return None

    @extended_supported_rates.setter
    def extended_supported_rates(self, values):
        '''
        Extended supported rates setter (`list of floats`)
        '''
        cdef vector[float] rates = [float(rate) for rate in values]
        (<cppDot11ManagementFrame*> self.ptr).extended_supported_rates(rates)


    @property
    def qos_capability(self):
        '''
        QoS capability getter (`uint8_t`)
        '''
        try:
            return (<cppDot11ManagementFrame*> self.ptr).qos_capability()
        except OptionNotFound:
            return None

    @qos_capability.setter
    def qos_capability(self, value):
        '''
        QoS capability setter (`uint8_t`)
        '''
        (<cppDot11ManagementFrame*> self.ptr).qos_capability(<uint8_t> int(value))


    @property
    def power_capability(self):
        '''
        Power capability getter (`uint8_t`)
        '''
        try:
            return <tuple>((<cppDot11ManagementFrame*> self.ptr).power_capability())
        except OptionNotFound:
            return None

    @power_capability.setter
    def power_capability(self, pair_values):
        '''
        Power capability setter (`uint8_t`)
        '''
        (<cppDot11ManagementFrame*> self.ptr).power_capability(<uint8_t> int(pair_values[0]), <uint8_t> int(pair_values[1]))


    @property
    def supported_channels(self):
        '''
        Supported channels field getter (`list of uint8_t`)
        '''
        try:
            return [(p.first, p.second) for p in (<cppDot11ManagementFrame*> self.ptr).supported_channels()]
        except OptionNotFound:
            return None

    @supported_channels.setter
    def supported_channels(self, channels):
        '''
        Supported channels field setter (`list of uint8_t`)
        '''
        (<cppDot11ManagementFrame*> self.ptr).supported_channels(<vector[pair[uint8_t, uint8_t]]> channels)


    @property
    def request_information(self):
        '''
        Request information field getter (`list of uint8_t`)
        '''
        try:
            return <list> ((<cppDot11ManagementFrame*> self.ptr).request_information())
        except OptionNotFound:
            return None

    @request_information.setter
    def request_information(self, elements):
        '''
        Request information field setter (`list of uint8_t`)
        '''
        (<cppDot11ManagementFrame*> self.ptr).request_information(<vector[uint8_t]> elements)


    @property
    def fh_parameter_set(self):
        '''
        fh paramater set tagged option getter (:py:class:`~.fh_params`)
        '''
        cdef cppDot11ManagementFrame.fh_params_set s
        try:
            s = (<cppDot11ManagementFrame*> self.ptr).fh_parameter_set()
            return fh_params(s.dwell_time, s.hop_set, s.hop_pattern, s.hop_index)
        except OptionNotFound:
            return None

    @fh_parameter_set.setter
    def fh_parameter_set(self, value):
        '''
        fh paramater set tagged option setter (:py:class:`~.fh_params`)
        '''
        dwell_time, hop_set, hop_pattern, hop_index = value
        cdef cppDot11ManagementFrame.fh_params_set s = cppDot11ManagementFrame.fh_params_set(
            <uint16_t> dwell_time, <uint8_t> hop_set, <uint8_t> hop_pattern, <uint8_t> hop_index
        )
        (<cppDot11ManagementFrame*> self.ptr).fh_parameter_set(s)


    @property
    def ds_parameter_set(self):
        '''
        ds paramater set getter (`uint8_t`)
        '''
        try:
            return int((<cppDot11ManagementFrame*> self.ptr).ds_parameter_set())
        except OptionNotFound:
            return None

    @ds_parameter_set.setter
    def ds_parameter_set(self, value):
        '''
        ds paramater set setter (`uint8_t`)
        '''
        (<cppDot11ManagementFrame*> self.ptr).ds_parameter_set(<uint8_t> int(value))


    @property
    def cf_parameter_set(self):
        '''
        cf paramater set tagged option  getter (:py:class:`~.cf_params`)
        '''
        cdef cppDot11ManagementFrame.cf_params_set s
        try:
            s = (<cppDot11ManagementFrame*> self.ptr).cf_parameter_set()
            return cf_params(s.cfp_count, s.cfp_period, s.cfp_max_duration, s.cfp_dur_remaining)
        except OptionNotFound:
            return None

    @cf_parameter_set.setter
    def cf_parameter_set(self, value):
        '''
        cf paramater set tagged option setter (:py:class:`~.cf_params`)
        '''
        cfp_count, cfp_period, cfp_max_duration, cfp_dur_remaining = value
        cdef cppDot11ManagementFrame.cf_params_set s = cppDot11ManagementFrame.cf_params_set(
            <uint8_t> cfp_count, <uint8_t> cfp_period, <uint16_t> cfp_max_duration, <uint16_t> cfp_dur_remaining
        )
        (<cppDot11ManagementFrame*> self.ptr).cf_parameter_set(s)


    @property
    def ibss_parameter_set(self):
        '''
        ibss parameter getter (`uint8_t`)
        '''
        try:
            return (<cppDot11ManagementFrame*> self.ptr).ibss_parameter_set()
        except OptionNotFound:
            return None

    @ibss_parameter_set.setter
    def ibss_parameter_set(self, value):
        '''
        ibss parameter setter (`uint8_t`)
        '''
        (<cppDot11ManagementFrame*> self.ptr).ibss_parameter_set(<uint16_t> int(value))


    @property
    def ibss_dfs(self):
        '''
        IBSS DFS tagged option getter (:py:class:`~.dfs_params`)
        '''
        cdef cppDot11ManagementFrame.ibss_dfs_params p
        try:
            p = (<cppDot11ManagementFrame*> self.ptr).ibss_dfs()
        except OptionNotFound:
            return None
        dfs_owner = HWAddress(<bytes> (p.dfs_owner.to_string()))
        channel_map = [(int(apair.first), int(apair.second)) for apair in p.channel_map]
        return dfs_params(dfs_owner, int(p.recovery_interval), channel_map)

    @ibss_dfs.setter
    def ibss_dfs(self, value):
        '''
        IBSS DFS tagged option setter (:py:class:`~.dfs_params`)
        '''
        dfs_owner, recovery_interval, channel_map = value
        if not isinstance(dfs_owner, HWAddress):
            dfs_owner = HWAddress(dfs_owner)
        recovery_interval = int(recovery_interval)
        cdef vector[pair[uint8_t, uint8_t]] channels
        cdef pair[uint8_t, uint8_t] apair
        for (x, y) in channel_map:
            apair.first = <uint8_t> int(x)
            apair.second = <uint8_t> int(y)
            channels.push_back(apair)
        cdef cppDot11ManagementFrame.ibss_dfs_params params = cppDot11ManagementFrame.ibss_dfs_params(
            (<HWAddress> dfs_owner).ptr[0], <uint8_t> recovery_interval, channels
        )
        (<cppDot11ManagementFrame*> self.ptr).ibss_dfs(params)


    @property
    def country(self):
        '''
        country tagged option getter (:py:class:`~.country_params`)
        '''
        cdef cppDot11ManagementFrame.country_params country_p
        try:
            country_p = (<cppDot11ManagementFrame*> self.ptr).country()
        except OptionNotFound:
            return None
        country_name = <bytes> country_p.country
        first_channel = <list> country_p.first_channel
        number_channels = <list> country_p.number_channels
        max_transmit_power = <list> country_p.max_transmit_power
        return country_params(country_name, first_channel, number_channels, max_transmit_power)

    @country.setter
    def country(self, value):
        '''
        country tagged option getter (:py:class:`~.country_params`)
        '''
        country_name, first_channel, number_channels, max_transmit_power = value
        cdef vector[uint8_t] first_channel_v = first_channel
        cdef vector[uint8_t] number_channels_v = number_channels
        cdef vector[uint8_t] max_transmit_power_v = max_transmit_power
        cdef cppDot11ManagementFrame.country_params params = cppDot11ManagementFrame.country_params(
            <string> country_name, first_channel_v, number_channels_v, max_transmit_power_v
        )
        (<cppDot11ManagementFrame*> self.ptr).country(params)


    @property
    def fh_parameters(self):
        '''
        FH parameters set tagged option getter (`(uint8_t, uint8_t)`)
        '''
        cdef pair[uint8_t, uint8_t] apair
        try:
            apair = (<cppDot11ManagementFrame*> self.ptr).fh_parameters()
        except OptionNotFound:
            return None
        return apair.first, apair.second

    @fh_parameters.setter
    def fh_parameters(self, value):
        '''
        FH parameters set tagged option setter (`(uint8_t, uint8_t)`)
        '''
        first, second = value
        (<cppDot11ManagementFrame*> self.ptr).fh_parameters(<uint8_t> int(first), <uint8_t> int(second))


    @property
    def fh_pattern_table(self):
        '''
        FH pattern table tagged option getter (:py:class:`~.fh_pattern`)
        '''
        cdef cppDot11ManagementFrame.fh_pattern_type t
        try:
            t = (<cppDot11ManagementFrame*> self.ptr).fh_pattern_table()
        except OptionNotFound:
            return None
        random_table = <list> t.random_table
        return fh_pattern(int(t.flag), int(t.number_of_sets), int(t.modulus), int(t.offset), random_table)

    @fh_pattern_table.setter
    def fh_pattern_table(self, value):
        '''
        FH pattern table tagged option setter (:py:class:`~.fh_pattern`)
        '''
        flag, number_of_sets, modulus, offset, random_table = value
        cdef vector[uint8_t] random_table_v = random_table
        cdef cppDot11ManagementFrame.fh_pattern_type t = cppDot11ManagementFrame.fh_pattern_type(
            <uint8_t> int(flag), <uint8_t> int(number_of_sets), <uint8_t> int(modulus), <uint8_t> int(offset), random_table_v
        )
        (<cppDot11ManagementFrame*> self.ptr).fh_pattern_table(t)


    @property
    def power_constraint(self):
        '''
        Power constraint getter ('int')
        '''
        try:
            return int((<cppDot11ManagementFrame*> self.ptr).power_constraint())
        except OptionNotFound:
            return None

    @power_constraint.setter
    def power_constraint(self, value):
        '''
        Power constraint setter ('int')
        '''
        (<cppDot11ManagementFrame*> self.ptr).power_constraint(<uint8_t>int(value))


    @property
    def channel_switch(self):
        '''
        Channel switch getter (:py:class:`~.channel_switch_t`)
        '''
        cdef cppDot11ManagementFrame.channel_switch_type c
        try:
            c = (<cppDot11ManagementFrame*> self.ptr).channel_switch()
        except OptionNotFound:
            return None
        return channel_switch_t(int(c.switch_mode), int(c.new_channel), int(c.switch_count))

    @channel_switch.setter
    def channel_switch(self, value):
        '''
        Channel switch setter (:py:class:`~.channel_switch_t`)
        '''
        switch_mode, new_channel, switch_count = value
        cdef cppDot11ManagementFrame.channel_switch_type c = cppDot11ManagementFrame.channel_switch_type(
            <uint8_t> int(switch_mode), <uint8_t> int(new_channel), <uint8_t> int(switch_count)
        )
        (<cppDot11ManagementFrame*> self.ptr).channel_switch(c)


    @property
    def quiet(self):
        '''
        Quiet tagged option getter (:py:class:`~.quiet_t`)
        '''
        cdef cppDot11ManagementFrame.quiet_type q
        try:
            q = (<cppDot11ManagementFrame*> self.ptr).quiet()
        except OptionNotFound:
            return None
        return quiet_t(int(q.quiet_count), int(q.quiet_period), int(q.quiet_duration), int(q.quiet_offset))

    @quiet.setter
    def quiet(self, value):
        '''
        Quiet tagged option setter (:py:class:`~.quiet_t`)
        '''
        quiet_count, quiet_period, quiet_duration, quiet_offset = value
        cdef cppDot11ManagementFrame.quiet_type q = cppDot11ManagementFrame.quiet_type(
            <uint8_t> int(quiet_count), <uint8_t> int(quiet_period), <uint16_t> int(quiet_duration), <uint16_t> int(quiet_offset)
        )
        (<cppDot11ManagementFrame*> self.ptr).quiet(q)


    @property
    def tpc_report(self):
        '''
        TPC Report tagged option getter (`(uint8_t, uint8_t)`)
        '''
        cdef pair[uint8_t, uint8_t] apair
        try:
            apair = (<cppDot11ManagementFrame*> self.ptr).tpc_report()
        except OptionNotFound:
            return None
        return int(apair.first), int(apair.second)

    @tpc_report.setter
    def tpc_report(self, value):
        '''
        TPC Report tagged option setter (`(uint8_t, uint8_t)`)
        '''
        first, second = value
        (<cppDot11ManagementFrame*> self.ptr).tpc_report(<uint8_t> int(first), <uint8_t> int(second))


    @property
    def erp_information(self):
        '''
        ERP information getter ('int')
        '''
        try:
            return int((<cppDot11ManagementFrame*> self.ptr).erp_information())
        except OptionNotFound:
            return None

    @erp_information.setter
    def erp_information(self, value):
        '''
        ERP information setter ('int')
        '''
        (<cppDot11ManagementFrame*> self.ptr).erp_information(<uint8_t> int(value))


    @property
    def bss_load(self):
        '''
        BSS Load tagged option getter (:py:class:`~.bss_load_t`)
        '''
        cdef cppDot11ManagementFrame.bss_load_type bss
        try:
            bss = (<cppDot11ManagementFrame*> self.ptr).bss_load()
        except OptionNotFound:
            return None
        return bss_load_t(int(bss.station_count), int(bss.channel_utilization), int(bss.available_capacity))

    @bss_load.setter
    def bss_load(self, value):
        '''
        BSS Load tagged option setter (:py:class:`~.bss_load_t`)
        '''
        station_count, channel_utilization, available_capacity = value
        cdef cppDot11ManagementFrame.bss_load_type bss = cppDot11ManagementFrame.bss_load_type(
            <uint16_t> int(station_count), <uint8_t> int(channel_utilization), <uint16_t> int(available_capacity)
        )
        (<cppDot11ManagementFrame*> self.ptr).bss_load(bss)


    @property
    def tim(self):
        '''
        TIM tagged option getter (:py:class:`~.tim_t`)
        '''
        cdef cppDot11ManagementFrame.tim_type t
        try:
            t = (<cppDot11ManagementFrame*> self.ptr).tim()
        except OptionNotFound:
            return None
        bitmap = <list> t.partial_virtual_bitmap
        return tim_t(int(t.dtim_count), int(t.dtim_period), int(t.bitmap_control), bitmap)

    @tim.setter
    def tim(self, value):
        '''
        TIM tagged option setter (:py:class:`~.tim_t`)
        '''
        dtim_count, dtim_period, bitmap_control, bitmap = value
        cdef vector[uint8_t] bitmap_v = [int(x) for x in bitmap]
        cdef cppDot11ManagementFrame.tim_type t = cppDot11ManagementFrame.tim_type(
            <uint8_t> int(dtim_count), <uint8_t> int(dtim_period), <uint8_t> int(bitmap_control), bitmap_v
        )
        (<cppDot11ManagementFrame*> self.ptr).tim(t)


    @property
    def vendor_specific(self):
        '''
        Vendor Specific tagged option getter (:py:class:`~.vendor_specific_t`)
        '''
        cdef cppDot11ManagementFrame.vendor_specific_type vendor
        try:
            vendor = (<cppDot11ManagementFrame*> self.ptr).vendor_specific()
        except OptionNotFound:
            return None
        addr = <bytes> (vendor.oui.to_string())
        data = <list> vendor.data
        return vendor_specific_t(addr, data)

    @vendor_specific.setter
    def vendor_specific(self, value):
        '''
        Vendor Specific tagged option setter (:py:class:`~.vendor_specific_t`)
        '''
        cdef cppHWAddress3 addr = cppHWAddress3(<string> bytes(value[0]))
        cdef vector[uint8_t] data = [int(x) for x in value[1]]
        cdef cppDot11ManagementFrame.vendor_specific_type vendor = cppDot11ManagementFrame.vendor_specific_type(addr, data)
        (<cppDot11ManagementFrame*> self.ptr).vendor_specific(vendor)


    @property
    def challenge_text(self):
        '''
        challenge text option getter (`bytes`)
        '''
        try:
            return <bytes>((<cppDot11ManagementFrame*> self.ptr).challenge_text())
        except OptionNotFound:
            return None

    @challenge_text.setter
    def challenge_text(self, value):
        '''
        challenge text option getter (`bytes`)
        '''
        (<cppDot11ManagementFrame*> self.ptr).challenge_text(<string> bytes(value))



cdef class Capabilities(object):
    '''
    Represents the IEEE 802.11 frames's capability information.
    '''
    def __cinit__(self):
        pass

    def __init__(self):
        pass

    def __dealloc__(self):
        pass

    @staticmethod
    cdef factory(cppDot11ManagementFrame.capability_information& info):
        '''
        Make a Capabilities object from a C++ capabilities object.

        Parameters
        ----------
        info: cppDot11ManagementFrame.capability_information
        '''
        obj = Capabilities()
        (<Capabilities> obj).cap_info = info
        return obj


    @property
    def ess(self):
        '''
        ess flag getter (`bool`)
        '''
        return bool(self.cap_info.ess())

    @ess.setter
    def ess(self, value):
        '''
        ess flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.ess(val)


    @property
    def ibss(self):
        '''
        ibss flag getter (`bool`)
        '''
        return bool(self.cap_info.ibss())

    @ibss.setter
    def ibss(self, value):
        '''
        ibss flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.ibss(val)


    @property
    def cf_poll(self):
        '''
        cf_poll flag getter (`bool`)
        '''
        return bool(self.cap_info.cf_poll())

    @cf_poll.setter
    def cf_poll(self, value):
        '''
        cf_poll flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.cf_poll(val)


    @property
    def cf_poll_req(self):
        '''
        cf_poll_req flag getter (`bool`)
        '''
        return bool(self.cap_info.cf_poll_req())

    @cf_poll_req.setter
    def cf_poll_req(self, value):
        '''
        cf_poll_req flag (read-write, `bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.cf_poll_req(val)


    @property
    def privacy(self):
        '''
        privacy flag getter (`bool`)
        '''
        return bool(self.cap_info.privacy())

    @privacy.setter
    def privacy(self, value):
        '''
        privacy flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.privacy(val)


    @property
    def short_preamble(self):
        '''
        short_preamble flag getter (`bool`)
        '''
        return bool(self.cap_info.short_preamble())

    @short_preamble.setter
    def short_preamble(self, value):
        '''
        short_preamble flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.short_preamble(val)


    @property
    def pbcc(self):
        '''
        pbcc flag getter (`bool`)
        '''
        return bool(self.cap_info.pbcc())

    @pbcc.setter
    def pbcc(self, value):
        '''
        pbcc flag (read-write, `bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.pbcc(val)


    @property
    def channel_agility(self):
        '''
        channel_agility flag getter (`bool`)
        '''
        return bool(self.cap_info.channel_agility())

    @channel_agility.setter
    def channel_agility(self, value):
        '''
        channel_agility flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.channel_agility(val)


    @property
    def spectrum_mgmt(self):
        '''
        spectrum_mgmt flag getter (`bool`)
        '''
        return bool(self.cap_info.spectrum_mgmt())

    @spectrum_mgmt.setter
    def spectrum_mgmt(self, value):
        '''
        spectrum_mgmt flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.spectrum_mgmt(val)


    @property
    def qos(self):
        '''
        qos flag getter (`bool`)
        '''
        return bool(self.cap_info.qos())

    @qos.setter
    def qos(self, value):
        '''
        qos flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.qos(val)


    @property
    def flas(self):
        '''
        sst flag getter (`bool`)
        '''
        return bool(self.cap_info.sst())

    @flag.setter
    def flag(self, value):
        '''
        sst flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.sst(val)


    @property
    def apsd(self):
        '''
        apsd flag getter (`bool`)
        '''
        return bool(self.cap_info.apsd())

    @apsd.setter
    def apsd(self, value):
        '''
        apsd flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.apsd(val)


    @property
    def radio_measurement(self):
        '''
        radio_measurement flag getter (`bool`)
        '''
        return bool(self.cap_info.radio_measurement())

    @radio_measurement.setter
    def radio_measurement(self, value):
        '''
        radio_measurement flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.radio_measurement(val)


    @property
    def dss_ofdm(self):
        '''
        dsss_ofdm flag getter (`bool`)
        '''
        return bool(self.cap_info.dsss_ofdm())

    @dsss_ofdm.setter
    def dsss_ofdm(self, value):
        '''
        dsss_ofdm flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.dsss_ofdm(val)


    @property
    def delayed_block_ack(self):
        '''
        delayed_block_ack flag getter (`bool`)
        '''
        return bool(self.cap_info.delayed_block_ack())

    @delayed_block_ack.setter
    def delayed_block_ack(self, value):
        '''
        delayed_block_ack flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.delayed_block_ack(val)


    @property
    def immediate_block_ack(self):
        '''
        immediate_block_ack flag getter (`bool`)
        '''
        return bool(self.cap_info.immediate_block_ack())

    @immediate_block_ack.setter
    def immediate_block_ack(self, value):
        '''
        immediate_block_ack flag setter (`bool`)
        '''
        cdef cpp_bool val = 1 if value else 0
        self.cap_info.immediate_block_ack(val)


cdef class Dot11Disassoc(Dot11ManagementFrame):
    '''
    802.11 Disassociation frame
    '''
    pdu_flag = PDU.DOT11_DIASSOC
    pdu_type = PDU.DOT11_DIASSOC

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11Disassoc:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11Disassoc((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Disassoc* p = <cppDot11Disassoc*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def reason_code(self):
        '''
        reason code field getter ('int')
        '''
        return int((<cppDot11Disassoc*> self.ptr).reason_code())

    @reason_code.setter
    def reason_code(self, value):
        '''
        reason code field setter ('int')
        '''
        (<cppDot11Disassoc*> self.ptr).reason_code(<uint16_t> int(value))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11Disassoc(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11Disassoc*> ptr


cdef class Dot11AssocRequest(Dot11ManagementFrame):
    '''
    802.11 Association Request frame
    '''
    pdu_flag = PDU.DOT11_ASSOC_REQ
    pdu_type = PDU.DOT11_ASSOC_REQ

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11AssocRequest:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11AssocRequest((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11AssocRequest* p = <cppDot11AssocRequest*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def listen_interval(self):
        '''
        listen interval field getter ('int')
        '''
        return int((<cppDot11AssocRequest*> self.ptr).listen_interval())

    @listen_interval.setter
    def listen_interval(self, value):
        '''
        listen interval field setter ('int')
        '''
        (<cppDot11AssocRequest*> self.ptr).listen_interval(<uint16_t> int(value))


    @property
    def capabilities_get(self):
        '''
        Capabilities getter (:py:class:`~.Capabilities`)
        '''
        return Capabilities.factory((<cppDot11AssocRequest*> self.ptr).capabilities())


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11AssocRequest(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11AssocRequest*> ptr


cdef class Dot11AssocResponse(Dot11ManagementFrame):
    '''
    802.11 Association Response frame
    '''
    pdu_flag = PDU.DOT11_ASSOC_RESP
    pdu_type = PDU.DOT11_ASSOC_RESP

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11AssocResponse:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11AssocResponse((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11AssocResponse* p = <cppDot11AssocResponse*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)

    @property
    def status_code(self):
        '''
        status code field getter ('int')
        '''
        return int((<cppDot11AssocResponse*> self.ptr).status_code())

    @status_code.setter
    def status_code(self, value):
        '''
        status code field setter ('int')
        '''
        (<cppDot11AssocResponse*> self.ptr).status_code(<uint16_t> int(value))


    @property
    def aid(self):
        '''
        AID field getter('int')
        '''
        return int((<cppDot11AssocResponse*> self.ptr).aid())

    @aid.setter
    def aid(self, value):
        '''
        AID field setter ('int')
        '''
        (<cppDot11AssocResponse*> self.ptr).aid(<uint16_t> int(value))


    @property
    def capabilities(self):
        '''
        Capabilities getter (:py:class:`~.Capabilities`)
        '''
        return Capabilities.factory((<cppDot11AssocResponse*> self.ptr).capabilities())


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11AssocResponse(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11AssocResponse*> ptr


cdef class Dot11ReAssocRequest(Dot11ManagementFrame):
    '''
    802.11 ReAssociation Request frame
    '''
    pdu_flag = PDU.DOT11_REASSOC_REQ
    pdu_type = PDU.DOT11_REASSOC_REQ

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11ReAssocRequest:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11ReAssocRequest((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11ReAssocRequest* p = <cppDot11ReAssocRequest*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)

    @property
    def capabilities(self):
        '''
        Capabilities getter (:py:class:`~.Capabilities`)
        '''
        return Capabilities.factory((<cppDot11ReAssocRequest*> self.ptr).capabilities())


    @property
    def listen_interval(self):
        '''
        listen interval field getter ('int')
        '''
        return int((<cppDot11ReAssocRequest*> self.ptr).listen_interval())

    @listen_interval.setter
    def listen_interval(self, value):
        '''
        listen interval field setter ('int')
        '''
        (<cppDot11ReAssocRequest*> self.ptr).listen_interval(<uint16_t> int(value))


    @property
    def current_ap(self):
        '''
        current ap field getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes> ((<cppDot11ReAssocRequest*> self.ptr).current_ap().to_string()))

    @current_ap.setter
    def current_ap(self, value):
        '''
        current ap field setter (:py:class:`~.HWAddress`)
        '''
        if not(isinstance(value, HWAddress)):
            value = HWAddress(value)
        (<cppDot11ReAssocRequest*> self.ptr).current_ap((<HWAddress> value).ptr[0])


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11ReAssocRequest(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11ReAssocRequest*> ptr


cdef class Dot11ReAssocResponse(Dot11ManagementFrame):
    '''
    802.11 Association Response frame
    '''
    pdu_flag = PDU.DOT11_REASSOC_RESP
    pdu_type = PDU.DOT11_REASSOC_RESP

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw or type(self) != Dot11ReAssocResponse:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11ReAssocResponse((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11ReAssocResponse* p = <cppDot11ReAssocResponse*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)

    @property 
    def capabilities(self):
        '''
        Capabilities getter (:py:class:`~.Capabilities`)
        '''
        return Capabilities.factory((<cppDot11ReAssocResponse*> self.ptr).capabilities())


    @property
    def status_code(self):
        '''
        Status code getter ('int')
        '''
        return int((<cppDot11ReAssocResponse*> self.ptr).status_code())

    @status_code.setter
    def status_code(self, value):
        '''
        Status code setter ('int')
        '''
        (<cppDot11ReAssocResponse*> self.ptr).status_code(<uint16_t> int(value))


    @property
    def aid(self):
        '''
        AID field getter ('int')
        '''
        return int((<cppDot11ReAssocResponse*> self.ptr).aid())

    @aid.setter
    def aid(self, value):
        '''
        AID field setter ('int')
        '''
        (<cppDot11ReAssocResponse*> self.ptr).aid(<uint16_t> int(value))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11ReAssocResponse(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11ReAssocResponse*> ptr


cdef class Dot11Authentication(Dot11ManagementFrame):
    '''
    802.11 Authentication Request frame.
    '''
    pdu_flag = PDU.DOT11_AUTH
    pdu_type = PDU.DOT11_AUTH

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11Authentication:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11Authentication((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Authentication* p = <cppDot11Authentication*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def status_code(self):
        '''
        Status code getter ('int')
        '''
        return int((<cppDot11Authentication*> self.ptr).status_code())

    @status_code.setter
    def status_code(self, value):
        '''
        Status code setter ('int')
        '''
        (<cppDot11Authentication*> self.ptr).status_code(<uint16_t> int(value))


    @property 
    def auth_algorithm(self):
        '''
        Authetication algorithm number field getter ('int')
        '''
        return int((<cppDot11Authentication*> self.ptr).auth_algorithm())

    @auth_algorithm.setter
    def auth_algorithm(self, value):
        '''
        Authetication algorithm number field setter ('int')
        '''
        (<cppDot11Authentication*> self.ptr).auth_algorithm(<uint16_t> int(value))


    @property
    def auth_seq_number(self):
        '''
        Authentication sequence number field getter ('int')
        '''
        return int((<cppDot11Authentication*> self.ptr).auth_seq_number())
    @auth_seq_number.setter
    def auth_seq_number(self, value):
        '''
        Authentication sequence number field getter ('int')
        '''
        (<cppDot11Authentication*> self.ptr).auth_seq_number(<uint16_t> int(value))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11Authentication(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11Authentication*> ptr


cdef class Dot11Deauthentication(Dot11ManagementFrame):
    '''
    802.11 Deauthentication frame.
    '''
    pdu_flag = PDU.DOT11_DEAUTH
    pdu_type = PDU.DOT11_DEAUTH

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11Deauthentication:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11Deauthentication((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Deauthentication* p = <cppDot11Deauthentication*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def reason_code(self):
        '''
        reason code field getter ('int')
        '''
        return int((<cppDot11Deauthentication*> self.ptr).reason_code())

    @reason_code.setter
    def reason_code(self, value):
        '''
        reason code field setter ('int')
        '''
        (<cppDot11Deauthentication*> self.ptr).reason_code(<uint16_t> int(value))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11Deauthentication(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11Deauthentication*> ptr


cdef class Dot11Beacon(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_BEACON
    pdu_type = PDU.DOT11_BEACON

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11Beacon:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11Beacon((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Beacon* p = <cppDot11Beacon*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def timestamp(self):
        '''
        the timestamp field getter ('int')
        '''
        return int((<cppDot11Beacon*> self.ptr).timestamp())

    @timestamp.setter
    def timestamp(self, value):
        '''
        the timestamp field setter ('int')
        '''
        (<cppDot11Beacon*> self.ptr).timestamp(<uint64_t> int(value))


    @property
    def interval(self):
        '''
        the interval field getter ('int')
        '''
        return int((<cppDot11Beacon*> self.ptr).interval())

    @interval.setter
    def interval(self, value):
        '''
        the interval field setter ('int')
        '''
        (<cppDot11Beacon*> self.ptr).interval(<uint16_t> int(value))


    @property
    def capabilities(self):
        '''
        Capabilities getter (:py:class:`~.Capabilities`)
        '''
        return Capabilities.factory((<cppDot11Beacon*> self.ptr).capabilities())


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11Beacon(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11Beacon*> ptr


cdef class Dot11ProbeRequest(Dot11ManagementFrame):
    '''
    802.11 Probe Request frame.
    '''
    pdu_flag = PDU.DOT11_PROBE_REQ
    pdu_type = PDU.DOT11_PROBE_REQ

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11ProbeRequest:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11ProbeRequest((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11ProbeRequest* p = <cppDot11ProbeRequest*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11ProbeRequest(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11ProbeRequest*> ptr


cdef class Dot11ProbeResponse(Dot11ManagementFrame):
    '''
    802.11 Probe Response frame.
    '''
    pdu_flag = PDU.DOT11_PROBE_RESP
    pdu_type = PDU.DOT11_PROBE_RESP

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11ProbeResponse:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11ProbeResponse((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11ProbeResponse* p = <cppDot11ProbeResponse*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11ManagementFrame.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def timestamp(self):
        '''
        the timestamp field getter ('int')
        '''
        return int((<cppDot11ProbeResponse*> self.ptr).timestamp())

    @timestamp.setter
    def timestamp(self, value):
        '''
        the timestamp field setter ('int')
        '''
        (<cppDot11ProbeResponse*> self.ptr).timestamp(<uint64_t> int(value))


    @property
    def interval(self):
        '''
        interval field getter ('int')
        '''
        return int((<cppDot11ProbeResponse*> self.ptr).interval())

    @interval.setter
    def interval(self, value):
        '''
        interval field getter ('int')
        '''
        (<cppDot11ProbeResponse*> self.ptr).interval(<uint16_t> int(value))


    @property
    def capabilities(self):
        '''
        Capabilities getter (:py:class:`~.Capabilities`)
        '''
        return Capabilities.factory((<cppDot11ProbeResponse*> self.ptr).capabilities())


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11ProbeResponse(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11ProbeResponse*> ptr


cdef class Dot11Control(Dot11):
    '''
    802.11 control frame
    '''
    pdu_flag = PDU.DOT11_CONTROL
    pdu_type = PDU.DOT11_CONTROL

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):         # src is ignored
        if _raw is True or type(self) != Dot11Control:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)

        self.ptr = new cppDot11Control((<HWAddress> dst_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Control* p = <cppDot11Control*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: any
            ignored
        '''
        Dot11.__init__(self, dst_hw_addr, src_hw_addr)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11Control(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11Control*> ptr


cdef class Dot11RTS(Dot11Control):
    '''
    IEEE 802.11 RTS frame.
    '''
    pdu_flag = PDU.DOT11_RTS
    pdu_type = PDU.DOT11_RTS

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11RTS:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11RTS((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11RTS* p = <cppDot11RTS*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11Control.__init__(self, dst_hw_addr, src_hw_addr)


    @property 
    def target_addr(self):
        '''
        target address field getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

    @target_addr.setter
    def target_addr(self, value):
        '''
        target address field setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11RTS(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11RTS*> ptr


cdef class Dot11PSPoll(Dot11Control):
    '''
    802.11 PS-Poll frame.
    '''
    pdu_flag = PDU.DOT11_PS_POLL
    pdu_type = PDU.DOT11_PS_POLL

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11PSPoll:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11PSPoll((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11PSPoll* p = <cppDot11PSPoll*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11Control.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def target_addr(self):
        '''
        target address field getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

    @target_addr.setter
    def target_addr(self, value):
        '''
        target address field setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11PSPoll(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11PSPoll*> ptr


cdef class Dot11CFEnd(Dot11Control):
    '''
    802.11 CF-End frame.
    '''
    pdu_flag = PDU.DOT11_CF_END
    pdu_type = PDU.DOT11_CF_END

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11CFEnd:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11CFEnd((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11CFEnd* p = <cppDot11CFEnd*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11Control.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def target_addr(self):
        '''
        target address field getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

    @target_addr.setter
    def target_addr(self, value):
        '''
        target address field setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11CFEnd(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11CFEnd*> ptr


cdef class Dot11EndCFAck(Dot11Control):
    '''
    802.11 End-CF-Ack frame.
    '''
    pdu_flag = PDU.DOT11_END_CF_ACK
    pdu_type = PDU.DOT11_END_CF_ACK

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11EndCFAck:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11EndCFAck((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11EndCFAck* p = <cppDot11EndCFAck*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11Control.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def target_addr(self):
        '''
        target address field getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

    @target_addr.setter
    def target_addr(self, value):
        '''
        target address field setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11EndCFAck(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11EndCFAck*> ptr


cdef class Dot11Ack(Dot11Control):
    '''
    802.11 Ack frame.
    '''
    pdu_flag = PDU.DOT11_ACK
    pdu_type = PDU.DOT11_ACK

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11Ack:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)

        self.ptr = new cppDot11Ack((<HWAddress> dst_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Ack* p = <cppDot11Ack*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: any
            ignored
        '''
        Dot11Control.__init__(self, dst_hw_addr, src_hw_addr)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11Ack(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11Ack*> ptr


cdef class Dot11BlockAckRequest(Dot11Control):
    '''
    802.11 Block Ack Request frame.
    '''
    pdu_flag = PDU.DOT11_BLOCK_ACK_REQ
    pdu_type = PDU.DOT11_BLOCK_ACK_REQ

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11BlockAckRequest:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11BlockAckRequest((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11BlockAckRequest* p = <cppDot11BlockAckRequest*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11Control.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def target_addr(self):
        '''
        target address field getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

    @target_addr.setter
    def target_addr(self, value):
        '''
        target address field setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])


    @property
    def bar_control(self):
        '''
        bar control field getter ('int')
        '''
        return int(<uint8_t>((<cppDot11BlockAckRequest*> self.ptr).bar_control()))

    @bar_control.setter
    def bar_control(self, value):
        '''
        bar control field setter (`4-bits int`)
        '''
        (<cppDot11BlockAckRequest*> self.ptr).bar_control(small_uint4(<uint8_t>int(value)))


    @property
    def start_sequence(self):
        '''
        start sequence field getter ('int')
        '''
        return int(<uint16_t>((<cppDot11BlockAckRequest*> self.ptr).start_sequence()))

    @start_sequence.setter
    def start_sequence(self, value):
        '''
        start sequence field setter (`12-bits int`)
        '''
        (<cppDot11BlockAckRequest*> self.ptr).start_sequence(small_uint12(<uint16_t>int(value)))


    @property
    def fragment_number(self):
        '''
        fragment number field getter ('int')
        '''
        return int(<uint8_t>((<cppDot11BlockAckRequest*> self.ptr).fragment_number()))

    @fragment_number.setter
    def fragment_number(self, value):
        '''
        fragment number field setter (`4-bits int`)
        '''
        (<cppDot11BlockAckRequest*> self.ptr).fragment_number(small_uint4(<uint8_t>int(value)))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11BlockAckRequest(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11BlockAckRequest*> ptr


cdef class Dot11BlockAck(Dot11Control):
    '''
    802.11 Block Ack frame.
    '''
    pdu_flag = PDU.DOT11_BLOCK_ACK
    pdu_type = PDU.DOT11_BLOCK_ACK

    def __cinit__(self, dst_hw_addr=None, src_hw_addr=None, _raw=False):
        if _raw is True or type(self) != Dot11BlockAck:
            return

        if not isinstance(dst_hw_addr, HWAddress):
            dst_hw_addr = HWAddress(dst_hw_addr)
        if not isinstance(src_hw_addr, HWAddress):
            src_hw_addr = HWAddress(src_hw_addr)

        self.ptr = new cppDot11BlockAck((<HWAddress> dst_hw_addr).ptr[0], (<HWAddress> src_hw_addr).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11BlockAck* p = <cppDot11BlockAck*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dst_hw_addr=None, src_hw_addr=None):
        '''
        __init__(dst_hw_addr=None, src_hw_addr=None)

        Parameters
        ----------
        dst_hw_addr: :py:class:`~.HWAddress`
            The destination hardware address
        src_hw_addr: :py:class:`~.HWAddress`
            The source hardware address
        '''
        Dot11Control.__init__(self, dst_hw_addr, src_hw_addr)


    @property
    def target_addr(self):
        '''
        target address field getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

    @target_addr.setter
    def target_addr(self, value):
        '''
        target address field setter (:py:class:`~.HWAddress`)
        '''
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])


    @property
    def bar_control(self):
        '''
        bar control field getter ('int')
        '''
        return int(<uint8_t>((<cppDot11BlockAck*> self.ptr).bar_control()))

    @bar_control.setter
    def bar_control(self, value):
        '''
        bar control field setter ('int')
        '''
        (<cppDot11BlockAck*> self.ptr).bar_control(small_uint4(<uint8_t>int(value)))


    @property
    def start_sequence(self):
        '''
        start sequence field getter ('int')
        '''
        return int(<uint16_t>((<cppDot11BlockAck*> self.ptr).start_sequence()))

    @start_sequence.setter
    def start_sequence(self, value):
        '''
        start sequence field setter ('int')
        '''
        (<cppDot11BlockAck*> self.ptr).start_sequence(small_uint12(<uint16_t>int(value)))


    @property
    def fragment_number(self):
        '''
        fragment number field getter ('int')
        '''
        return int(<uint8_t>((<cppDot11BlockAck*> self.ptr).fragment_number()))

    @fragment_number.setter
    def fragment_number(self, value):
        '''
        fragment number field ('int')
        '''
        (<cppDot11BlockAck*> self.ptr).fragment_number(small_uint4(<uint8_t>int(value)))


    @property
    def bitmap(self):
        '''
        the bitmap field getter ('bytes')
        '''
        cdef uint8_t* b = <uint8_t*> ((<cppDot11BlockAck*> self.ptr).bitmap())
        return <bytes> b[:dot11_block_ack_bitmap_size]

    @bitmap.setter
    def bitmap(self, value):
        '''
        the bitmap field setter ('bytes')
        '''
        value = (bytes(value)[:dot11_block_ack_bitmap_size]).ljust(dot11_block_ack_bitmap_size, '\x00')
        (<cppDot11BlockAck*> self.ptr).bitmap(<uint8_t*>(<bytes>value))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot11BlockAck(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot11BlockAck*> ptr



