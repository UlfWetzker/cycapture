# -*- coding: utf-8 -*-

cdef class RadioTap(PDU):
    '''
    RadioTap packet
    '''
    pdu_flag = PDU.RADIOTAP
    pdu_type = PDU.RADIOTAP
    broadcast = HWAddress.broadcast
    datalink_type = DLT_IEEE802_11_RADIO

    ChannelType = make_enum('RT_ChannelType', 'ChannelType', 'Enumeration of the different channel types. See `RadioTap.channel`.', {
        'TURBO': RT_TURBO,
        'CCK': RT_CCK,
        'OFDM': RT_OFDM,
        'TWO_GZ': RT_TWO_GZ,
        'FIVE_GZ': RT_FIVE_GZ,
        'PASSIVE': RT_PASSIVE,
        'DYN_CCK_OFDM': RT_DYN_CCK_OFDM,
        'GFSK': RT_GFSK
    })

    PresentFlags = make_enum('RT_PresentFlags', 'PresentFlags', 'Flags used in the `RadioTap.present` property', {
        'TSTF': RT_TSTF,
        'FLAGS': RT_FLAGS,
        'RATE': RT_RATE,
        'CHANNEL': RT_CHANNEL,
        'FHSS': RT_FHSS,
        'DBM_SIGNAL': RT_DBM_SIGNAL,
        'DBM_NOISE': RT_DBM_NOISE,
        'LOCK_QUALITY': RT_LOCK_QUALITY,
        'TX_ATTENUATION': RT_TX_ATTENUATION,
        'DB_TX_ATTENUATION': RT_DB_TX_ATTENUATION,
        'DBM_TX_ATTENUATION': RT_DBM_TX_ATTENUATION,
        'ANTENNA': RT_ANTENNA,
        'DB_SIGNAL': RT_DB_SIGNAL,
        'DB_NOISE': RT_DB_NOISE,
        'RX_FLAGS': RT_RX_FLAGS,
        'TX_FLAGS': RT_TX_FLAGS,
        'DATA_RETRIES': RT_DATA_RETRIES,
        'CHANNEL_PLUS': RT_CHANNEL_PLUS,
        'MCS': RT_MCS
    })

    FrameFlags = make_enum('RT_FrameFlags', 'FrameFlags', 'Flags used in the `RadioTap.flags` property', {
        'CFP': RT_CFP,
        'PREAMBLE': RT_PREAMBLE,
        'WEP': RT_WEP,
        'FRAGMENTATION': RT_FRAGMENTATION,
        'FCS': RT_FCS,
        'PADDING': RT_PADDING,
        'FAILED_FCS': RT_FAILED_FCS,
        'SHORT_GI': RT_SHORT_GI
    })

    def __cinit__(self, _raw=False):
        if _raw:
            return
        self.ptr = new cppRadioTap()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self):
        '''
        __init__()
        '''

    cpdef send(self, PacketSender sender, NetworkInterface iface):
        if sender is None:
            raise ValueError("sender can't be None")
        if iface is None:
            raise ValueError("iface can't be None")
        self.ptr.send((<PacketSender> sender).ptr[0], (<NetworkInterface> iface).interface)


    @property
    def version(self):
        '''
        Version field getter ('int')
        '''
        return self.ptr.version()

    @version.setter
    def version(self, value):
        '''
        Version field setter ('int')
        '''
        self.ptr.version(<uint8_t> int(value))


    @property
    def padding(self):
        '''
        Padding getter ('int')
        '''
        return self.ptr.padding()

    @padding.setter    
    def padding(self, value):
        '''
        Padding setter ('int')
        '''
        self.ptr.padding(<uint8_t> int(value))


    @property
    def length(self):
        '''
        Length field getter ('int')
        '''
        return self.ptr.length()

    @length.setter
    def length(self, value):
        '''
        Length field setter ('int')
        '''
        self.ptr.length(<uint16_t> int(value))


    @property
    def tsft(self):
        '''
        Time Synchronisation Function Timer getter ('int')
        '''
        try:
            return self.ptr.tsft()
        except FieldNotPresent:
            return None

    @tsft.setter
    def tsft(self, value):
        '''
        Time Synchronisation Function Timer setter ('int')
        '''
        self.ptr.tsft(<uint64_t> int(value))


    @property
    def rate(self):
        '''
        Rate getter ('int')
        '''
        try:
            return self.ptr.rate()
        except FieldNotPresent:
            return None

    @rate.setter 
    def rate(self, value):
        '''
        Rate setter ('int')
        '''
        self.ptr.rate(<uint8_t> int(value))


    @property
    def dbm_signal(self):
        '''
        Dbm signal getter ('int')
        '''
        try:
            return self.ptr.dbm_signal()
        except FieldNotPresent:
            return None

    @dbm_signal.setter
    def dbm_signal(self, value):
        '''
        Dbm signal setter ('int')
        '''
        self.ptr.dbm_signal(<uint8_t> int(value))


    @property
    def dbm_noise(self):
        '''
        Dbm noise getter ('int')
        '''
        try:
            return self.ptr.dbm_noise()
        except FieldNotPresent:
            return None

    @dbm_noise.setter
    def dbm_noise(self, value):
        '''
        Dbm noise setter ('int')
        '''
        self.ptr.dbm_noise(<uint8_t> int(value))


    @property
    def signal_quality(self):
        '''
        Signal quality getter ('int')
        '''
        try:
            return self.ptr.signal_quality()
        except FieldNotPresent:
            return None

    @signal_quality.setter
    def signal_quality(self, value):
        '''
        Signal quality setter ('int')
        '''
        self.ptr.signal_quality(<uint8_t> int(value))


    @property
    def antenna(self):
        '''
        Antenna field getter ('int')
        '''
        try:
            return self.ptr.antenna()
        except FieldNotPresent:
            return None

    @antenna.setter
    def antenna(self, value):
        '''
        Antenna field setter ('int')
        '''
        self.ptr.antenna(<uint8_t> int(value))


    @property
    def db_signal(self):
        '''
        Db signal setter ('int')
        '''
        try:
            return self.ptr.db_signal()
        except FieldNotPresent:
            return None

    @db_signal.setter
    def db_signal(self, value):
        '''
        Db signal getter ('int')
        '''
        self.ptr.db_signal(<uint8_t> int(value))


    @property
    def rx_flags(self):
        '''
        Rx flags getter ('int')
        '''
        try:
            return self.ptr.rx_flags()
        except FieldNotPresent:
            return None

    @rx_flags.setter
    def rx_flags(self, value):
        '''
        Rx flags setter ('int')
        '''
        self.ptr.rx_flags(<uint16_t> int(value))


    @property
    def tx_flags(self):
        '''
        Tx flags getter ('int')
        '''
        try:
            return self.ptr.tx_flags()
        except FieldNotPresent:
            return None

    @tx_flags.setter
    def tx_flags(self, value):
        '''
        Tx flags setter ('int')
        '''
        self.ptr.tx_flags(<uint16_t> int(value))


    @property 
    def data_retries(self):
        '''
        Data retries getter ('int')
        '''
        try:
            return self.ptr.data_retries()
        except FieldNotPresent:
            return None

    @data_retries.setter
    def data_retries(self, value):
        '''
        Data retries setter ('int')
        '''
        self.ptr.data_retries(<uint8_t> int(value))


    @property
    def flags(self):
        '''
        Flags getter ('int')
        '''
        try:
            return int(self.ptr.flags())
        except FieldNotPresent:
            return None

    @flags.setter
    def flags(self, value):
        '''
        Flags setter ('int')
        '''
        value = int(value)
        self.ptr.flags(<RTFrameFlags> value)


    @property
    def channel_freq(self):
        '''
        Channel frequ getter ('int')
        '''
        try:
            return self.ptr.channel_freq()
        except FieldNotPresent:
            return None


    @property
    def channel_type(self):
        '''
        Channel type getter ('int')
        '''
        try:
            return self.ptr.channel_type()
        except FieldNotPresent:
            return None


    @property
    def xchannel(self):
        '''
        XChannel field setter ('int')
        '''
        try:
            return self.ptr.xchannel()
        except FieldNotPresent:
            return None

    cpdef channel(self, new_freq, new_type):
        '''
        channel(self, new_freq, new_type)
        Setter for the channel frequency and type field

        Parameters
        ----------
        new_freq: uint16_t
            The new channel frequency
        new_type: uint16_t
            The new channel type (you can OR the `ChannelType` values)
        Returns
        -------
        '''

        if new_freq is None:
            raise ValueError("new_freq can't be None")
        if new_type is None:
            raise ValueError("new_type can't be None")
        self.ptr.channel(<uint16_t> int(new_freq), <uint16_t> int(new_type))


    @property
    def present(self):
        '''
        Present field getter. You can mask this value using the PresentFlags enum. ('int')
        '''
        return int(self.ptr.present())


    @property
    def mcs(self):
        '''
        MCS field getter ('int')
        '''
        cdef mcs_type t
        try:
            t = self.ptr.mcs()
            return t.known, t.flags, t.mcs
        except FieldNotPresent:
            return None

    @mcs.setter
    def mcs(self, tuple_value):
        '''
        MCS field setter ('int')
        '''
        _known, _flags, _mcs = tuple_value
        cdef mcs_type t
        t.known = <uint8_t> _known
        t.flags = <uint8_t> _flags
        t.mcs = <uint8_t> _mcs
        self.ptr.mcs(t)


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppRadioTap(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppRadioTap*> ptr

Radiotap = RadioTap
