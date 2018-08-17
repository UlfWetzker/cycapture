# -*- coding: utf-8 -*-

cdef class EAPOL(PDU):
    '''
    EAPOL abstract class
    '''
    pdu_flag = PDU.EAPOL
    pdu_type = PDU.EAPOL

    Types = IntEnum("Types", {
        'RC4': EAPOL_RC4,
        'RSN': EAPOL_RSN,
        'EAPOL_WPA': EAPOL_EAPOL_WPA
    })

    def __cinit__(self):
        pass

    def __init__(self):
        raise NotImplementedError

    def __dealloc__(self):
        pass

    @staticmethod
    def from_bytes(buf):
        if buf is None:
            raise ValueError("buf can't be None")
        cdef uint8_t* buf_addr
        cdef uint32_t size
        PDU.prepare_buf_arg(buf, &buf_addr, &size)
        return EAPOL.c_from_bytes(buf_addr, size)

    @staticmethod
    cdef c_from_bytes(uint8_t* buf_addr, uint32_t size):
        if buf_addr is NULL or size == 0:
            raise ValueError("buffer can't be empty")
        cdef cppEAPOL* p = eapol_from_bytes(buf_addr, size)         # equivalent to new
        if p is NULL:
            raise MalformedPacket
        return PDU.from_ptr(p, parent=None)


    @property
    def version(self):
        '''
        Version field getter ('int')
        '''
        return int((<cppEAPOL*> self.ptr).version())

    @version.setter
    def version(self, value):
        '''
        Version field setter ('int')
        '''
        (<cppEAPOL*> self.ptr).version(<uint8_t> int(value))


    @property
    def packet_type(self):
        '''
        Packet type getter ('int')
        '''
        return int((<cppEAPOL*> self.ptr).packet_type())

    @packet_type.setter
    def packet_type(self, value):
        '''
        Packet type setter ('int')
        '''
        (<cppEAPOL*> self.ptr).packet_type(<uint8_t> int(value))


    @property
    def length(self):
        '''
        Length field getter ('int')
        '''
        return int((<cppEAPOL*> self.ptr).length())

    @length.setter
    def length(self, value):
        '''
        Length field setter ('int')
        '''
        (<cppEAPOL*> self.ptr).length(<uint16_t> int(value))


    @property
    def type(self):
        '''
        Type field getter ('int')
        '''
        return int((<cppEAPOL*> self.ptr).type())

    @type.setter
    def type(self, value):
        '''
        Type field setter ('int')
        '''
        (<cppEAPOL*> self.ptr).type(<uint8_t> int(value))


cdef class RC4EAPOL(EAPOL):
    pdu_flag = PDU.RC4EAPOL
    pdu_type = PDU.RC4EAPOL

    key_iv_size = rc4eapol_key_iv_size
    key_sign_size = rc4eapol_key_sign_size

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != RC4EAPOL:
            return

        self.ptr = new cppRC4EAPOL()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppRC4EAPOL* p = <cppRC4EAPOL*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    # noinspection PyMissingConstructor
    def __init__(self):
        """
        __init__()
        """

    @property
    def key_length(self):
        '''
        Key length getter ('int')
        '''
        return int((<cppRC4EAPOL*> self.ptr).key_length())

    @key_length.setter
    def key_length(self, value):
        '''
        Key length setter ('int')
        '''
        (<cppRC4EAPOL*> self.ptr).key_length(<uint16_t> int(value))


    @property
    def replay_counter(self):
        '''
        Replay counter getter ('int')
        '''
        return int((<cppRC4EAPOL*> self.ptr).replay_counter())

    @replay_counter.setter
    def replay_counter(self, value):
        '''
        Relay counter setter ('int')
        '''
        (<cppRC4EAPOL*> self.ptr).replay_counter(<uint64_t> int(value))


    @property
    def key_flag(self):
        '''
        Key flag getter ('bool')
        '''
        return bool(<uint8_t> ((<cppRC4EAPOL*> self.ptr).key_flag()))

    @key_flag.setter
    def key_flag(self, value):
        '''
        Key Flag setter ('bool')
        '''
        cdef uint8_t v = 1 if value else 0
        (<cppRC4EAPOL*> self.ptr).key_flag(small_uint1(v))


    @property
    def key_index(self):
        '''
        Key index getter ('int')
        '''
        return int(<uint8_t> ((<cppRC4EAPOL*> self.ptr).key_index()))

    @key_index.setter
    def key_index(self, value):
        '''
        Key index setter ('int')
        '''
        (<cppRC4EAPOL*> self.ptr).key_index(small_uint7(<uint8_t>int(value)))


    @property
    def key(self):
        '''
        Key getter ('bytes')
        '''
        cdef vector[uint8_t] k = (<cppRC4EAPOL*> self.ptr).key()
        return <bytes>((&(k[0]))[:k.size()])

    @key.setter
    def key(self, value):
        '''
        Key setter ('bytes')
        '''
        value = bytes(value)
        cdef uint8_t* p = <uint8_t*> (<bytes> value)
        cdef vector[uint8_t] v
        v.assign(p, p + len(value))
        (<cppRC4EAPOL*> self.ptr).key(v)


    @property
    def key_iv(self):
        '''
        Key IV getter ('bytes')
        '''
        cdef uint8_t* p = <uint8_t*> ((<cppRC4EAPOL*> self.ptr).key_iv())
        return <bytes> p[:RC4EAPOL.key_iv_size]

    @key_iv.setter
    def key_iv(self, value):
        '''
        Key IV setter ('bytes')
        '''
        value = bytes(value)[:RC4EAPOL.key_iv_size].ljust(RC4EAPOL.key_iv_size, '\x00')
        (<cppRC4EAPOL*> self.ptr).key_iv(<uint8_t*> (<bytes> value))


    @property
    def key_sign(self):
        '''
        Key sign getter ('bytes')
        '''
        cdef uint8_t* p = <uint8_t*> ((<cppRC4EAPOL*> self.ptr).key_sign())
        return <bytes> p[:RC4EAPOL.key_sign_size]

    @key_sign.setter
    def key_sign(self, value):
        '''
        Key sign setter ('bytes')
        '''
        value = bytes(value)[:RC4EAPOL.key_sign_size].ljust(RC4EAPOL.key_sign_size, '\x00')
        (<cppRC4EAPOL*> self.ptr).key_sign(<uint8_t*> (<bytes> value))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppRC4EAPOL(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppRC4EAPOL*> ptr


cdef class RSNEAPOL(EAPOL):
    pdu_flag = PDU.RSNEAPOL
    pdu_type = PDU.RSNEAPOL

    key_iv_size = rsneapol_key_iv_size
    nonce_size = rsneapol_nonce_size
    mic_size = rsneapol_mic_size
    rsc_size = rsneapol_rsc_size
    id_size = rsneapol_id_size

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != RSNEAPOL:
            return

        self.ptr = new cppRSNEAPOL()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppRSNEAPOL* p = <cppRSNEAPOL*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    # noinspection PyMissingConstructor
    def __init__(self):
        """
        __init__()
        """

    @property
    def key_length(self):
        '''
        Key length getter ('int')
        '''
        return int((<cppRSNEAPOL*> self.ptr).key_length())

    @key_length.setter
    def key_length(self, value):
        '''
        Key length setter ('int')
        '''
        (<cppRSNEAPOL*> self.ptr).key_length(<uint16_t> int(value))


    @property
    def replay_counter(self):
        '''
        Replay counter getter ('int')
        '''
        return int((<cppRSNEAPOL*> self.ptr).replay_counter())

    @replay_counter.setter
    def replay_counter(self, value):
        '''
        Replay counter setter ('int')
        '''
        (<cppRSNEAPOL*> self.ptr).replay_counter(<uint64_t> int(value))


    @property
    def wpa_length(self):
        '''
        WPA length getter ('int')
        '''
        return int((<cppRSNEAPOL*> self.ptr).wpa_length())

    @wpa_length.setter
    def wpa_length(self, value):
        '''
        WPA length setter ('int')
        '''
        (<cppRSNEAPOL*> self.ptr).wpa_length(<uint16_t> int(value))


    @property
    def key_mic(self):
        '''
        Key mic field getter ('bool')
        '''
        return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_mic()))

    @key_mic.setter
    def key_mic(self, value):
        '''
        Key mic field setter ('bool')
        '''
        (<cppRSNEAPOL*> self.ptr).key_mic(small_uint1(<uint8_t> bool(value)))


    @property
    def secure(self):
        '''
        Secure field getter ('bool')
        '''
        return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).secure()))

    @secure.setter
    def secure(self, value):
        '''
        Secure field setter ('bool')
        '''
        (<cppRSNEAPOL*> self.ptr).secure(small_uint1(<uint8_t> bool(value)))


    @property
    def error(self):
        '''
        Error field getter ('bool')
        '''
        return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).error()))

    @error.setter
    def error(self, value):
        '''
        Error field setter ('bool')
        '''
        (<cppRSNEAPOL*> self.ptr).error(small_uint1(<uint8_t> bool(value)))


    @property
    def request(self):
        '''
        REquest field getter ('bool')
        '''
        return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).request()))

    @request.setter
    def request(self, value):
        '''
        Request field setter ('bool')
        '''
        (<cppRSNEAPOL*> self.ptr).request(small_uint1(<uint8_t> bool(value)))


    @property
    def encrypted(self):
        '''
        Encrypted field getter ('bool')
        '''
        return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).encrypted()))

    @encrypted.setter
    def encrypted(self, value):
        '''
        Encrypted field setter ('bool')
        '''
        (<cppRSNEAPOL*> self.ptr).encrypted(small_uint1(<uint8_t> bool(value)))


    @property
    def key_t(self):
        '''
        Key T getter ('bool')
        '''
        return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_t()))

    @key_t.setter
    def key_t(self, value):
        '''
        Key T setter ('bool')
        '''
        (<cppRSNEAPOL*> self.ptr).key_t(small_uint1(<uint8_t> bool(value)))


    @property
    def install(self):
        '''
        Install field setter ('bool')
        '''
        return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).install()))

    @install.setter
    def install(self, value):
        '''
        Install field setter ('bool')
        '''
        (<cppRSNEAPOL*> self.ptr).install(small_uint1(<uint8_t> bool(value)))


    @property
    def key_ack(self):
        '''
        Key ACK getter ('bool')
        '''
        return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_ack()))

    @key_ack.setter
    def key_ack(self, value):
        '''
        Key ACK setter ('bool')
        '''
        (<cppRSNEAPOL*> self.ptr).key_ack(small_uint1(<uint8_t> bool(value)))


    @property
    def key_descriptor(self):
        '''
        Key descriptor getter ('int')
        '''
        return int(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_descriptor()))

    @key_descriptor.setter
    def key_descriptor(self, value):
        '''
        Key descriptor setter ('int')
        '''
        (<cppRSNEAPOL*> self.ptr).key_descriptor(small_uint3(<uint8_t> int(value)))


    @property
    def key_index(self):
        '''
        Key index getter ('int')
        '''
        return int(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_index()))

    @key_index.setter
    def key_index(self, value):
        '''
        Key index setter ('int')
        '''
        (<cppRSNEAPOL*> self.ptr).key_index(small_uint2(<uint8_t> int(value)))


    @property
    def key(self):
        '''
        Key getter ('bytes')
        '''
        cdef vector[uint8_t] k = (<cppRSNEAPOL*> self.ptr).key()
        return <bytes>((&(k[0]))[:k.size()])

    @key.setter
    def key(self, value):
        '''
        Key setter ('bytes')
        '''
        value = bytes(value)
        cdef uint8_t* p = <uint8_t*> (<bytes> value)
        cdef vector[uint8_t] v
        v.assign(p, p + len(value))
        (<cppRSNEAPOL*> self.ptr).key(v)


    @property
    def key_iv(self):
        '''
        Key IV getter ('bytes')
        '''
        cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).key_iv())
        return <bytes> p[:RSNEAPOL.key_iv_size]

    @key_iv.setter
    def key_iv(self, value):
        '''
        Key IV setter ('bytes')
        '''
        value = bytes(value)[:RSNEAPOL.key_iv_size].ljust(RSNEAPOL.key_iv_size, '\x00')
        (<cppRSNEAPOL*> self.ptr).key_iv(<uint8_t*> (<bytes> value))


    @property
    def nonce(self):
        '''
        NONCE getter ('bytes')
        '''
        cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).nonce())
        return <bytes> p[:RSNEAPOL.nonce_size]

    @nonce.setter
    def nonce(self, value):
        '''
        NONCE setter ('bytes')
        '''
        value = bytes(value)[:RSNEAPOL.nonce_size].ljust(RSNEAPOL.nonce_size, '\x00')
        (<cppRSNEAPOL*> self.ptr).nonce(<uint8_t*> (<bytes> value))


    @property
    def rsc(self):
        '''
        RSC field getter ('bytes')
        '''
        cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).rsc())
        return <bytes> p[:RSNEAPOL.rsc_size]

    @rsc.setter
    def rsc(self, value):
        '''
        RSC field setter ('bytes')
        '''
        value = bytes(value)[:RSNEAPOL.rsc_size].ljust(RSNEAPOL.rsc_size, '\x00')
        (<cppRSNEAPOL*> self.ptr).rsc(<uint8_t*> (<bytes> value))


    @property
    def id(self):
        '''
        ID field getter ('bytes')
        '''
        cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).id())
        return <bytes> p[:RSNEAPOL.id_size]

    @id.setter
    def id(self, value):
        '''
        ID field setter ('bytes')
        '''
        value = bytes(value)[:RSNEAPOL.id_size].ljust(RSNEAPOL.id_size, '\x00')
        (<cppRSNEAPOL*> self.ptr).id(<uint8_t*> (<bytes> value))


    @property
    def mic(self):
        '''
        MIC field getter ('bytes')
        '''
        cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).mic())
        return <bytes> p[:RSNEAPOL.mic_size]

    @mic.setter
    def mic(self, value):
        '''
        MIC field setter ('bytes')
        '''
        value = bytes(value)[:RSNEAPOL.mic_size].ljust(RSNEAPOL.mic_size, '\x00')
        (<cppRSNEAPOL*> self.ptr).mic(<uint8_t*> (<bytes> value))


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppRSNEAPOL(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppRSNEAPOL*> ptr

RC4_EAPOL = RC4EAPOL
RSN_EAPOL = RSNEAPOL
