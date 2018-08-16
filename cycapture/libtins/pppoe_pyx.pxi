# -*- coding: utf-8 -*-

cdef class PPPoE(PDU):
    """
    Point-to-point protocol over Ethernet packet
    """
    pdu_flag = PDU.PPPOE
    pdu_type = PDU.PPPOE

    TagTypes = make_enum('PPPoE_TagTypes', 'TagTypes', 'Tag types enum', {
        'END_OF_LIST': PPPoE_END_OF_LIST,
        'SERVICE_NAME': PPPoE_SERVICE_NAME,
        'AC_NAME': PPPoE_AC_NAME,
        'HOST_UNIQ': PPPoE_HOST_UNIQ,
        'AC_COOKIE': PPPoE_AC_COOKIE,
        'VENDOR_SPECIFIC': PPPoE_VENDOR_SPECIFIC,
        'RELAY_SESSION_ID': PPPoE_RELAY_SESSION_ID,
        'SERVICE_NAME_ERROR': PPPoE_SERVICE_NAME_ERROR,
        'AC_SYSTEM_ERROR': PPPoE_AC_SYSTEM_ERROR,
        'GENERIC_ERROR': PPPoE_GENERIC_ERROR
    })

    def __cinit__(self, _raw=False):
        if _raw or type(self) != PPPoE:
            return

        self.ptr = new cppPPPoE()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppPPPoE* p = <cppPPPoE*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()

        The default constructor sets the version and type fields to ``0x1``.
        """


    @property
    def version(self):
        """
        version field getter ('int')
        """
        return int(<uint8_t> self.ptr.version())

    @version.setter
    def version(self, value):
        """
        version field setter ('int')
        """
        self.ptr.version(small_uint4(<uint8_t> int(value)))


    @property
    def type(self):
        """
        type field getter('int')
        """
        return int(<uint8_t> self.ptr.type())

    @type.setter
    def type(self, value):
        """
        type field setter ('int')
        """
        self.ptr.type(small_uint4(<uint8_t> int(value)))


    @property
    def code(self):
        """
        code field getter ('int')
        """
        return int(self.ptr.code())

    @code.setter
    def code(self, value):
        """
        code field setter ('int')
        """
        self.ptr.code(<uint8_t> int(value))


    @property
    def session_id(self):
        """
        session_id field getter ('int')
        """
        return int(self.ptr.session_id())

    @session_id.setter
    def session_id(self, value):
        """
        session_id field setter ('int')
        """
        self.ptr.session_id(<uint16_t> int(value))


    @property
    def payload_length(self):
        """
        the payload_length field getter ('int')
        """
        return int(self.ptr.payload_length())

    @payload_length.setter
    def payload_length(self, value):
        """
        the payload_length field setter ('int')
        """
        self.ptr.payload_length(<uint16_t> int(value))


    @property
    def service_name(self):
        """
        service-name tag getter('bytes')
        """
        try:
            return <bytes> (self.ptr.service_name())
        except OptionNotFound:
            return None

    @service_name.setter
    def service_name(self, value):
        """
        service-name tag setter ('bytes')
        """
        value = bytes(value)
        self.ptr.service_name(<string> (<bytes> value))


    @property
    def ac_name(self):
        """
        AC-name tag getter ('bytes')
        """
        try:
            return <bytes> (self.ptr.ac_name())
        except OptionNotFound:
            return None

    @ac_name.setter
    def ac_name(self, value):
        """
        AC-name tag setter ('bytes')
        """
        value = bytes(value)
        self.ptr.ac_name(<string> (<bytes> value))


    @property
    def service_name_error(self):
        """
        Service-Name-Error tag getter ('bytes')
        """
        try:
            return <bytes> (self.ptr.service_name_error())
        except OptionNotFound:
            return None

    @service_name_error.setter
    def service_name_error(self, value):
        """
        Service-Name-Error tag ('bytes')
        """
        value = bytes(value)
        self.ptr.service_name_error(<string> (<bytes> value))


    @property
    def ac_system_error(self):
        """
        AC-System-Error tag getter ('bytes')
        """
        try:
            return <bytes> (self.ptr.ac_system_error())
        except OptionNotFound:
            return None

    @ac_system_error.setter
    def ac_system_error(self, value):
        """
        AC-System-Error tag setter ('bytes')
        """
        value = bytes(value)
        self.ptr.ac_system_error(<string> (<bytes> value))


    @property
    def generic_error(self):
        """
        Generic-Error tag getter ('bytes')
        """
        try:
            return <bytes> (self.ptr.generic_error())
        except OptionNotFound:
            return None

    @generic_error.setter
    def generic_error(self, value):
        """
        Generic-Error tag setter ('bytes')
        """
        value = bytes(value)
        self.ptr.generic_error(<string> (<bytes> value))


    @property
    def  host_uniq(self):
        """
        Host-uniq tag getter ('bytes')
        """
        cdef vector[uint8_t] v = self.ptr.host_uniq()
        cdef uint8_t* p = &v[0]
        return <bytes> p[:v.size()]

    @host_uniq.setter
    def  host_uniq(self, value):
        """
        host-uniq tag setter ('bytes')
        """
        value = bytes(value)
        cdef uint8_t* p = <uint8_t*> (<bytes> value)
        cdef vector[uint8_t] v
        v.assign(p, p + len(value))
        self.ptr.host_uniq(v)


    @property
    def ac_cookie(self):
        """
        AC-Cookie tag getter ('bytes')
        """
        cdef vector[uint8_t] v = self.ptr.ac_cookie()
        cdef uint8_t* p = &v[0]
        return <bytes> p[:v.size()]

    @ac_cookie.setter
    def ac_cookie(self, value):
        """
        AC-Cookie tag setter ('bytes')
        """
        value = bytes(value)
        cdef uint8_t* p = <uint8_t*> (<bytes> value)
        cdef vector[uint8_t] v
        v.assign(p, p + len(value))
        self.ptr.ac_cookie(v)


    @property
    def relay_session_id(self):
        """
        Relay-Session-Id tag getter ('bytes')
        """
        cdef vector[uint8_t] v = self.ptr.relay_session_id()
        cdef uint8_t* p = &v[0]
        return <bytes> p[:v.size()]

    @relay_session_id.setter
    def relay_session_id(self, value):
        """
        Relay-Session-Id tag setter ('bytes')
        """
        value = bytes(value)
        cdef uint8_t* p = <uint8_t*> (<bytes> value)
        cdef vector[uint8_t] v
        v.assign(p, p + len(value))
        self.ptr.relay_session_id(v)


    @property
    def tags(self):
        """
        Current tags list getter ('list')
        """
        returned_tags = []
        cdef vector[pppoe_tag] all_tags = self.ptr.tags()
        cdef pppoe_tag tag
        cdef size_t length
        for tag in all_tags:
            length = tag.data_size()
            returned_tags.append((
                int(tag.option()),
                b"" if length == 0 else <bytes> ((tag.data_ptr())[:length])
            ))
        return returned_tags


    cpdef search_tag(self, tag_type):
        """
        search_tag(tag_type)
        Search for a tag by type.

        Parameters
        ----------
        tag_type: :py:class:`~.PPPoE:TagTypes`

        Returns
        -------
        tag: bytes or ``None``
        """
        tag_type = int(tag_type)
        cdef pppoe_tag* tag_ptr = <pppoe_tag*> (self.ptr.search_tag(<PPPoE_TagTypes> tag_type))
        if tag_ptr is NULL:
            return None
        cdef size_t length = int(tag_ptr.data_size())
        if length == 0:
            return b''
        return <bytes> ((tag_ptr.data_ptr())[:length])

    cpdef add_tag(self, tag_type, data=None):
        """
        add_tag(tag_type, data=None)
        Add a tag

        Parameters
        ----------
        tag_type: :py:class:`~.PPPoE:TagTypes`
        data: bytes
        """
        tag_type = int(tag_type)
        cdef pppoe_tag tag
        if data is None:
            tag = pppoe_tag(<PPPoE_TagTypes> tag_type)
        else:
            data = bytes(data)
            tag = pppoe_tag(<PPPoE_TagTypes> tag_type, len(data), <uint8_t*> data)
        self.ptr.add_tag(tag)

    cpdef get_vendor_specific(self):
        """
        get_vendor_specific()

        Returns
        -------
        (vendor_id, data): (uint32_t, bytes)

        Raises
        ------
        exception: :py:class:`~.OptionNotFound`
            if the PDU does not have a Vendor-Specific tag
        """
        cdef pppoe_vendor_spec_type vendor = self.ptr.vendor_specific()
        cdef uint8_t* p = &(vendor.data[0])
        return int(vendor.vendor_id), <bytes> p[:vendor.data.size()]

    cpdef set_vendor_specific(self, vendor_id, data):
        """
        set_vendor_specific(vendor_id, data)
        Add a Vendor-Specific tag

        Parameters
        ----------
        vendor_id: uint32_t
        data: bytes
        """
        vendor_id = int(vendor_id)
        data = bytes(data)
        cdef vector[uint8_t] v
        cdef uint8_t* p = <uint8_t*> (<bytes> data)
        v.assign(p, p + len(data))
        cdef pppoe_vendor_spec_type vendor = pppoe_vendor_spec_type(<uint32_t> vendor_id, v)
        self.ptr.vendor_specific(vendor)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppPPPoE(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppPPPoE*> ptr

PPPOE = PPPoE
