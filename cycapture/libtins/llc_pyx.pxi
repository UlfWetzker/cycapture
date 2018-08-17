# -*- coding: utf-8 -*-

cdef class LLC(PDU):
    """
    LLC frame (IEEE 802.2)
    """
    pdu_flag = PDU.LLC
    pdu_type = PDU.LLC

    Format = make_enum('LLC_Format', 'Format', 'LLC Format flags', {
        "INFORMATION": LLC_INFORMATION,
        "SUPERVISORY": LLC_SUPERVISORY,
        "UNNUMBERED": LLC_UNNUMBERED
    })

    ModifierFunctions = make_enum('LLC_ModifierFunctions', 'ModifierFunctions', 'LLC Modifier functions', {
        "UI": LLC_UI,
        "XID": LLC_XID,
        "TEST": LLC_TEST,
        "SABME": LLC_SABME,
        "DISC": LLC_DISC,
        "UA": LLC_UA,
        "DM": LLC_DM,
        "FRMR": LLC_FRMR
    })

    SupervisoryFunctions = make_enum('LLC_SupervisoryFunctions', 'SupervisoryFunctions', 'LLC Supervisory functions', {
        "RECEIVE_READY": LLC_RECEIVE_READY,
        "REJECT": LLC_REJECT,
        "RECEIVE_NOT_READY": LLC_RECEIVE_NOT_READY
    })

    def __cinit__(self, dsap=0, ssap=0, _raw=False):
        if _raw is True or type(self) != LLC:
            return

        self.ptr = new cppLLC(<uint8_t> int(dsap), <uint8_t> int(ssap))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppLLC* p = <cppLLC*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dsap=0, ssap=0):
        """
        __init__(dsap=0, ssap=0)
        Constructs an instance of LLC, setting the dsap and ssap.

        The control field is set to 0.

        Parameters
        ----------
        dsap: int
            The dsap value
        ssap: int
            The ssap value
        """

    cpdef clear_information_fields(self):
        self.ptr.clear_information_fields()


    @property
    def group(self):
        """
        group destination bit getter ('bool')
        """
        return bool(self.ptr.group())

    @group.setter
    def group(self, value):
        """
        group destination bit setter ('bool')
        """
        value = bool(value)
        self.ptr.group(<cpp_bool> value)


    @property
    def dsap(self):
        """
        dsap field getter ('int')
        """
        return int(self.ptr.dsap())

    @dsap.setter
    def dsap(self, value):
        """
        dsap field setter ('int')
        """
        self.ptr.dsap(<uint8_t> int(value))


    @property
    def response(self):
        """
        response bit getter ('bool')
        """
        return bool(self.ptr.response())

    @response.setter
    def response(self, value):
        """
        response bit setter ('bool')
        """
        value = bool(value)
        self.ptr.response(<cpp_bool> value)


    @property
    def ssap(self):
        """
        ssap field getter ('int')
        """
        return int(self.ptr.ssap())

    @ssap.setter
    def ssap(self, value):
        """
        ssap field setter ('int')
        """
        self.ptr.ssap(<uint8_t> int(value))


    @property
    def type(self):
        """
        LLC frame format type getter (:py:class:`~.LLC.Format`)
        """
        return int(self.ptr.type())

    @type.setter
    def type(self, value):
        """
        LLC frame format type (read-write, :py:class:`~.LLC.Format`)
        """
        if isinstance(value, LLC.Format):
            value = value.value
        value = int(value)
        self.ptr.type(<LLC_Format> value)


    @property
    def send_seq_number(self):
        """
        sender send sequence number getter ('int'; only applied if format is INFORMATION)
        """
        return int(self.ptr.send_seq_number())

    @send_seq_number.setter
    def send_seq_number(self, value):
        """
        sender send sequence number setter ('int'; only applied if format is INFORMATION)
        """
        self.ptr.send_seq_number(<uint8_t> int(value))


    @property
    def receive_seq_number(self):
        """
        sender receive sequence number getter ('int'; only applied if format is INFORMATION or SUPERVISORY)
        """
        return int(self.ptr.receive_seq_number())

    @receive_seq_number.setter
    def receive_seq_number(self, value):
        """
        sender receive sequence number setter ('int'; only applied if format is INFORMATION or SUPERVISORY)
        """
        self.ptr.receive_seq_number(<uint8_t> int(value))


    @property
    def poll_final(self):
        """
        poll/final flag getter ('bool')
        """
        return bool(self.ptr.poll_final())

    @poll_final.setter
    def poll_final(self, value):
        """
        poll/final flag setter ('bool')
        """
        value = bool(value)
        self.ptr.poll_final(<cpp_bool> value)


    @property
    def supervisory_function(self):
        """
        supervisory function (:py:class:`~.LLC.SupervisoryFunctions`; only applied if format is SUPERVISORY)
        """
        return int(self.ptr.supervisory_function())

    @supervisory_function.setter
    def supervisory_function(self, value):
        """
        supervisory function (:py:class:`~.LLC.SupervisoryFunctions`; only applied if format is SUPERVISORY)
        """
        if isinstance(value, LLC.SupervisoryFunctions):
            value = value.value
        value = int(value)
        self.ptr.supervisory_function(<LLC_SupervisoryFunctions> value)


    @property
    def modifier_function(self):
        """
        modifier function field getter (:py:class:`~.LLC.ModifierFunctions`; only applied if format is UNNUMBERED)
        """
        return int(self.ptr.modifier_function())

    @modifier_function.setter
    def modifier_function(self, value):
        """
        modifier function field setter (:py:class:`~.LLC.ModifierFunctions`; only applied if format is UNNUMBERED)
        """
        if isinstance(value, LLC.ModifierFunctions):
            value = value.value
        value = int(value)
        self.ptr.modifier_function(<LLC_ModifierFunctions> value)


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppLLC(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppLLC*> ptr
