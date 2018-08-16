# -*- coding: utf-8 -*-

cdef class bpdu_id(object):
    """
    BPDU identifier.

    Immutable, hashable, copyable, supports equality.
    """
    def __cinit__(self, int priority=0, int ext_id=0, ident=None):
        self._priority = small_uint4(<uint8_t> priority)
        self._ext_id = small_uint12(<uint16_t> ext_id)
        if not isinstance(ident, HWAddress):
            ident = HWAddress(ident)
        self._id = (<HWAddress> ident).ptr[0]

    def __init__(self, int priority=0, int ext_id=0, ident=None):
        """
        __init__(priority=0, ext_id=0, ident=None)

        Parameters
        ----------
        priority: int
        ext_id: int
        ident: :py:class:`~.HWAddress`
        """

    @property
    def priority(self):
        '''
        Priority field getter ('int')
        '''
        return int(<uint8_t> self._priority)


    @property
    def ext_id(self):
        '''
        Ext id getter ('int')
        '''
        return int(<uint16_t> self._ext_id)

    @property
    def id(self):
        '''
        Id getter (:py:class:`~.HWAddress`)
        '''
        return HWAddress(self._id.to_string())


    def __hash__(self):
        return hash((self.priority, self.ext_id, <bytes> (self._id.to_string())))

    cpdef equals(self, other):
        if not isinstance(other, bpdu_id):
            return False
        return self.priority == (<bpdu_id> other).priority \
               and self.ext_id == (<bpdu_id> other).ext_id \
               and self._id.equals((<bpdu_id> other)._id)

    def __richcmp__(self, other, op):
        if op == 2:
            return (<bpdu_id> self).equals(other)
        elif op == 3:
            return not (<bpdu_id> self).equals(other)
        raise TypeError

    def __copy__(self):
        obj = bpdu_id()
        (<bpdu_id> obj)._priority = self._priority
        (<bpdu_id> obj)._ext_id = self._ext_id
        (<bpdu_id> obj)._id = self._id
        return obj

    @staticmethod
    cdef from_native(bpdu_id_type t):
        obj = bpdu_id()
        (<bpdu_id> obj)._priority = t.priority
        (<bpdu_id> obj)._ext_id = t.ext_id
        (<bpdu_id> obj)._id = t.id
        return obj

    cdef bpdu_id_type to_native(self):
        return bpdu_id_type(self._priority, self._ext_id, self._id)


cdef class STP(PDU):
    """
    Spanning Tree Protocol frame.
    """
    pdu_flag = PDU.STP
    pdu_type = PDU.STP
    bpdu_id_t = bpdu_id

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != STP:
            return

        self.ptr = new cppSTP()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppSTP* p = <cppSTP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    @property
    def proto_id(self):
        """
        Protocol ID field getter ('int')
        """
        return int(self.ptr.proto_id())

    @proto_id.setter
    def proto_id(self, value):
        """
        Protocol ID field setter ('int')
        """
        self.ptr.proto_id(<uint16_t> int(value))


    @property
    def proto_version(self):
        """
        Protocol Version field getter ('int')
        """
        return int(self.ptr.proto_version())

    @proto_version.setter
    def proto_version(self, value):
        """
        Protocol Version field setter ('int')
        """
        self.ptr.proto_version(<uint8_t> int(value))


    @property
    def bpdu_type(self):
        """
        BPDU Type field getter ('int')
        """
        return int(self.ptr.bpdu_type())
    @bpdu_type.setter
    def bpdu_type(self, value):
        """
        BPDU Type field setter ('int')
        """
        self.ptr.bpdu_type(<uint8_t> int(value))


    @property
    def bpdu_flags(self):
        """
        BPDU Flags field getter ('int')
        """
        return int(self.ptr.bpdu_flags())

    @bpdu_flags.setter
    def bpdu_flags(self, value):
        """
        BPDU Flags field setter ('int')
        """
        self.ptr.bpdu_flags(<uint8_t> int(value))


    @property
    def root_path_cost(self):
        """
        Root Path Cost field getter ('int')
        """
        return int(self.ptr.root_path_cost())

    @root_path_cost.setter
    def root_path_cost(self, value):
        """
        Root Path Cost field setter ('int')
        """
        self.ptr.root_path_cost(<uint32_t> int(value))


    @property
    def port_id(self):
        """
        Port ID field getter ('int')
        """
        return int(self.ptr.port_id())

    @port_id.setter
    def port_id(self, value):
        """
        Port ID field setter ('int')
        """
        self.ptr.port_id(<uint16_t> int(value))


    @property
    def msg_age(self):
        """
        Message Age field getter ('int')
        """
        return int(self.ptr.msg_age())

    @msg_age.setter
    def msg_age(self, value):
        """
        Message Age field setter('int')
        """
        self.ptr.msg_age(<uint16_t> int(value))


    @property
    def max_age(self):
        """
        Maximum Age field getter ('int')
        """
        return int(self.ptr.max_age())

    @max_age.setter
    def max_age(self, value):
        """
        Maximum Age field setter ('int')
        """
        self.ptr.max_age(<uint16_t> int(value))


    @property
    def hello_time(self):
        """
        Hello Time field getter ('int')
        """
        return int(self.ptr.hello_time())

    @hello_time.setter
    def hello_time(self, value):
        """
        Hello Time field setter ('int')
        """
        self.ptr.hello_time(<uint16_t> int(value))


    @property
    def fwd_delay(self):
        """
        Forward Delay field getter ('int')
        """
        return int(self.ptr.fwd_delay())

    @fwd_delay.setter
    def fwd_delay(self, value):
        """
        Forward Delay field setter ('int')
        """
        self.ptr.fwd_delay(<uint16_t> int(value))


    @property
    def root_id(self):
        """
        Root ID field getter (:py:class:`~.bpdu_id`)
        """
        return bpdu_id.from_native(self.ptr.root_id())

    @root_id.setter
    def root_id(self, value):
        """
        Root ID field setter (:py:class:`~.bpdu_id`)
        """
        if not isinstance(value, bpdu_id):
            priority, ext_id, ident = value
            value = bpdu_id(priority, ext_id, ident)
        self.ptr.root_id((<bpdu_id> value).to_native())


    @property
    def bridge_id(self):
        """
        Bridge ID field getter (:py:class:`~.bpdu_id`)
        """
        return bpdu_id.from_native(self.ptr.bridge_id())

    @bridge_id
    def bridge_id(self, value):
        """
        Bridge ID field setter (:py:class:`~.bpdu_id`)
        """
        if not isinstance(value, bpdu_id):
            priority, ext_id, ident = value
            value = bpdu_id(priority, ext_id, ident)
        self.ptr.bridge_id((<bpdu_id> value).to_native())


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppSTP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppSTP*> ptr
