from libcpp.string cimport string
from libcpp.vector cimport vector
# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t

cdef extern from "tins/network_interface.h" namespace "Tins":
    cdef cppclass cppNetworkInterface "Tins::NetworkInterface":
        cppclass Info:
            cppIPv4Address ip_addr, netmask, bcast_addr
            cppHWAddress6 hw_addr

        cppNetworkInterface()
        cppNetworkInterface(const string &name) except +ValueError
        cppNetworkInterface(const char *name) except +ValueError
        cppNetworkInterface(cppIPv4Address ip) except +ValueError
        uint32_t ident "id"() const
        string name() except +IOError
        cppNetworkInterface.Info addresses() except +IOError
        bool is_loopback() const
        bool operator==(const cppNetworkInterface &rhs) const
        bool operator!=(const cppNetworkInterface &rhs) const

    cppNetworkInterface default_interface "Tins::NetworkInterface::default_interface"()
    # noinspection PyUnresolvedReferences
    vector[cppNetworkInterface] all_interfaces "Tins::NetworkInterface::all"()
    cppNetworkInterface network_interface_from_index "Tins::NetworkInterface::from_index"(uint32_t identifier)

cdef extern from "wrap.h" namespace "Tins":
    bool network_interface_to_bool(const cppNetworkInterface& nwi)

cdef class NetworkInterface(object):
    cdef cppNetworkInterface* ptr
    cpdef int ident(self)
    cpdef bytes name(self)
    cpdef object addresses(self)
    cpdef bool is_loopback(self)
    cdef object _make_from_address(self, object address)