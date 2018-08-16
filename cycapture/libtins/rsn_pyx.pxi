# -*- coding: utf-8 -*-

cdef class RSNInformation(object):
    """
    The RSN information structure
    """

    CypherSuites = make_enum('RSN_CypherSuites', 'CypherSuites', 'the different cypher suites', {
        'WEP_40': RSN_WEP_40,
        'TKIP': RSN_TKIP,
        'CCMP': RSN_CCMP,
        'WEP_104': RSN_WEP_104,
        'BIP_CMAC_128': RSN_BIP_CMAC_128,
        'GCMP_128': RSN_GCMP_128,
        'GCMP_256': RSN_GCMP_256,
        'CCMP_256': RSN_CCMP_256,
        'BIP_GMAC_128': RSN_BIP_GMAC_128,
        'BIP_GMAC_256': RSN_BIP_GMAC_256,
        'BIP_CMAC_256': RSN_BIP_CMAC_256
    })

    AKMSuites = make_enum('RSN_AKMSuites', 'AKMSuites', 'the different akm suites', {
        'EAP': RSN_EAP,
        'PSK': RSN_PSK,
        'EAP_FT': RSN_EAP_FT,
        'PSK_FT': RSN_PSK_FT,
        'EAP_SHA256': RSN_EAP_SHA256,
        'PSK_SHA256': RSN_PSK_SHA256,
        'TDLS': RSN_TDLS,
        'SHA256': RSN_SAE_SHA256,
        'SAE_FT': RSN_SAE_FT,
        'APPEERKEY': RSN_APPEERKEY,
        'EAP_SHA256_FIPSB': RSN_EAP_SHA256_FIPSB,
        'EAP_SHA364:FIPSB': RSN_EAP_SHA384_FIPSB,
        'EAP_SHA384': RSN_EAP_SHA384
    })

    def __cinit__(self, _raw=False):
        if _raw is True:
            return
        self.ptr = new cppRSNInformation()

    def __init__(self):
        """
        __init__()

        The version is set to 1.
        """

    def __dealloc__(self):
        if self.ptr is not NULL:
            del self.ptr
        self.ptr = NULL

    cpdef add_pairwise_cypher(self, cypher):
        """
        add_pairwise_cypher(cypher)
        Add a pairwise cypher suite

        Parameters
        ----------
        cypher: :py:class:`~.RSNInformation.CypherSuites`
            The pairwise cypher suite
        """
        cypher = int(cypher)
        self.ptr.add_pairwise_cypher(<RSN_CypherSuites> cypher)

    cpdef add_akm_cypher(self, akm):
        """
        add_akm_cypher(akm)
        Add an akm suite

        Parameters
        ----------
        akm: :py:class:`~.RSNInformation.AKMSuites`
            The akm suite

        """
        akm = int(akm)
        self.ptr.add_akm_cypher(<RSN_AKMSuites> akm)

    @property
    def group_suite(self):
        """
        group suite cypher field getter (:py:class:`~.RSNInformation.CypherSuites`)
        """
        return int(self.ptr.group_suite())

    @group_suite.setter
    def group_suite(self, value):
        """
        group suite cypher field setter (:py:class:`~.RSNInformation.CypherSuites`)
        """
        value = int(value)
        self.ptr.group_suite(<RSN_CypherSuites> value)


    @property
    def version(self):
        """
        Version field getter (`uint16_t`)
        """
        return self.ptr.version()

    @version.setter
    def version(self, value):
        """
        Version field setter (`uint16_t`)
        """
        self.ptr.version(<uint16_t> int(value))


    @property
    def capabilities(self):
        """
        capabilities field getter (`uint16_t`)
        """
        return self.ptr.capabilities()

    @capabilities.setter
    def capabilities(self, value):
        """
        capabilities field setter (`uint16_t`)
        """
        self.ptr.capabilities(<uint16_t> int(value))


    cpdef get_pairwise_cyphers(self):
        """
        get_pairwise_cyphers()
        Returns the pairwise cypher suite list.

        Returns
        -------
        suites: list of :py:class:`~.RSNInformation.CypherSuites`
        """
        cdef vector[RSN_CypherSuites] v = self.ptr.pairwise_cyphers()
        return [int(suite) for suite in v]

    cpdef get_akm_cyphers(self):
        """
        get_pairwise_cyphers()
        Returns the akm suite list.

        Returns
        -------
        suites: list of :py:class:`~.RSNInformation.AKMSuites`
        """
        cdef vector[RSN_AKMSuites] v = self.ptr.akm_cyphers()
        return [int(suite) for suite in v]

    cpdef serialize(self):
        """
        Serialize the object.

        Returns
        -------
        s: bytes
        """
        cdef vector[uint8_t] v = self.ptr.serialize()
        return <bytes>((&v[0])[:v.size()])

    @staticmethod
    cdef factory(cppRSNInformation* info):
        obj = RSNInformation.__new__(RSNInformation, _raw=True)
        (<RSNInformation> obj).ptr = new cppRSNInformation()
        (<RSNInformation> obj).ptr[0] = info[0]
        return obj

    @staticmethod
    def from_buffer(buf):
        """
        Constructs an RSNInformation object

        Parameters
        ----------
        buf: bytes or bytearray or memoryview

        Returns
        -------
        obj: :py:class:`~.RSNInformation`
        """
        obj = RSNInformation.__new__(RSNInformation, _raw=True)
        cdef uint8_t* buf_addr
        cdef uint32_t size
        PDU.prepare_buf_arg(buf, &buf_addr, &size)
        (<RSNInformation> obj).ptr = new cppRSNInformation(buf_addr, size)
        return obj
