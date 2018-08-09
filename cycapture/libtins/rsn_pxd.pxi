# -*- coding: utf-8 -*-

cdef extern from "tins/rsn_information.h" namespace "Tins" nogil:

    # typedef std::vector<CypherSuites> cyphers_type;
    # typedef std::vector<AKMSuites> akm_type;
    # typedef std::vector<uint8_t> serialization_type;

    ctypedef enum RSN_CypherSuites "Tins::RSNInformation::CypherSuites":
        RSN_WEP_40 "Tins::RSNInformation::WEP_40",
        RSN_TKIP "Tins::RSNInformation::TKIP",
        RSN_CCMP "Tins::RSNInformation::CCMP",
        RSN_WEP_104 "Tins::RSNInformation::WEP_104",
        RSN_BIP_CMAC_128 "Tins::RSNInformation::BIP_CMAC_128",
        RSN_GCMP_128 "Tins::RSNInformation::GCMP_128",
        RSN_GCMP_256 "Tins::RSNInformation::GCMP_256",
        RSN_CCMP_256 "Tins::RSNInformation::CCMP_256",
        RSN_BIP_GMAC_128 "Tins::RSNInformation::BIP_GMAC_128",
        RSN_BIP_GMAC_256 "Tins::RSNInformation::BIP_GMAC_256",
        RSN_BIP_CMAC_256 "Tins::RSNInformation::BIP_CMAC_256"


    ctypedef enum RSN_AKMSuites "Tins::RSNInformation::AKMSuites":
        RSN_EAP "Tins::RSNInformation::EAP",
        RSN_PSK "Tins::RSNInformation::PSK",
        RSN_EAP_FT "Tins::RSNInformation::EAP_FT",
        RSN_PSK_FT "Tins::RSNInformation::PSK_FT",
        RSN_EAP_SHA256 "Tins::RSNInformation::EAP_SHA256",
        RSN_PSK_SHA256 "Tins::RSNInformation::PSK_SHA256",
        RSN_TDLS "Tins::RSNInformation::TDLS",
        RSN_SAE_SHA256 "Tins::RSNInformation::SAE_SHA256",
        RSN_SAE_FT "Tins::RSNInformation::SAE_FT",
        RSN_APPEERKEY "Tins::RSNInformation::APPEERKEY",
        RSN_EAP_SHA256_FIPSB "Tins::RSNInformation::EAP_SHA256_FIPSB",
        RSN_EAP_SHA384_FIPSB "Tins::RSNInformation::EAP_SHA384_FIPSB",
        RSN_EAP_SHA384 "Tins::RSNInformation::EAP_SHA384"


    cppclass cppRSNInformation "Tins::RSNInformation":
        cppRSNInformation()
        cppRSNInformation(const vector[uint8_t] &buf)
        cppRSNInformation(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler
        void add_pairwise_cypher(RSN_CypherSuites cypher)
        void add_akm_cypher(RSN_AKMSuites akm)
        RSN_CypherSuites group_suite()
        void group_suite(RSN_CypherSuites group)
        uint16_t version()
        void version(uint16_t ver)
        uint16_t capabilities()
        void capabilities(uint16_t cap)
        vector[RSN_CypherSuites] &pairwise_cyphers()
        vector[RSN_AKMSuites] &akm_cyphers()
        vector[uint8_t] serialize()

    cppRSNInformation RSN_from_option "Tins::RSNInformation::from_option" (const dot11_pdu_option& opt)
    cppRSNInformation RSN_wpa2_psk "Tins::RSNInformation::wpa2_psk" ()

cdef class RSNInformation(object):
    cdef cppRSNInformation* ptr
    cpdef add_pairwise_cypher(self, cypher)
    cpdef add_akm_cypher(self, akm)
    cpdef get_pairwise_cyphers(self)
    cpdef get_akm_cyphers(self)
    cpdef serialize(self)

    @staticmethod
    cdef factory(cppRSNInformation* info)

