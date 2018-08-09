# -*- coding: utf-8 -*-

cdef extern from "tins/radiotap.h" namespace "Tins" nogil:
    # noinspection PyUnresolvedReferences
    PDUType radiotap_pdu_flag "Tins::RadioTap::pdu_flag"

    enum RTChannelType "Tins::RadioTap::ChannelType":
        RT_TURBO "Tins::RadioTap::TURBO",
        RT_CCK "Tins::RadioTap::CCK",
        RT_OFDM "Tins::RadioTap::OFDM",
        RT_TWO_GZ "Tins::RadioTap::TWO_GZ"
        RT_FIVE_GZ "Tins::RadioTap::FIVE_GZ",
        RT_PASSIVE "Tins::RadioTap::PASSIVE",
        RT_DYN_CCK_OFDM "Tins::RadioTap::DYN_CCK_OFDM",
        RT_GFSK "Tins::RadioTap::GFSK"

    enum RTPresentFlags "Tins::RadioTap::PresentFlags":
        RT_TSTF "Tins::RadioTap::TSTF",
        RT_FLAGS "Tins::RadioTap::FLAGS",
        RT_RATE "Tins::RadioTap::RATE",
        RT_CHANNEL "Tins::RadioTap::CHANNEL",
        RT_FHSS "Tins::RadioTap::FHSS",
        RT_DBM_SIGNAL "Tins::RadioTap::DBM_SIGNAL",
        RT_DBM_NOISE "Tins::RadioTap::DBM_NOISE",
        RT_LOCK_QUALITY "Tins::RadioTap::LOCK_QUALITY",
        RT_TX_ATTENUATION "Tins::RadioTap::TX_ATTENUATION",
        RT_DB_TX_ATTENUATION "Tins::RadioTap::DB_TX_ATTENUATION",
        RT_DBM_TX_ATTENUATION "Tins::RadioTap::DBM_TX_ATTENUATION",
        RT_ANTENNA "Tins::RadioTap::ANTENNA",
        RT_DB_SIGNAL "Tins::RadioTap::DB_SIGNAL",
        RT_DB_NOISE "Tins::RadioTap::DB_NOISE",
        RT_RX_FLAGS "Tins::RadioTap::RX_FLAGS",
        RT_TX_FLAGS "Tins::RadioTap::TX_FLAGS",
        RT_DATA_RETRIES "Tins::RadioTap::DATA_RETRIES",
        RT_CHANNEL_PLUS "Tins::RadioTap::CHANNEL_PLUS",
        RT_MCS "Tins::RadioTap::MCS"

    enum RTFrameFlags "Tins::RadioTap::FrameFlags":
        RT_CFP "Tins::RadioTap::CFP",
        RT_PREAMBLE "Tins::RadioTap::PREAMBLE",
        RT_WEP "Tins::RadioTap::WEP",
        RT_FRAGMENTATION "Tins::RadioTap::FRAGMENTATION",
        RT_FCS "Tins::RadioTap::FCS",
        RT_PADDING "Tins::RadioTap::PADDING",
        RT_FAILED_FCS "Tins::RadioTap::FAILED_FCS",
        RT_SHORT_GI "Tins::RadioTap::SHORT_GI"

    struct mcs_type "Tins::RadioTap::mcs_type":
        uint8_t known,
        uint8_t flags,
        uint8_t mcs

    struct xchannel_type "Tins::RadioTap::xchannel_type":
        uint32_t flags,
        uint16_t frequency,
        uint8_t channel,
        uint8_t max_power

    cppclass cppRadioTap "Tins::RadioTap" (cppPDU):
        cppRadioTap()
        cppRadioTap(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        void send(cppPacketSender &sender, const cppNetworkInterface &iface) except +custom_exception_handler

        uint8_t version() const
        void version(uint8_t new_version)

        uint8_t padding() const
        void padding(uint8_t new_padding)

        uint16_t length() const
        void length(uint16_t new_length)

        uint64_t tsft() except +custom_exception_handler
        void tsft(uint64_t new_tsft)

        RTFrameFlags flags() except +custom_exception_handler
        void flags(RTFrameFlags new_flags)

        uint8_t rate() except +custom_exception_handler
        void rate(uint8_t new_rate)

        uint16_t channel_freq() except +custom_exception_handler
        uint16_t channel_type() except +custom_exception_handler
        xchannel_type xchannel() except +custom_exception_handler
        void channel(uint16_t new_freq, uint16_t new_type)

        int8_t dbm_signal() except +custom_exception_handler
        void dbm_signal(int8_t new_dbm_signal)

        int8_t dbm_noise() except +custom_exception_handler
        void dbm_noise(int8_t new_dbm_noise)

        uint16_t signal_quality() except +custom_exception_handler
        void signal_quality(uint8_t new_signal_quality)

        uint8_t antenna() except +custom_exception_handler
        void antenna(uint8_t new_antenna)

        uint8_t db_signal() except +custom_exception_handler
        void db_signal(uint8_t new_db_signal)

        uint16_t rx_flags() except +custom_exception_handler
        void rx_flags(uint16_t new_rx_flag)

        uint16_t tx_flags() except +custom_exception_handler
        void tx_flags(uint16_t new_tx_flag)

        uint8_t data_retries() except +custom_exception_handler
        void data_retries(uint8_t new_data_retries)

        mcs_type mcs() except +custom_exception_handler
        void mcs(const mcs_type& new_mcs)

        RTPresentFlags present() const


cdef class RadioTap(PDU):
    cdef cppRadioTap* ptr

    cpdef send(self, PacketSender sender, NetworkInterface iface)
    cpdef channel(self, new_freq, new_type)
