# -*- coding: utf-8 -*-

cdef class ARP(PDU):
    """
    ARP packet

    ARP requests and replies can be constructed easily using static methods :py:meth:`~.ARP.make_arp_request` and
    :py:meth:`~.ARP.make_arp_reply`.
    """
    pdu_flag = PDU.ARP
    pdu_type = PDU.ARP

    Flags = make_enum('ARP_Flags', 'Flags', 'Indicates the type of ARP packet', {
        'REQUEST': ARP_REQUEST,
        'REPLY': ARP_REPLY,
    })

    def __cinit__(self, target_ip=None, sender_ip=None, target_hw=None, sender_hw=None, _raw=False):
        if _raw is True:
            return

        if not isinstance(target_ip, IPv4Address):
            target_ip = IPv4Address(target_ip)
        if not isinstance(sender_ip, IPv4Address):
            sender_ip = IPv4Address(sender_ip)
        if not isinstance(target_hw, HWAddress):
            target_hw = HWAddress(target_hw)
        if not isinstance(sender_hw, HWAddress):
            sender_hw = HWAddress(sender_hw)

        self.ptr = new cppARP(
            (<IPv4Address> target_ip).ptr[0],
            (<IPv4Address> sender_ip).ptr[0],
            (<HWAddress> target_hw).ptr[0],
            (<HWAddress> sender_hw).ptr[0]
        )

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self, target_ip=None, sender_ip=None, target_hw=None, sender_hw=None):
        """
        __init__(target_ip=None, sender_ip=None, target_hw=None, sender_hw=None)

        Parameters
        ----------
        target_ip: :py:class:`~.IPv4Address`
            target IP address
        sender_ip: :py:class:`~.IPv4Address`
            sender IP address
        target_hw: :py:class:`~.HWAddress`
            target hardware address
        sender_hw: :py:class:`~.HWAddress`
            sender hardware address
        """

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    @staticmethod
    def make_arp_request(target, sender, hw_snd=None):
        """
        make_arp_request(target, sender, hw_snd=None)
        Creates an ARP Request within an EthernetII PDU.

        Parameters
        ----------
        target: :py:class:`~.IPv4Address`
            Target IP address
        sender: :py:class:`~.IPv4Address`
            Sender IP address
        hw_snd: :py:class:`~.HWAddress`
            Sender hardware address

        Returns
        -------
        packet: :py:class:`~.EthernetII`
        """
        if not isinstance(target, IPv4Address):
            target = IPv4Address(target)
        if not isinstance(sender, IPv4Address):
            sender = IPv4Address(sender)
        if not isinstance(hw_snd, HWAddress):
            hw_snd = HWAddress(hw_snd)

        cdef cppEthernetII eth_pdu = cpp_make_arp_request(
            (<IPv4Address> target).ptr[0],
            (<IPv4Address> sender).ptr[0],
            (<HWAddress> hw_snd).ptr[0]
        )

        return EthernetII.from_ptr(eth_pdu.clone(), parent=None)

    @staticmethod
    def make_arp_reply(target, sender, hw_tgt=None, hw_snd=None):
        """
        make_arp_reply(target, sender, hw_tgt=None, hw_snd=None)
        Creates an ARP Reply within an EthernetII PDU.

        Parameters
        ----------
        target: :py:class:`~.IPv4Address`
            Target IP address
        sender: :py:class:`~.IPv4Address`
            Sender IP address
        hw_tgt: :py:class:`~.HWAddress`
            Target hardware address
        hw_snd: :py:class:`~.HWAddress`
            Sender hardware address

        Returns
        -------
        packet: :py:class:`~.EthernetII`
        """
        if not isinstance(target, IPv4Address):
            target = IPv4Address(target)
        if not isinstance(sender, IPv4Address):
            sender = IPv4Address(sender)
        if not isinstance(hw_snd, HWAddress):
            hw_snd = HWAddress(hw_snd)
        if not isinstance(hw_tgt, HWAddress):
            hw_tgt = HWAddress(hw_tgt)

        cdef cppEthernetII eth_pdu = cpp_make_arp_reply(
            (<IPv4Address> target).ptr[0],
            (<IPv4Address> sender).ptr[0],
            (<HWAddress> hw_tgt).ptr[0],
            (<HWAddress> hw_snd).ptr[0]
        )

        return EthernetII.from_ptr(eth_pdu.clone(), parent=None)

    """
    Sender's hardware address (read-write, :py:class:`~.HWAddress`)
    """
    @property
    def sender_hw_addr(self):
        return HWAddress(<bytes>(self.ptr.sender_hw_addr().to_string()))

    @sender_hw_addr.setter
    def sender_hw_addr(self, value):
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        self.ptr.sender_hw_addr((<HWAddress> value).ptr[0])

    """
    Target's hardware address (read-write, :py:class:`~.HWAddress`)
    """
    @property
    def target_hw_addr(self):
        return HWAddress(<bytes>(self.ptr.target_hw_addr().to_string()))

    @target_hw_addr.setter
    def target_hw_addr(self, value):
        if not isinstance(value, HWAddress):
            value = HWAddress(value)
        self.ptr.target_hw_addr((<HWAddress> value).ptr[0])

    """
    Sender's IP address (read-write, :py:class:`~.IPv4Address`)
    """
    @property
    def sender_ip_addr(self):
        return IPv4Address(<bytes>(self.ptr.sender_ip_addr().to_string()))

    @sender_ip_addr.setter
    def sender_ip_addr(self, value):
        if not isinstance(value, IPv4Address):
            value = IPv4Address(value)
        self.ptr.sender_ip_addr((<IPv4Address> value).ptr[0])

    """
    Target's IP address (read-write, :py:class:`~.IPv4Address`)
    """
    @property
    def target_ip_addr(self):
        return IPv4Address(<bytes>(self.ptr.target_ip_addr().to_string()))

    @target_ip_addr.setter
    def target_ip_addr(self, value):
        if not isinstance(value, IPv4Address):
            value = IPv4Address(value)
        self.ptr.target_ip_addr((<IPv4Address> value).ptr[0])

    """
    Hardware address format field (read-write, `uint16_t`)
    """
    @property
    def hw_addr_format(self):
        return self.ptr.hw_addr_format()
    
    @hw_addr_format.setter
    def hw_addr_format(self, value):
        self.ptr.hw_addr_format(<uint16_t>int(value))

    """
    Protocol address format field (read-write, `uint16_t`)
    """
    @property
    def prot_addr_format(self):
        return self.ptr.prot_addr_format()

    @prot_addr_format.setter
    def prot_addr_format(self, value):
        self.ptr.prot_addr_format(<uint16_t>int(value))

    """
    Hardware address length field (read-write, `uint8_t`)
    """
    @property
    def hw_addr_length(self):
        return self.ptr.hw_addr_length()

    @hw_addr_length.setter
    def hw_addr_length(self, value):
        self.ptr.hw_addr_length(<uint8_t>int(value))

    """
    Protocol address length field (read-write, `uint8_t`)
    """
    @property
    def prot_addr_length(self):
        return self.ptr.prot_addr_length()

    @prot_addr_length.setter
    def prot_addr_length(self, value):
        self.ptr.prot_addr_length(<uint8_t>int(value))

    """
    ARP opcode field (:py:class:`~.ARP.Flags`)
    """
    @property
    def opcode(self):
        return self.ptr.opcode()

    @opcode.setter
    def opcode(self, value):
        if isinstance(value, ARP.Flags):
            value = value.value
        self.ptr.opcode(<ARP_Flags> value)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppARP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppARP*> ptr
