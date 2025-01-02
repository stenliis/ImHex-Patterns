#pragma description pcapng header and packets

#include <std/mem.pat>
#include <std/io.pat>
#include <std/sys.pat>
#include <std/core.pat>
#include <type/ip.pat>
#include <type/mac.pat>

//some pcapng are very large -> increase this limit when needed
#pragma pattern_limit 512000

//global variables
std::mem::Endian current_endian = std::core::get_endian();

//MACRO like define
#define ABORT_PARSING u8 corrupted[while (!std::mem::eof())]; return;
#define UNKNOWN_OPTION std::warning(std::format("Unknown option: {} : {} ", type, u16(type))); u8 data[len]; std::mem::AlignTo<4>;
#define UNKNOWN_BLOCK std::warning(std::format("Unknown block: {} : {}", type, u32(type))); u8 data[total_len_a - 12]; std::mem::AlignTo<4>;
     
     
enum block_type : u32 {
    RESERVED                = 0x00000000,
    INTERFACE_DESCRIPTION   = 0x00000001,
    PACKET_BLOCK            = 0x00000002,
    SIMPLE_PACKET           = 0x00000003,
    NAME_RESOLUTION         = 0x00000004,
    INTERFACE_STATISTICS    = 0x00000005,
    ENHANCED_PACKET         = 0x00000006,
    IRIG_TIMESTAMP          = 0x00000007, // IRIG Timestamp Block (requested by Gianluca Varenni <gianluca.varenni@cacetech.com>, CACE Technologies LLC); code also used for Socket Aggregation Event Block
    ARINC                   = 0x00000008, // ARINC 429 in AFDX Encapsulation Information Block (requested by Gianluca Varenni <gianluca.varenni@cacetech.com>, CACE Technologies LLC)
    SYSTEMD                 = 0x00000009, // [systemd Journal Export Block][I-D.richardson-opsawg-pcapng-extras]
    DECRYPTION_SECRETS      = 0x0000000A,
    HONE_MACHINE_INFO       = 0x00000101, // Hone Project Machine Info Block (see also Google version)
    HONE_CONNECTION_EVENT   = 0x00000102, // Hone Project Connection Event Block (see also Google version)
    SYSDIG_MACHINE_INFO     = 0x00000201, // Sysdig Machine Info Block
    SYSDIG_PROCESS_INFO     = 0x00000202, // Sysdig Process Info Block, version 1
    SYSDIG_FD_LIST          = 0x00000203, // Sysdig FD List Block
    SYSDIG_EVENT            = 0x00000204, // Sysdig Event Block
    SYSDIG_INTERFACE_LIST   = 0x00000205, // Sysdig Interface List Block
    SYSDIG_USER_LIST        = 0x00000206, // Sysdig User List Block
    SYSDIG_PROCESS_INFO     = 0x00000207, // Sysdig Process Info Block, version 2
    SYSDIG_EVENT_WITH_FLAGS = 0x00000208, // Sysdig Event Block with flags
    SYSDIG_PROCESS_INFO_V3  = 0x00000209, // Sysdig Process Info Block, version 3
    SYSDIG_PROCESS_INFO_V4  = 0x00000210, // Sysdig Process Info Block, version 4
    SYSDIG_PROCESS_INFO_V5  = 0x00000211, // Sysdig Process Info Block, version 5
    SYSDIG_PROCESS_INFO_V6  = 0x00000212, // Sysdig Process Info Block, version 6
    SYSDIG_PROCESS_INFO_V7  = 0x00000213, // Sysdig Process Info Block, version 7
    CUSTOM_BLOCK_CAN_COPY   = 0x00000BAD, // Custom Block that rewriters can copy into new files (Section 4.8)
    CUSTOM_BLOCK_CAN_NOT_COPY = 0x40000BAD, // Custom Block that rewriters should not copy into new files (Section 4.8)
    SECTION_HEADER          = 0x0A0D0D0A,
    RESERVED                = 0x0A0D0A00 ... 0x0A0D0AFF, //	Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
    //RESERVED                = 0x??0A0D0A //	Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
    //RESERVED                = 0x??0A0D0D, //	Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
    RESERVED                = 0x0D0D0A00 ... 0x0D0D0AFF, // Reserved. Used to detect trace files corrupted because of file transfers using the FTP protocol in text mode.
    RESERVED                = 0x80000000 ... 0xFFFFFFFF, // Reserved for local use.
};

enum endians : u32 {
    LE = 0x1A2B3C4D,
    BE = 0x4D3C2B1A,
};

enum shb_option_type : u16 {
    ENDOFOPT	   = 0,
    COMMENT        = 1,
    SHB_HARDWARE   = 2,
    SHB_OS         = 3,
    SHB_USERAPPL   = 4,
    //opt_custom	2988/2989/19372/19373
};

enum if_option_type : u16 {
    ENDOFOPT	   = 0,
    COMMENT        = 1,
    IF_NAME        = 2,
    IF_DESCRIPTION = 3,
    IF_IPv4ADDR	   = 4,
    IF_IPv6ADDR	   = 5,
    IF_MAC_ADDR	   = 6,
    IF_EUI_ADDR    = 7,
    IF_SPEED	   = 8,
    IF_TSRESOL	   = 9,
    IF_TZONE	   = 10,
    IF_FILTER	   = 11,
    IF_OS	       = 12,
    IF_FCSLEN	   = 13,
    IF_TSOFFSET	   = 14,
    IF_HARDWARE	   = 15,
    IF_TXSPEED	   = 16,
    IF_RXSPEED	   = 17,
    IF_IANA_TZNAME = 18,
    //opt_custom	2988/2989/19372/19373
};

enum epb_option_type : u16 {
    ENDOFOPT	   = 0,
    COMMENT        = 1,
    EPB_FLAGS      = 2,
    EPB_HASH       = 3,
    EPB_DROPCOUNT  = 4,
    EPB_PACKETID   = 5,
    EPB_QUEUE      = 6,
    EPB_VERDICT    = 7,
    EPB_PROCESSID_THREADID = 8,
    //opt_custom	2988/2989/19372/19373
};

enum ns_option_type : u16 {
    ENDOFOPT	     = 0,
    COMMENT          = 1,
    NS_DNSNAME       = 2,
    NS_DNS_IPv4_ADDR = 3,
    NS_DNS_IPv6_ADDR = 4,
    //opt_custom	2988/2989/19372/19373
};

enum isb_option_type : u16 {
    ENDOFOPT	     = 0,
    COMMENT          = 1,
    ISB_STARTTIME    = 2,
    ISB_ENDTIME      = 3,
    ISB_IFRECV       = 4,
    ISB_IFDROP       = 5,
    ISB_FILTERACCEPT = 6,
    ISB_OSDROP       = 7,
    ISB_USRDELIV     = 8,
     //opt_custom	2988/2989/19372/19373
};

enum nrb_record_type : u16 {
    NRB_END_OF_RECORD = 0,
    NRB_IPv4_RECORD   = 1,
    NRB_IPv6_RECORD   = 2,
    NRB_EUI48         = 3,
    NRB_EUI64         = 4,
};

enum ns_opton_type : u16 {
    ENDOFOPT	     = 0,
    COMMENT          = 1,
    NS_DNSNAME       = 2,
    NS_DNS_IPv4_ADDR = 3,
    NS_DNS_IPv6_ADDR = 4,
    //opt_custom	2988/2989/19372/19373
};

enum link_type : u16 {
    LINKTYPE_NULL               = 0, //	BSD loopback encapsulation
    LINKTYPE_ETHERNET           = 1, //	IEEE 802.3 Ethernet
    LINKTYPE_EXP_ETHERNET       = 2, //	Xerox experimental 3Mb Ethernet
    LINKTYPE_AX25	            = 3, //	AX.25 packet
    LINKTYPE_PRONET	            = 4, //	Reserved for PRONET
    LINKTYPE_CHAOS	            = 5, //	Reserved for MIT CHAOSNET
    LINKTYPE_IEEE802_5	        = 6, // IEEE 802.5 Token Ring
    LINKTYPE_ARCNET_BSD	        = 7, //	ARCNET Data Packets with BSD encapsulation
    LINKTYPE_SLIP	            = 8, //	SLIP, w/LINKTYPE_SLIP header.
    LINKTYPE_PPP	            = 9, //	PPP, as per RFC 1661/RFC 1662
    LINKTYPE_FDDI	            = 10, // FDDI: per ANSI INCITS 239-1994.
    DO_NOT_USE                  = 11 ... 49, // Do not use these values
    LINKTYPE_PPP_HDLC	        = 50, // PPP in HDLC-like framing, as per RFC 1662
    LINKTYPE_PPP_ETHER	        = 51, // PPPoE; per RFC 2516
    DO_NOT_USE                  = 52 ... 98, // Do not use these values
    LINKTYPE_SYMANTEC_FIREWALL	= 99, // Reserved for Symantec Enterprise Firewall
    LINKTYPE_ATM_RFC1483	    = 100, // RFC 1483 LLC/SNAP-encapsulated ATM
    LINKTYPE_RAW                = 101, // Raw IP; begins with an IPv4 or IPv6 header
    LINKTYPE_SLIP_BSDOS	        = 102, // Reserved for BSD/OS SLIP BPF header
    LINKTYPE_PPP_BSDOS	        = 103, // Reserved for BSD/OS PPP BPF header
    LINKTYPE_C_HDLC	            = 104, // Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547
    LINKTYPE_IEEE802_11	        = 105, // IEEE 802.11 wireless LAN.
    LINKTYPE_ATM_CLIP           = 106, // ATM Classical IP, with no header preceding IP
    LINKTYPE_FRELAY             = 107, // Frame Relay LAPF frames
    LINKTYPE_LOOP	            = 108, // OpenBSD loopback encapsulation
    LINKTYPE_ENC	            = 109, // Reserved for OpenBSD IPSEC encapsulation
    LINKTYPE_LANE8023	        = 110, // Reserved for ATM LANE + 802.3
    LINKTYPE_HIPPI	            = 111, // Reserved for NetBSD HIPPI
    LINKTYPE_HDLC	            = 112, // Reserved for NetBSD HDLC framing
    LINKTYPE_LINUX_SLL	        = 113, // Linux "cooked" capture encapsulation
    LINKTYPE_LTALK	            = 114, // Apple LocalTalk
    LINKTYPE_ECONET	            = 115, // Reserved for Acorn Econet
    LINKTYPE_IPFILTER	        = 116, // Reserved for OpenBSD ipfilter
    LINKTYPE_PFLOG	            = 117, // OpenBSD pflog; "struct pfloghdr" structure
    LINKTYPE_CISCO_IOS	        = 118, // Reserved for Cisco-internal use
    LINKTYPE_IEEE802_11_PRISM   = 119, // Prism monitor mode
    LINKTYPE_IEEE802_11_AIRONET	= 120, // Reserved for 802.11 + FreeFreeBSD Aironet radio metadata
    LINKTYPE_HHDLC	            = 121, // Reserved for Siemens HiPath HDLC
    LINKTYPE_IP_OVER_FC         = 122, // RFC 2625 IP-over-Fibre Channel
    LINKTYPE_SUNATM	            = 123, // ATM traffic, / per SunATM devices
    LINKTYPE_RIO	            = 124, // Reserved for RapidIO
    LINKTYPE_PCI_EXP	        = 125, // Reserved for PCI Express
    LINKTYPE_AURORA	            = 126, // Reserved for Xilinx Aurora link layer
    LINKTYPE_IEEE802_11_RADIOTAP= 127, // Radiotap header[Radiotap], followed by an 802.11 header
    LINKTYPE_TZSP	            = 128, // Reserved for Tazmen Sniffer Protocol
    LINKTYPE_ARCNET_LINUX	    = 129, // ARCNET Data Packets, per RFC 1051 frames w/variations
    LINKTYPE_JUNIPER_MLPPP	    = 130, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_MLFR	    = 131, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_ES	        = 132, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_GGSN	    = 133, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_MFR	    = 134, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_ATM2	    = 135, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_SERVICES	= 136, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_ATM1	    = 137, // Reserved for Juniper Networks
    LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138, // Apple IP-over-IEEE 1394 cooked header
    LINKTYPE_MTP2_WITH_PHDR	    = 139, // Signaling System 7 (SS7) Message Transfer Part Level ITU-T Q.703
    LINKTYPE_MTP2	            = 140, // SS7 Level 2, Q.703
    LINKTYPE_MTP3	            = 141, // SS7 Level 3, Q.704
    LINKTYPE_SCCP	            = 142, // SS7 Control Part, ITU-T Q.711/Q.712/Q.713/Q.714
    LINKTYPE_DOCSIS	            = 143, // DOCSIS MAC frames, DOCSIS 3.1
    LINKTYPE_LINUX_IRDA	        = 144, // Linux-IrDA packets w/LINKTYPE_LINUX_IRDA header
    LINKTYPE_IBM_SP	            = 145, // Reserved for IBM SP switch
    LINKTYPE_IBM_SN	            = 146, // Reserved for IBM Next Federation switch
    LINKTYPE_RESERVED_01	    = 147, // For private use
    LINKTYPE_RESERVED_02	    = 148, // For private use
    LINKTYPE_RESERVED_03	    = 149, // For private use
    LINKTYPE_RESERVED_04	    = 150, // For private use
    LINKTYPE_RESERVED_05	    = 151, // For private use
    LINKTYPE_RESERVED_06	    = 152, // For private use
    LINKTYPE_RESERVED_07	    = 153, // For private use
    LINKTYPE_RESERVED_08	    = 154, // For private use
    LINKTYPE_RESERVED_09	    = 155, // For private use
    LINKTYPE_RESERVED_10	    = 156, // For private use
    LINKTYPE_RESERVED_11	    = 157, // For private use
    LINKTYPE_RESERVED_12	    = 158, // For private use
    LINKTYPE_RESERVED_13	    = 159, // For private use
    LINKTYPE_RESERVED_14	    = 160, // For private use
    LINKTYPE_RESERVED_15	    = 161, // For private use
    LINKTYPE_RESERVED_16	    = 162, // For private use
    LINKTYPE_IEEE802_11_AVS	    = 163, // AVS header[AVS], followed by an 802.11 header
    LINKTYPE_JUNIPER_MONITOR	= 164, // Reserved for Juniper Networks
    LINKTYPE_BACNET_MS_TP	    = 165, // BACnet MS/TP frames, per 9.3 MS/TP Frame Format ANSI 135
    LINKTYPE_PPP_PPPD	        = 166, // PPP in HDLC-like encapsulation, like LINKTYPE_PPP_HDLC, different stuffing
    LINKTYPE_JUNIPER_PPPOE	    = 167, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_PPPOE_ATM	= 168, // Reserved for Juniper Networks
    LINKTYPE_GPRS_LLC	        = 169, // General Packet Radio Service Logical Link Control, as per 3GPP TS 04.64
    LINKTYPE_GPF_T	            = 170, // Transparent-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303
    LINKTYPE_GPF_F	            = 171, // Frame-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303
    LINKTYPE_GCOM_T1E1	        = 172, // Reserved for Gcom T1/E1 line monitoring equipment
    LINKTYPE_GCOM_SERIAL	    = 173, // Reserved for Gcom T1/E1 line monitoring equipment
    LINKTYPE_JUNIPER_PIC_PEER	= 174, // Reserved for Juniper Networks
    LINKTYPE_ERF_ETH	        = 175, // Endace ERF header followed by 802.3 Ethernet
    LINKTYPE_ERF_POS	        = 176, // Endace ERF header followed by Packet-over-SONET
    LINKTYPE_LINUX_LAPD	        = 177, // Link Access Procedures on the D Channel (LAPD) frames, as specified by ITU-T Recommendation Q.920 and ITU-T Recommendation Q.921 , captured via vISDN, with a LINKTYPE_LINUX_LAPD header , followed by the Q.921 frame, starting with the address field.
    LINKTYPE_JUNIPER_ETHER	    = 178, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_PPP	    = 179, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_FRELAY	    = 180, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_CHDLC	    = 181, // Reserved for Juniper Networks
    LINKTYPE_MFR	            = 182, // FRF.16.1 Multi-Link Frame Relay frames, beginning with an FRF.12 Interface fragmentation format fragmentation header.
    LINKTYPE_JUNIPER_VP	        = 182, // Reserved for Juniper Networks
    LINKTYPE_A653_ICM	        = 185, // Reserved for Arinc 653 Interpartition Communication messages
    LINKTYPE_USB_FREEBSD	    = 186, // USB packets, beginning with a FreeBSD USB header
    LINKTYPE_BLUETOOTH_HCI_H4	= 187, // Bluetooth HCI UART transport layer; the frame contains an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent Bluetooth Core specification , followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification.
    LINKTYPE_IEEE802_16_MAC_CPS	= 188, // Reserved for IEEE 802.16 MAC Common Part Sublayer
    LINKTYPE_USB_LINUX	        = 189, // USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree. Only the first 48 bytes of that header are present. All fields in the header are in host byte order. When performing a live capture, the host byte order is the byte order of the machine on which the packets are captured. When reading a pcap file, the byte order is the byte order for the file, as specified by the file's magic number; when reading a pcapng file, the byte order is the byte order for the section of the pcapng file, as specified by the Section Header Block.
    LINKTYPE_CAN20B	            = 190, // Reserved for Controller Area Network (CAN) v. 2.0B packets
    LINKTYPE_IEEE802_15_4_LINUX	= 191, // IEEE 802.15.4, with address fields padded, as is done by Linux drivers
    LINKTYPE_PPI	            = 192, // Per-Packet Information information, as specified by the Per-Packet Information Header Specification , followed by a packet with the LINKTYPE_ value specified by the pph_dlt field of that header.
    LINKTYPE_IEEE802_16_MAC_CPS_RADIO = 193, // Reserved for 802.16 MAC Common Part Sublayer plus radio header
    LINKTYPE_JUNIPER_ISM	    = 194, // Reserved for Juniper Networks
    LINKTYPE_IEEE802_15_4_WITHFCS = 195, // IEEE 802.15.4 Low-Rate Wireless Networks, with each packet having the FCS at the end of the frame.
    LINKTYPE_SITA	            = 196, // Various link-layer types, with a pseudo-header , for SITA
    LINKTYPE_ERF	            = 197, // Various link-layer types, with a pseudo-header, for Endace DAG cards; encapsulates Endace ERF records.
    LINKTYPE_RAIF1	            = 198, // Reserved for Ethernet packets captured from a u10 Networks board
    LINKTYPE_IPMB_KONTRON	    = 199, // Reserved for IPMB packet for IPMI, with a 2-byte header
    LINKTYPE_JUNIPER_ST	        = 200, // Reserved for Juniper Networks
    LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR	= 201, // Bluetooth HCI UART transport layer; the frame contains a 4-byte direction field, in network byte order (big-endian), the low-order bit of which is set if the frame was sent from the host to the controller and clear if the frame was received by the host from the controller, followed by an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent Bluetooth Core specification , followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification.
    LINKTYPE_AX25_KISS	        = 202, // AX.25 packet, with a 1-byte KISS header containing a type indicator.
    LINKTYPE_LAPD	            = 203, // Link Access Procedures on the D Channel (LAPD) frames, as specified by ITU-T Recommendation Q.920 and ITU-T Recommendation Q.921 , starting with the address field, with no pseudo-header.
    LINKTYPE_PPP_WITH_DIR	    = 204, // PPP, as per RFC 1661 and RFC 1662 , preceded with a one-byte pseudo-header with a zero value meaning received by this host and a non-zero value meaning sent by this host; if the first 2 bytes are 0xff and 0x03, it's PPP in HDLC-like framing, with the PPP header following those two bytes, otherwise it's PPP without framing, and the packet begins with the PPP header. The data in the frame is not octet-stuffed or bit-stuffed.
    LINKTYPE_C_HDLC_WITH_DIR	= 205, // Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547 , preceded with a one-byte pseudo-header with a zero value meaning received by this host and a non-zero value meaning sent by this host.
    LINKTYPE_FRELAY_WITH_DIR	= 206, // Frame Relay LAPF frames, beginning with a one-byte pseudo-header with a zero value meaning received by this host (DCE->DTE) and a non-zero value meaning sent by this host (DTE->DCE), followed by an ITU-T Recommendation Q.922 LAPF header starting with the address field, and without an FCS at the end of the frame.
    LINKTYPE_LAPB_WITH_DIR	    = 207, // Link Access Procedure, Balanced (LAPB), as specified by ITU-T Recommendation X.25 , preceded with a one-byte pseudo-header with a zero value meaning received by this host (DCE->DTE) and a non-zero value meaning sent by this host (DTE->DCE).
    RESERVED	                = 208, // Reserved for an unspecified link-layer type
    LINKTYPE_IPMB_LINUX	        = 209, // IPMB over an I2C circuit, with a Linux-specific pseudo-header
    LINKTYPE_FLEXRAY	        = 210, // Reserved for FlexRay automotive bus
    LINKTYPE_MOST	            = 211, // Reserved for Media Oriented Systems Transport (MOST) bus
    LINKTYPE_LIN	            = 212, // Reserved for Local Interconnect Network (LIN) bus for vehicle networks
    LINKTYPE_X2E_SERIAL	        = 213, // Reserved for X2E serial line captures
    LINKTYPE_X2E_XORAYA	        = 214, // Reserved for X2E Xoraya data loggers
    LINKTYPE_IEEE802_15_4_NONASK_PHY = 215, // IEEE 802.15.4 Low-Rate Wireless Networks, with each packet having the FCS at the end of the frame, and with the PHY-level data for the O-QPSK, BPSK, GFSK, MSK, and RCC DSS BPSK PHYs (4 octets of 0 as preamble, one octet of SFD, one octet of frame length + reserved bit) preceding the MAC-layer data (starting with the frame control field).
    LINKTYPE_LINUX_EVDEV        = 216, // Reserved for Linux evdev messages
    LINKTYPE_GSMTAP_UM	        = 217, // Reserved for GSM Um interface, with gsmtap header
    LINKTYPE_GSMTAP_ABIS	    = 218, // Reserved for GSM Abis interface, with gsmtap header
    LINKTYPE_MPLS	            = 219, // MPLS packets with MPLS label as the header
    LINKTYPE_USB_LINUX_MMAPPED	= 220, // USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree. All 64 bytes of the header are present. All fields in the header are in host byte order. When performing a live capture, the host byte order is the byte order of the machine on which the packets are captured. When reading a pcap file, the byte order is the byte order for the file, as specified by the file's magic number; when reading a pcapng file, the byte order is the byte order for the section of the pcapng file, as specified by the Section Header Block. For isochronous transfers, the ndesc field specifies the number of isochronous descriptors that follow.
    LINKTYPE_DECT	            = 221, // Reserved for DECT packets, with a pseudo-header
    LINKTYPE_AOS	            = 222, // Reserved for OS Space Data Link Protocol
    LINKTYPE_WIHART	            = 223, // Reserved for Wireless HART (Highway Addressable Remote Transducer)
    LINKTYPE_FC_2	            = 224, // Fibre Channel FC-2 frames, beginning with a Frame_Header.
    LINKTYPE_FC_2_WITH_FRAME_DELIMS	= 225, // Fibre Channel FC-2 frames, beginning an encoding of the SOF, followed by a Frame_Header, and ending with an encoding of the SOF. The encodings represent the frame delimiters as 4-byte sequences representing the corresponding ordered sets, with K28.5 represented as 0xBC, and the D symbols as the corresponding byte values; for example, SOFi2, which is K28.5 - D21.5 - D1.2 - D21.2, is represented as 0xBC 0xB5 0x55 0x55.
    LINKTYPE_IPNET	            = 226, // Solaris ipnet pseudo-header , followed by an IPv4 or IPv6 datagram.
    LINKTYPE_CAN_SOCKETCAN      = 227, // CAN (Controller Area Network) frames, with a pseudo-header followed by the frame payload.
    LINKTYPE_IPV4	            = 228, // Raw IPv4; the packet begins with an IPv4 header.
    LINKTYPE_IPV6	            = 229, // Raw IPv6; the packet begins with an IPv6 header.
    LINKTYPE_IEEE802_15_4_NOFCS	= 230, // IEEE 802.15.4 Low-Rate Wireless Network, without the FCS at the end of the frame.
    LINKTYPE_DBUS	            = 231, // Raw D-Bus messages , starting with the endianness flag, followed by the message type, etc., but without the authentication handshake before the message sequence.
    LINKTYPE_JUNIPER_VS	        = 232, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_SRX_E2E	= 233, // Reserved for Juniper Networks
    LINKTYPE_JUNIPER_FIBRECHANNEL=234, // Reserved for Juniper Networks
    LINKTYPE_DVB_CI	            = 235, // DVB-CI (DVB Common Interface for communication between a PC Card module and a DVB receiver), with the message format specified by the PCAP format for DVB-CI specification
    LINKTYPE_MUX27010	        = 236, // Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but not the same as, 27.010).
    LINKTYPE_STANAG_5066_D_PDU	= 237, // D_PDUs as described by NATO standard STANAG 5066, starting with the synchronization sequence, and including both header and data CRCs. The current version of STANAG 5066 is backwards-compatible with the 1.0.2 version , although newer versions are classified.
    LINKTYPE_JUNIPER_ATM_CEMIC	= 238, // Reserved for Juniper Networks
    LINKTYPE_NFLOG              = 239, // Linux netlink NETLINK NFLOG socket log messages.
    LINKTYPE_NETANALYZER	    = 240, // Pseudo-header for Hilscher Gesellschaft fuer Systemautomation mbH netANALYZER devices , followed by an Ethernet frame, beginning with the MAC header and ending with the FCS.
    LINKTYPE_NETANALYZER_TRANSPARENT = 241, // Pseudo-header for Hilscher Gesellschaft fuer Systemautomation mbH netANALYZER devices , followed by an Ethernet frame, beginning with the preamble, SFD, and MAC header, and ending with the FCS.
    LINKTYPE_IPOIB	            = 242, // IP-over-InfiniBand, as specified by RFC 4391 section 6
    LINKTYPE_MPEG_2_TS	        = 243, // MPEG-2 Transport Stream transport packets, as specified by ISO 13818-1/ ITU-T Recommendation H.222.0 (see table 2-2 of section 2.4.3.2 Transport Stream packet layer).
    LINKTYPE_NG40	            = 244, // Pseudo-header for ng4T GmbH's UMTS Iub/Iur-over-ATM and Iub/Iur-over-IP format as used by their ng40 protocol tester , followed by frames for the Frame Protocol as specified by 3GPP TS 25.427 for dedicated channels and 3GPP TS 25.435 for common/shared channels in the case of ATM AAL2 or UDP traffic, by SSCOP packets as specified by ITU-T Recommendation Q.2110 for ATM AAL5 traffic, and by NBAP packets for SCTP traffic.
    LINKTYPE_NFC_LLCP	        = 245, // Pseudo-header for NFC LLCP packet captures , followed by frame data for the LLCP Protocol as specified by NFCForum-TS-LLCP_1.1
    LINKTYPE_PFSYNC	            = 246, // Reserved for pfsync output
    LINKTYPE_INFINIBAND	        = 247, // Raw InfiniBand frames, starting with the Local Routing Header, as specified in Chapter 5 Data packet format of InfiniBand[TM] Architectural Specification Release 1.2.1 Volume 1 - General Specifications
    LINKTYPE_SCTP	            = 248, // SCTP packets, as defined by RFC 4960 , with no lower-level protocols such as IPv4 or IPv6.
    LINKTYPE_USBPCAP	        = 249, // USB packets, beginning with a USBPcap header
    LINKTYPE_RTAC_SERIAL	    = 250, // Serial-line packet header for the Schweitzer Engineering Laboratories RTAC product , followed by a payload for one of a number of industrial control protocols.
    LINKTYPE_BLUETOOTH_LE_LL	= 251, // Bluetooth Low Energy air interface Link Layer packets, in the format described in section 2.1 PACKET FORMAT of volume 6 of the Bluetooth Specification Version 4.0 (see PDF page 2200), but without the Preamble.
    LINKTYPE_WIRESHARK_UPPER_PDU= 252, // Reserved for Wireshark
    LINKTYPE_NETLINK	        = 253, // Linux Netlink capture encapsulation
    LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254, // Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack
    LINKTYPE_BLUETOOTH_BREDR_BB	= 255, // Bluetooth Basic Rate and Enhanced Data Rate baseband packets
    LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256, // Bluetooth Low Energy link-layer packets
    LINKTYPE_PROFIBUS_DL	    = 257, // PROFIBUS data link layer packets, as specified by IEC standard 61158-4-3, beginning with the start delimiter, ending with the end delimiter, and including all octets between them.
    LINKTYPE_PKTAP	            = 258, // Apple PKTAP capture encapsulation
    LINKTYPE_EPON	            = 259, // Ethernet-over-passive-optical-network packets, starting with the last 6 octets of the modified preamble as specified by 65.1.3.2 Transmit in Clause 65 of Section 5 of IEEE 802.3 , followed immediately by an Ethernet frame.
    LINKTYPE_IPMI_HPM_2         = 260, // IPMI trace packets, as specified by Table 3-20 Trace Data Block Format in the PICMG HPM.2 specification The time stamps for packets in this format must match the time stamps in the Trace Data Blocks.
    LINKTYPE_ZWAVE_R1_R2	    = 261, // Z-Wave RF profile R1 and R2 packets , as specified by ITU-T Recommendation G.9959 , with some MAC layer fields moved.
    LINKTYPE_ZWAVE_R3	        = 262, // Z-Wave RF profile R3 packets , as specified by ITU-T Recommendation G.9959 , with some MAC layer fields moved.
    LINKTYPE_WATTSTOPPER_DLM	= 263, // Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol common packet structure captures.
    LINKTYPE_ISO_14443	        = 264, // Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card, PICC) and card readers (Proximity Coupling Device, PCD), with the message format specified by the PCAP format for ISO14443 specification
    LINKTYPE_RDS	            = 265, // Radio data system (RDS) groups, as per IEC 62106, encapsulated in this form
    LINKTYPE_USB_DARWIN	        = 266, // USB packets, beginning with a Darwin (macOS, etc.) USB header
    LINKTYPE_OPENFLOW	        = 267, // Reserved for OpenBSD DLT_OPENFLOW
    LINKTYPE_SDLC	            = 268, // SDLC packets, as specified by Chapter 1, DLC Links, section Synchronous Data Link Control (SDLC) of Systems Network Architecture Formats, GA27-3136-20 , without the flag fields, zero-bit insertion, or Frame Check Sequence field, containing SNA path information units (PIUs) as the payload.
    LINKTYPE_TI_LLN_SNIFFER	    = 269, // Reserved for Texas Instruments protocol sniffer
    LINKTYPE_LORATAP	        = 270, // LoRaTap pseudo-header , followed by the payload, which is typically the PHYPayload from the LoRaWan specification
    LINKTYPE_VSOCK	            = 271, // Protocol for communication between host and guest machines in VMware and KVM hypervisors.
    LINKTYPE_NORDIC_BLE	        = 272, // Messages to and from a Nordic Semiconductor nRF Sniffer for Bluetooth LE packets, beginning with a pseudo-header
    LINKTYPE_DOCSIS31_XRA31     = 273, // DOCSIS packets and bursts, preceded by a pseudo-header giving metadata about the packet
    LINKTYPE_ETHERNET_MPACKET	= 274, // mPackets, as specified by IEEE 802.3br Figure 99-4, starting with the preamble and always ending with a CRC field.
    LINKTYPE_DISPLAYPORT_AUX	= 275, // DisplayPort AUX channel monitoring data as specified by VESA DisplayPort(DP) Standard preceded by a pseudo-header
    LINKTYPE_LINUX_SLL2	        = 276, // Linux cooked capture encapsulation v2
    LINKTYPE_SERCOS_MONITOR	    = 277, // Reserved for Sercos Monitor
    LINKTYPE_OPENVIZSLA	        = 278, // Openvizsla FPGA-based USB sniffer
    LINKTYPE_EBHSCR	            = 279, // Elektrobit High Speed Capture and Replay (EBHSCR) format
    LINKTYPE_VPP_DISPATCH	    = 280, // Records in traces from the http://fd.io VPP graph dispatch tracer, in the the graph dispatcher trace format
    LINKTYPE_DSA_TAG_BRCM	    = 281, // Ethernet frames, with a switch tag inserted between the source address field and the type/length field in the Ethernet header.
    LINKTYPE_DSA_TAG_BRCM_PREPEND=282, // Ethernet frames, with a switch tag inserted before the destination address in the Ethernet header.
    LINKTYPE_IEEE802_15_4_TAP	= 283, // IEEE 802.15.4 Low-Rate Wireless Networks, with a pseudo-header containing TLVs with metadata preceding the 802.15.4 header.
    LINKTYPE_DSA_TAG_DSA	    = 284, // Ethernet frames, with a switch tag inserted between the source address field and the type/length field in the Ethernet header.
    LINKTYPE_DSA_TAG_EDSA	    = 285, // Ethernet frames, with a programmable Ethernet type switch tag inserted between the source address field and the type/length field in the Ethernet header.
    LINKTYPE_ELEE	            = 286, // Payload of lawful intercept packets using the ELEE protocol The packet begins with the ELEE header; it does not include any transport-layer or lower-layer headers for protcols used to transport ELEE packets.
    LINKTYPE_Z_WAVE_SERIAL	    = 287, // Serial frames transmitted between a host and a Z-Wave chip over an RS-232 or USB serial connection, as described in section 5 of the Z-Wave Serial API Host Application Programming Guide
    LINKTYPE_USB_2_0	        = 288, // USB 2.0, 1.1, or 1.0 packet, beginning with a PID, as described by Chapter 8 Protocol Layer of the the Universal Serial Bus Specification Revision 2.0
    LINKTYPE_ATSC_ALP	        = 289, // ATSC Link-Layer Protocol frames, as described in section 5 of the A/330 Link-Layer Protocol specification, found at the ATSC 3.0 standards page , beginning with a Base Header
    LINKTYPE_SPECIFICATION_REQUIRED = 290 ... 32767, // unused values, available for registration (Specification Required)
    LINKTYPE_FCFS               = 32768 ... 64999, // unused values, available for registration (First-Come First-served)
    LINKTYPE_PRIVATE_USE        = 65000 ... 65535, // private use link types.
};

struct if_option {
    if_option_type type;
    u16 len;
    if (type == if_option_type::IF_NAME) {
        char if_name[len];
    }
    else if (type == if_option_type::IF_DESCRIPTION) {
        char if_description[len];
    }
    else if (type == if_option_type::IF_IPv4ADDR) {
        type::IPv4Address addr;;
    }
    else if (type == if_option_type::IF_IPv6ADDR) {
        type::IPv6Address addr;
    }
    else if (type == if_option_type::IF_MAC_ADDR) {
        type::MACAddress  addr;
    }
    else if (type == if_option_type::IF_EUI_ADDR) {
        type::IPv6Address eui;
    }
    else if (type == if_option_type::IF_SPEED) {
        u64 speed;
    }
    else if (type == if_option_type::IF_TSRESOL) {
        u8 tsresol;
    }
    else if (type == if_option_type::IF_TZONE) {
        u32 zone;
    }
    else if (type == if_option_type::IF_FILTER) {
        char filter[len];
    }
    else if (type == if_option_type::IF_OS) {
        char os_nam[len];
    }
    else if (type == if_option_type::IF_FCSLEN) {
        u8 fcslen;
    }
    else if (type == if_option_type::IF_TSOFFSET) {
        u64 rsoffset;
    }
    else if (type == if_option_type::IF_HARDWARE) {
        char if_hardware[len];
    }
    else if (type == if_option_type::IF_TXSPEED) {
        u64 txspeed;
    }
    else if (type == if_option_type::IF_RXSPEED) {
        u64 rxspeed;
    }
    else if (type == if_option_type::IF_IANA_TZNAME) {
        char tzname[len];
    }
    else if (type == if_option_type::COMMENT) {
        char comment[len]; 
    }
    else if (type == if_option_type::ENDOFOPT) {
        //end of options
    }
    else {
        UNKNOWN_OPTION
    }
    std::mem::AlignTo<4>;
};


struct isb_option {
    isb_option_type type;
    u16 len;
    if (type == isb_option_type::ISB_STARTTIME) {
        u64 start_time;
    }
    else if (type == isb_option_type::ISB_ENDTIME) {
        u64 end_time;
    }
    else if (type == isb_option_type::ISB_IFRECV) {
        u64 ifrecv;
    }
    else if (type == isb_option_type::ISB_IFDROP) {
        u64 ifdrop;
    }
    else if (type == isb_option_type::ISB_FILTERACCEPT) {
        u64 filteraccept;
    }
    else if (type == isb_option_type::ISB_OSDROP) {
        u64 osdrop;
    }
    else if (type == isb_option_type::ISB_USRDELIV) {
        u64 usrdeliv;
    }
    else if (type == isb_option_type::COMMENT) {
        char comment[len];
    }
    else if (type == isb_option_type::ENDOFOPT) {
        //end of options
    }
    else {
        UNKNOWN_OPTION
    }
    std::mem::AlignTo<4>;
};   

struct nrb_record {
    nrb_record_type type;
    u16 len;
    if (type == nrb_record_type::NRB_IPv4_RECORD) {
        char data[len];
    }
    else if (type == nrb_record_type::NRB_IPv6_RECORD) {
        char data[len];
    }
    else if (type == nrb_record_type::NRB_EUI48) {
        type::MACAddress eui48;
    }
    else if (type == nrb_record_type::NRB_EUI64) {
        u64 eui;
    }
    else if (type == nrb_record_type::NRB_END_OF_RECORD) {
        //end of option
    } else {
        UNKNOWN_OPTION
    }
    std::mem::AlignTo<4>;
};

struct ns_option {
    ns_option_type type;
    u16 len;
    if (type == ns_option_type::NS_DNSNAME) {
        char dns_name[len];
    }
    else if (type == ns_option_type::NS_DNS_IPv4_ADDR) {
        type::IPv4Address addr;
    }
    else if (type == ns_option_type::NS_DNS_IPv6_ADDR) {
        type::IPv6Address addr;
    }
    else if (type == ns_option_type::COMMENT) {
        char comment[len];
    }
    else if (type == ns_option_type::ENDOFOPT) {
        //end of options
    } else {
        UNKNOWN_OPTION
    }
    std::mem::AlignTo<4>;    
};

struct shb_option {
    shb_option_type type;
    u16 len;
    if (type == shb_option_type::SHB_HARDWARE) {
        char hardware[len];
    }
    else if (type == shb_option_type::SHB_OS) {
        char os_name[len];
    }
    else if (type == shb_option_type::SHB_USERAPPL) {
        char app_name[len];
    }
    else if (type == shb_option_type::COMMENT) {
        char comment[len];
    }
    else if (type == shb_option_type::ENDOFOPT) {
        //end of options
    }
    else {
        UNKNOWN_OPTION
    }
    std::mem::AlignTo<4>;
};

enum epb_flag_direction : u8 {
    UNKNOWN  = 0,
    INBOUND  = 1,
    OUTBOUND = 2,
};

enum epb_flag_reception_type : u8 {
    UNKNOWN     = 0,
    UNICAST     = 1,
    MULTICAST   = 2,
    BROADCAST   = 3,
    PROMISCUOUS = 4,
};

bitfield epb_flags {
    epb_flag_direction direction : 2;
    epb_flag_reception_type reception_type: 3;
    fcs_len : 4;
    reserved : 7;
    link_layer_dependent_errors : 16;
}; 

struct epb_option {
    epb_option_type type;
    u16 len;
    if (type == epb_option_type::EPB_FLAGS) {
        epb_flags flags;
    }
    else if (type == epb_option_type::EPB_HASH) {
        u8 hash[len];
    }
    else if (type == epb_option_type::EPB_DROPCOUNT) {
        u64 dropcount;
    }
    else if (type == epb_option_type::EPB_PACKETID) {
        u64 packetid;
    }
    else if (type == epb_option_type::EPB_QUEUE) {
        u32 queue;
    }
    else if (type == epb_option_type::EPB_VERDICT) {
        u8 verdict[len];
    }
    else if (type == epb_option_type::COMMENT) {
        char comment[len];
    }
    else if (type == epb_option_type::ENDOFOPT) {
        //end of options
    }
    else {
        UNKNOWN_OPTION
    }
    std::mem::AlignTo<4>;
};


#define SECTION_HEADER_LEN_WITHOUT_OPTIONS 28
#define INTERFACE_DESCRIPTION_LEN_WITHOUT_OPTIONS 20
#define NAME_RESOLUTION_LEN_WITHOUT_RECORDS_AND_OPTIONS 12
#define INTERFACE_STATISTICS_LEN_WITHOUT_OPTIONS 24
#define ENHANCED_PACKET_LEN_WITHOUT_DATA_AND_OPTIONS 32 

union EndianConverter {
    u32 raw;
    endians end;
};

fn is_last_option() {
    //every options type variant have same end mark (type == 0 and len == 0)
    
    u16 type = std::mem::read_unsigned($, 2);
    if (type != 0) {
        return false;
    }
    u16 len = std::mem::read_unsigned($ + 2, 2);
    if (len != 0) {
        std::warning("Invalid end option len");
    }
    return true;
};

fn check_endian(block_type type) {
    if (type != block_type::SECTION_HEADER)
    {
        return;
    }
    
    EndianConverter conv;
    conv.raw = std::mem::read_unsigned($ + 4, 4);
    endians byte_order = conv.end;

    if (byte_order == endians::LE) {
        std::core::set_endian(std::mem::Endian::Little);
    }
    else if (byte_order == endians::BE)
    {
        std::core::set_endian(std::mem::Endian::Big);
    }
    else
    {
        std::warning("Invalid endians type value");
        ABORT_PARSING
    }
    current_endian = std::core::get_endian();
    
};

struct TLV<T> {
    T record[while(!is_last_option())];
    T record_end;
} [[inline]];

fn calc_len_with_padding(u32 len) {
    u8 pad_len = (4 - len %4) % 4;
    return len + pad_len;
};
                                                                                        
struct base_block {
    std::core::set_endian(current_endian);
    
    block_type type;
    check_endian(type);
    u32 total_len_a;
    
    if (type == block_type::SECTION_HEADER) {
        endians byte_order;
        u16 major_version;
        u16 mirror_version;
        u64 section_len;
        if (total_len_a > SECTION_HEADER_LEN_WITHOUT_OPTIONS) {
            TLV<shb_option>;
        }
    }
    else if (type == block_type::INTERFACE_DESCRIPTION) {
        link_type link_type;
        u16 reserved;
        u32 snap_len;
        if (total_len_a > INTERFACE_DESCRIPTION_LEN_WITHOUT_OPTIONS) {
            TLV<if_option>;
        }
    }
    else if (type == block_type::NAME_RESOLUTION) {
        TLV<nrb_record> nrb;
        if (total_len_a > (NAME_RESOLUTION_LEN_WITHOUT_RECORDS_AND_OPTIONS + sizeof(nrb))) {
            TLV<ns_option>;
        }
    }
    else if (type == block_type::ENHANCED_PACKET) {
        u32 interface_id;
        u64 timestamp;
        u32 captured_packet_len;
        u32 original_packet_len;
        u8 packet_data[captured_packet_len];
        std::mem::AlignTo<4>;
        if (total_len_a > (ENHANCED_PACKET_LEN_WITHOUT_DATA_AND_OPTIONS + calc_len_with_padding(captured_packet_len))) {
            TLV<epb_option>;
        }
    }
    else if (type == block_type::SIMPLE_PACKET) {
        u32 len;
        u8 data[total_len_a - 16];
        std::mem::AlignTo<4>;
    }
    else if (type == block_type::INTERFACE_STATISTICS) {
        u32 interface_id;
        u64 timestamp;
        if (total_len_a > INTERFACE_STATISTICS_LEN_WITHOUT_OPTIONS) {
            TLV<isb_option>;
        }
    }
    else if (type == block_type::CUSTOM_BLOCK_CAN_COPY || type == block_type::CUSTOM_BLOCK_CAN_NOT_COPY) {
        u32 pen;
        u8 data[total_len_a - 16];
        std::mem::AlignTo<4>;
    }

    else {
        UNKNOWN_BLOCK
    }

    u32 total_len_b;
    if (total_len_a != total_len_b) {
        std::warning("Block is corrupted!");
        ABORT_PARSING
    }
};

struct pcapng {
    base_block blocks[while (!std::mem::eof())];
} [[inline]];

pcapng pcapng @ 0x00;