/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>
//#include <v1model.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> ip4Port_t;
typedef bit<8> ip4Proto_t;
typedef bit<32> teid_t;
typedef bit<9> svc_t;

typedef bit<9> switchPort_t;

const switchPort_t SW_PORT_ENB = 1; //SET THIS
const switchPort_t SW_PORT_ESP = 2; //SET THIS
const switchPort_t SW_PORT_PGW = 3; //SET THIS

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_VLAN = 0x8100;

const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;
const bit<8>  IPPROTO_SCTP   = 0x84;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;

const bit<16> GTP_UDP_PORT     = 2152;

const bit<32> MAC_LEARN_RECEIVER = 1;
const bit<32> ARP_LEARN_RECEIVER = 1025;

const bit<48> OWN_MAC = 0x001122334455;

//const bit<48> ESP_MAC = 0x000000000202; //MININET MAC
//const bit<48> ESP_MAC = 0x985aebe038a3; //MAX's MACBOOK MAC
const bit<48> ESP_MAC = 0x3085a9177789; //MAX's old ASUS MAC

const bit<32> IP_PGW = 0xC0A801FE; // 192.168.1.254

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16>   etherType;
}

header vlan_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    bit<48>  sha;
    bit<32> spa;
    bit<48>  tha;
    bit<32> tpa;
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

/* GPRS Tunnelling Protocol (GTP) common part for v1 and v2 */

header gtp_common_t {
	bit<3> version; /* this should be 1 for GTPv1 and 2 for GTPv2 */
	bit<1> pFlag;   /* protocolType for GTPv1 and pFlag for GTPv2 */
	bit<1> tFlag;   /* only used by GTPv2 - teid flag */
	bit<1> eFlag;   /* only used by GTPv1 - E flag */
	bit<1> sFlag;   /* only used by GTPv1 - S flag */
	bit<1> pnFlag;  /* only used by GTPv1 - PN flag */
	bit<8> messageType;
	bit<16> messageLength;
}

header gtp_teid_t {
	bit<32> teid;
}

/* GPRS Tunnelling Protocol (GTP) v1 */

/* 
This header part exists if any of the E, S, or PN flags are on.
*/

header gtpv1_optional_t {
	bit<16> sNumber;
	bit<8> pnNumber;
	bit<8> nextExtHdrType;
}

/* Extension header if E flag is on. */

header gtpv1_extension_hdr_t {
	bit<8> plength; /* length in 4-octet units */
	varbit<128> contents; 
	bit<8> nextExtHdrType;
}


/* GPRS Tunnelling Protocol (GTP) v2 (also known as evolved-GTP or eGTP) */


header gtpv2_ending_t {
	bit<24> sNumber;
	bit<8> reserved;
}

/* TCP */

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* UDP */

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}

/* SCTP */
header sctp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> verifi;
    bit<32> checksum;
}

/* Local metadata */

struct gtp_metadata_t {
	bit<32> teid;
	bit<8> color;
}

struct arp_metadata_t {
    bit<32> dst_ipv4;
    bit<48>  mac_da;
    bit<48>  mac_sa;
    bit<9>   egress_port;
    bit<48>  my_mac;
}

struct routing_metadata_t {
    bit<8> nhgrp;
}


struct my_ingress_metadata_t {
    gtp_metadata_t gtp_metadata;
    arp_metadata_t arp_metadata;
    routing_metadata_t routing_metadata;

    svc_t svc_num;
    ip4Addr_t eNBip;
    macAddr_t eNBmac;
    teid_t    pgwToUE;
}

struct my_ingress_headers_t {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv4_t       inner_ipv4;
    icmp_t       icmp;
    icmp_t	 inner_icmp;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    vlan_t       vlan;
    gtp_common_t gtp_common;
    gtp_teid_t gtp_teid;
    gtpv1_extension_hdr_t gtpv1_extension_hdr;
    gtpv1_optional_t gtpv1_optional;
    gtpv2_ending_t gtpv2_ending;
    udp_t udp;
    udp_t inner_udp;
    udp_t inner_tcp;
    sctp_t sctp;
}

/************************************************************************
************************ D I G E S T  ***********************************
*************************************************************************/

struct mac_learn_digest {
    bit<48> srcAddr;
    bit<8>  ingress_port;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser IngressParser(packet_in        packet,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md) {
                //inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.arp_metadata.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.arp_metadata.dst_ipv4 = hdr.ipv4.dstAddr;
        transition select(hdr.ipv4.protocol) {
            IPPROTO_ICMP : parse_icmp;
            IPPROTO_UDP  : parse_udp;
            IPPROTO_SCTP : parse_sctp;
            default      : accept;
        }
    }

    state parse_sctp {
	    packet.extract(hdr.sctp);
	    transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            GTP_UDP_PORT : parse_gtp;
            default      : accept;    
        }
    }

    state parse_gtp {
        packet.extract(hdr.gtp_common);
        transition select(hdr.gtp_common.version, hdr.gtp_common.tFlag) {
		    (1,0)	: parse_teid;
		    (1,1) : parse_teid;
		    (2,1) : parse_teid;
		    (2,0) : parse_gtpv2;
		    default : accept;
	    }
    }

    state parse_teid {
        packet.extract(hdr.gtp_teid);
        transition parse_inner;
    }
 
    state parse_gtpv2 {
        packet.extract(hdr.gtpv2_ending);
        transition accept;
    }

    state parse_gtpv1optional {
        packet.extract(hdr.gtpv1_optional);
        transition parse_inner;
    }

    state parse_inner {
        packet.extract(hdr.inner_ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

/*
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}
*/

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control Ingress(inout my_ingress_headers_t                       hdr,
                inout my_ingress_metadata_t                      meta,
                  /* Intrinsic */
                  in    ingress_intrinsic_metadata_t               ig_intr_md,
                  in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
                  inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
                  inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md) {
                  //inout standard_metadata_t standard_metadata) {

    action drop() {
        //mark_to_drop(standard_metadata);
        ig_dprsr_md.drop_ctl = 1;
    }
    
    action mac_learn() {
    /*    digest(MAC_LEARN_RECEIVER, { hdr.ethernet.srcAddr, standard_metadata.ingress_port } );*/
    }

    action arp_digest() {
        NoAction(); /*digest(ARP_LEARN_RECEIVER, */
    }

    action arp_reply() {
        hdr.ethernet.dstAddr = hdr.arp_ipv4.sha;
        hdr.ethernet.srcAddr = OWN_MAC;
        
        hdr.arp.oper         = ARP_OPER_REPLY;
        
        hdr.arp_ipv4.tha     = hdr.arp_ipv4.sha;
        hdr.arp_ipv4.tpa     = hdr.arp_ipv4.spa;
        hdr.arp_ipv4.sha     = OWN_MAC;
        hdr.arp_ipv4.spa     = meta.arp_metadata.dst_ipv4;

        //standard_metadata.egress_spec = standard_metadata.ingress_port;
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action send_icmp_reply() {
        bit<48>   tmp_mac;
        bit<32>  tmp_ip;

        tmp_mac              = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp_mac;

        tmp_ip               = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr     = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr     = tmp_ip;

        hdr.icmp.type        = ICMP_ECHO_REPLY;
        hdr.icmp.checksum    = 0; // For now

        //standard_metadata.egress_spec = standard_metadata.ingress_port;
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action forward(bit<9> port) { 
        //standard_metadata.egress_spec = port;
	    ig_tm_md.ucast_egress_port = port;
        hdr.ethernet.srcAddr = OWN_MAC;
    }

    action bcast() {
        ig_tm_md.ucast_egress_port = 100;
        //standard_metadata.egress_spec = 100;
    }

   action gtp_encapsulate(bit<32> teid, bit<32> ip) {
            hdr.inner_ipv4.setValid();
            hdr.inner_ipv4 = hdr.ipv4;
	        //hdr.udp.setValid()) //in the apply statement
	        hdr.gtp_common.setValid();
            hdr.gtp_teid.setValid();
            hdr.udp.srcPort = 58947;
            hdr.udp.dstPort = GTP_UDP_PORT;
            hdr.udp.checksum = 0;
            hdr.udp.plength = hdr.inner_ipv4.totalLen + 16;
            hdr.gtp_teid.teid = teid;
            hdr.gtp_common.version = 1;
            hdr.gtp_common.pFlag = 1;
            hdr.gtp_common.messageType = 255;
            hdr.gtp_common.messageLength = hdr.inner_ipv4.totalLen;
            hdr.ipv4.srcAddr = IP_PGW;
            hdr.ipv4.dstAddr = ip;
            hdr.ipv4.protocol = IPPROTO_UDP;
            hdr.ipv4.ttl = 255;
            hdr.ipv4.totalLen = hdr.udp.plength + 20;
            meta.gtp_metadata.teid = teid;	
    }

    action gtp_decapsulate() {
        hdr.ipv4 = hdr.inner_ipv4;
        meta.gtp_metadata.teid =  hdr.gtp_teid.teid;
        hdr.udp.setInvalid();
        hdr.gtp_common.setInvalid();
        hdr.gtp_teid.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

    action set_nhgrp(bit<8> nhgrp) {
        meta.routing_metadata.nhgrp = nhgrp;
	    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action pkt_send(bit<48> nhmac, bit<9> port) {
        hdr.ethernet.srcAddr = OWN_MAC; // simplified
        hdr.ethernet.dstAddr = nhmac;
        ig_tm_md.ucast_egress_port = port;
        //standard_metadata.egress_spec = port;
    }

    action forward_to_ue( ip4Addr_t eNBip, macAddr_t eNBmac, teid_t pgwToUE ) {
        meta.eNBip = eNBip;
        meta.eNBmac = eNBmac;
        meta.pgwToUE = pgwToUE; /* teid */
    }

	/* Defines the current eNodeB for a UE */
    table ue_at_eNB {
	    key = {
		    hdr.ipv4.dstAddr : lpm;
    	}
	    actions = { drop; forward_to_ue; }
	    size = 1000;
        default_action = drop;
	}
	

	action ue_forward_pgw() {
	    /* Send from ENB -> PGW */
        ig_tm_md.ucast_egress_port = SW_PORT_PGW;
	    //standard_metadata.egress_spec = SW_PORT_PGW;
    }

	action ue_getsvcnum( svc_t svc_num ) {
	    meta.svc_num = svc_num;
    }

	action ue_redirect(ip4Addr_t svcIP, ip4Port_t svcPort, ip4Proto_t svcProto, switchPort_t swPort) {
	    //standard_metadata.egress_spec = SW_PORT_ESP;
	    ig_tm_md.ucast_egress_port = SW_PORT_ESP;
        hdr.ipv4 = hdr.inner_ipv4;
        meta.gtp_metadata.teid =  hdr.gtp_teid.teid;
        hdr.udp.setInvalid();
        hdr.gtp_common.setInvalid();
        hdr.gtp_teid.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

	table ue_svc_match {
	    key = {
		    hdr.inner_ipv4.srcAddr: exact;
		    hdr.inner_ipv4.dstAddr: exact;
		}
        actions = {ue_getsvcnum; ue_forward_pgw; }
        size = 256;
        default_action = ue_forward_pgw;
    }

	table svc_info {
	    key = {
		    meta.svc_num : exact;
		    hdr.inner_ipv4.protocol: exact;
		    //meta.ipv4_port: exact;
        }
        actions = {ue_redirect; ue_forward_pgw; }
        size = 256;
        default_action = ue_forward_pgw;
    }



	
	apply {
        // if it's an s1ap and if we need to clone to cpu port
	    // no else. (current CPU port is 2, the EDGE port)
	    if(hdr.sctp.isValid()) {
		    //clone(CloneType.I2E, 32w250); //in CLI ensure: mirroring_add 250 <cpu_port> 
            ig_tm_md.copy_to_cpu = 1;
            //TODO and add to JSON?
            ig_tm_md.icos_for_copy_to_cpu = 4;
        }

	    /* if pkt from PGW forward to ENB */
	    //if ( standard_metadata.ingress_port == SW_PORT_PGW ) {
		if (ig_intr_md.ingress_port == SW_PORT_PGW) {
            //standard_metadata.egress_spec = SW_PORT_ENB;
            ig_tm_md.ucast_egress_port = SW_PORT_ENB;
       	//} else if ( standard_metadata.ingress_port == SW_PORT_ENB ) {
        } else if ( ig_intr_md.ingress_port == SW_PORT_ENB ) {
		    if ( hdr.gtp_common.isValid() && hdr.inner_ipv4.isValid() ) {

		        if ( ue_svc_match.apply().hit ) {
			        //standard_metadata.egress_spec = SW_PORT_ESP;
			        ig_tm_md.ucast_egress_port = SW_PORT_ESP;
                    hdr.ipv4 = hdr.inner_ipv4;
			        hdr.ethernet.dstAddr = ESP_MAC;

			        hdr.udp.setInvalid();
			        hdr.gtp_common.setInvalid();
			        hdr.gtp_teid.setInvalid();
			        hdr.inner_ipv4.setInvalid();
		        } else {
			        /* came in ENB but not a service packet */
			        // this is redundant, can remove
			        //standard_metadata.egress_spec = SW_PORT_PGW;
		        }
    	    } else {
		        /* came in ENB but not a GTP packet */
		        //standard_metadata.egress_spec = SW_PORT_PGW;
                ig_tm_md.ucast_egress_port = SW_PORT_PGW;
	        }
     	//} else if (standard_metadata.ingress_port == SW_PORT_ESP) {
        } else if (ig_intr_md.ingress_port == SW_PORT_ESP) {
		    if ( hdr.ipv4.isValid()) {
		        if (ue_at_eNB.apply().hit ) {
			        if (hdr.udp.isValid()) {
			            hdr.inner_udp.setValid();
			            hdr.inner_udp = hdr.udp;
			        } else {
			            hdr.udp.setValid();
			        }
			        gtp_encapsulate( meta.pgwToUE, meta.eNBip );
			        hdr.ethernet.dstAddr = meta.eNBmac;
			        //standard_metadata.egress_spec = SW_PORT_ENB;
                    ig_tm_md.ucast_egress_port = SW_PORT_ENB;
		        }
		    } else {
		        drop();
    		}
	    } else {
		    /* Came in from an unknown port */
		    drop();
	    }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out packet,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
 	    packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.sctp);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp_common);
        packet.emit(hdr.gtp_teid);
        packet.emit(hdr.inner_ipv4);
		packet.emit(hdr.inner_icmp);
	    packet.emit(hdr.inner_udp);
		packet.emit(hdr.icmp);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv4_t       inner_ipv4;
    icmp_t       icmp;
    icmp_t	 inner_icmp;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    vlan_t       vlan;
    gtp_common_t gtp_common;
    gtp_teid_t gtp_teid;
    gtpv1_extension_hdr_t gtpv1_extension_hdr;
    gtpv1_optional_t gtpv1_optional;
    gtpv2_ending_t gtpv2_ending;
    udp_t udp;
    udp_t inner_udp;
    udp_t inner_tcp;
    sctp_t sctp;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    gtp_metadata_t gtp_metadata;
    arp_metadata_t arp_metadata;
    routing_metadata_t routing_metadata;

    svc_t svc_num;
    ip4Addr_t eNBip;
    macAddr_t eNBmac;
    teid_t    pgwToUE;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        packet,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        packet.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.arp_metadata.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.arp_metadata.dst_ipv4 = hdr.ipv4.dstAddr;
        transition select(hdr.ipv4.protocol) {
            default      : accept;
        }
    }
}


/*************************************************************************
*************   E G R E S S   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control Egress(   /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md) {
    
    apply {
    }
    
    /*
    Checksum<bit<16>>(HashAlgorithm_t.CRC16) ipv4_checksum;

     apply {
         hdr.ipv4.hdrChecksum = ipv4_checksum.update(
             { hdr.ipv4.version,
             hdr.ipv4.ihl,
             hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr });
	*/
    /*
    update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
            hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm_t.CRC32);
            //HashAlgorithm.csum16);
    */
}



/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control EgressDeparser(packet_out packet,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    Hash<bit<16>>(HashAlgorithm_t.CRC16) ipv4_hash;

    apply {
        hdr.ipv4.hdrChecksum = ipv4_hash.get(
            { hdr.ipv4.version,
             hdr.ipv4.ihl,
             hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr });

        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
 	    packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

/*
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
Ipv4ComputeChecksum(),
MyDeparser()
) main;
*/

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
