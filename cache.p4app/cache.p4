/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  IP_PROT_UDP  = 0x11;
const bit<16> UDP_PORT     = 1234;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header reqHdr_t {
    bit<8>  key;
}

header resHdr_t {
    bit<8>  key;
    bit<8>  is_valid;
    bit<32> value;
}

struct metadata { }

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    udp_t         udp;
    reqHdr_t	  reqHdr;
    resHdr_t	  resHdr;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROT_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort, hdr.udp.srcPort) {
            (UDP_PORT,_): parse_reqHdr;
	    (_,UDP_PORT): parse_resHdr; 	
            default: accept;
        }
    }

    state parse_reqHdr {
        packet.extract(hdr.reqHdr);
        transition accept;
    }

    state parse_resHdr {
	packet.extract(hdr.resHdr);
	transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
	
	register<bit<32>>(256) cacheReg;

	action cache_response(bit<8> key, bit<8> is_valid, bit<32> value) {
		hdr.reqHdr.setInvalid(); // Sets the request header invalid (so that it does not go to IP forward)
		hdr.resHdr.setValid(); // Sets the response header valid so that we can send our cache response

		hdr.resHdr.key = key; // Setting the response header key to the key found in P4 table
		hdr.resHdr.is_valid = is_valid; 
		hdr.resHdr.value = value; 

		hdr.ipv4.totalLen = 34;
		hdr.udp.length_  = 14;

        macAddr_t tmpDstMac = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmpDstMac;

        ip4Addr_t tmpDstIp = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = tmpDstIp;

        bit<16> tmpDstPort = hdr.udp.dstPort;
        hdr.udp.dstPort = hdr.udp.srcPort;
        hdr.udp.srcPort = tmpDstPort;
        hdr.udp.checksum = 0;

		standard_metadata.egress_spec = standard_metadata.ingress_port;
	}

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

	action drop() {
        mark_to_drop(standard_metadata);
    }

    table ipv4_lpm {
		key = {
			hdr.ipv4.dstAddr: lpm;
		}
		actions = {
			ipv4_forward;
			drop;
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}
	
    table reqHdr_exact {
		key = {
			hdr.reqHdr.key: exact;
		}
		actions = {
			cache_response;
			NoAction;
		}
		size = 8;
		default_action = NoAction;
	}

    apply {
        
        if (hdr.reqHdr.isValid()) {
            reqHdr_exact.apply();
			if (!hdr.resHdr.isValid()) {
				
				hdr.resHdr.setValid(); // Sets the response header valid so that we can send our cache response
				cacheReg.read(hdr.resHdr.value,(bit<32>)hdr.reqHdr.key);
				if (hdr.resHdr.value > 0) {
							hdr.resHdr.key = hdr.reqHdr.key; // Setting the response header key to the key found in P4 table
							hdr.resHdr.is_valid = 1; 

						    hdr.reqHdr.setInvalid(); // Sets the request header invalid (so that it does not go to IP forward)
							hdr.ipv4.totalLen = 34;
							hdr.udp.length_  = 14;

							macAddr_t tmpDstMac = hdr.ethernet.dstAddr;
							hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
							hdr.ethernet.srcAddr = tmpDstMac;

							ip4Addr_t tmpDstIp = hdr.ipv4.dstAddr;
							hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
							hdr.ipv4.srcAddr = tmpDstIp;

							bit<16> tmpDstPort = hdr.udp.dstPort;
							hdr.udp.dstPort = hdr.udp.srcPort;
							hdr.udp.srcPort = tmpDstPort;
							hdr.udp.checksum = 0;

							standard_metadata.egress_spec = standard_metadata.ingress_port;					
					} else {
						ipv4_lpm.apply();	
						}
				}
		    } else {
			if (hdr.resHdr.isValid()) {
				if (hdr.resHdr.is_valid == 1) {
					cacheReg.write((bit<32>)hdr.resHdr.key, hdr.resHdr.value);
				}
				ipv4_lpm.apply();
			}
		}
	}
}
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
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
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
		packet.emit(hdr.udp);
		packet.emit(hdr.reqHdr);
		packet.emit(hdr.resHdr);
		
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
