// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#include "headers_dynpipe.p4"
#include "hashing_keys.p4"

typedef bit<9> Port_t;

/*
 * This is a custom header for the selection. We'll use
 * etherType 0x1234 for it (see parser)
 */
const bit<16> P4SELECT_ETYPE = 0x1234;
const bit<16> P4SELECT_JOIN  = 0x0001;   // '=' with padding
const bit<16> P4SELECT_GBY   = 0x0002;   // '!='
const bit<16> P4SELECT_JNGBY = 0x0003;   // '>' with padding

action nop(){}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            P4SELECT_ETYPE: parse_qtrp;
            default: accept;
        }
    }

    state parse_qtrp{ 
        packet.extract(hdr.qtrp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


control Join(
    inout qtrp_h qtrp,
    inout bit<3> drop_ctl)
    (bit<32> table_size)

{
    join_hash() join_key;
    action drop() {
        drop_ctl = 1;
    }

    /************************ hash tables ************/
    /* Define a struct to wrap the register */
    struct Register32 {
        register<bit<32>>(table_size) hash_table;
    };

    Register32 hash_table_1;
    Register32 hash_table_2;
    Register32 hash_table_3;
    Register32 hash_table_4;
    // /* bit<32> data and bit<16> register index */
    // register<bit<32>>(table_size) hash_table_1;
    // register<bit<32>>(table_size) hash_table_2;
    // register<bit<32>>(table_size) hash_table_3;
    // register<bit<32>>(table_size) hash_table_4;
    action build(Register32 hash_table, bit<32> idx, inout bit<1> success) {
        bit<32> stored_val;
        hash_table.read(stored_val, idx);
        if (stored_val == 0) {
            hash_table.write(idx, qtrp.fld01_uint32);
            success = 1;
        } else {
            success = 0;
        }
    }

     /* Helper function to search for a match */
    action probe(Register32 hash_table, bit<32> idx, out bit<32> result, inout bit<1> match) {
        hash_table.read(result, idx);
        if (result == qtrp.fld01_uint32) {
            match = 1;
        } else {
            match = 0;
        }
    }

    table tb_drop {
        actions = { 
            nop; 
        }
        default_action = nop();
        size = 1;
    }

    apply {
        if (qtrp.isValid() && drop_ctl != 1) {
            join_key.apply(qtrp, qtrp.fld04_uint16);  // get the hash of field 1, store the hash key in fld04_uint16
            bit<32> lookup_result = 0;
            bit<32> idx = qtrp.fld04_uint16;
            bit<1> success = 0;
            bit<1> match_found = 0;

            /* Build phase: Insert only once */
            if (qtrp.fld07_uint16 == 1) {
                if (qtrp.fld05_uint32 == 0) { 
                    build(hash_table_1, idx, success);
                    if (success == 0) build(hash_table_2, idx, success);
                    if (success == 0) build(hash_table_3, idx, success);
                    if (success == 0) build(hash_table_4, idx, success);
                }
            } else {  // it is a probe packet
                /* Probe phase: Search until we find a match */
                probe(hash_table_1, idx, lookup_result, match_found);
                if (match_found == 0) probe(hash_table_2, idx, lookup_result, match_found);
                if (match_found == 0) probe(hash_table_3, idx, lookup_result, match_found);
                if (match_found == 0) probe(hash_table_4, idx, lookup_result, match_found);
                
                qtrp.fld05_uint32 = lookup_result;
                if (match_found == 0) {
                    drop_ctl = 1;
                    tb_drop.apply();
                }
            }
            qtrp.fld07_uint16 = qtrp.fld07_uint16 - 1; // decrement the hop count by 1 
        }
    }
}



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action hit(Port_t port) {
        standard_metadata.egress_spec = port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table forward {
        key = {
            hdr.ethernet.dst_addr: exact;
        }

        actions = {
            hit;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    Join(TABLE_SIZE) join1;

    apply {
        forward.apply();
        if (hdr.qtrp.isValid()) {
            join1.apply(hdr.qtrp, standard_metadata.drop);
        }
    }
  

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

   action miss(bit<3> drop){
        mark_to_drop(standard_metadata);
   }

   table drop_table {
        actions = {
            nop;
            miss;
        }

        const default_action = nop();
        size=1024;
   }

   Join(TABLE_SIZE) join2;

   apply{
        drop_table.apply();
        if (hdr.qtrp.isValid()) {
            join2.apply(hdr.qtrp, standard_metadata.drop);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply{}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.qtrp);
        
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;