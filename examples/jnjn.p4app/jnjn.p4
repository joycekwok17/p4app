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
        transition select(hdr.ethernet.etherType) {
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
    table tb_drop {
    
        actions = {
            drop;
        }
        default_action = drop();
        size = 1;
    }

    /************************ hash tables ************/
    /* bit<32> data and bit<16> register index */
    #define CREATE_HASH_TABLE(N)                                          \
        register<bit<32>>(table_size) hash_table_##N;                     \
                                                                        \
        action build_##N(bit<32> index, bit<32> store_value) {                  \
            bit<32> register_value;                                        \
            hash_table_##N.read(current_value, index);                    \
            if (current_value == 0) {                                     \
                hash_table_##N.write(index, store_value);                       \
            }                                                             \
        }                                                                 \
                                                                        \
        action probe_##N(bit<32> index, out bit<32> result) {             \
            hash_table_##N.read(result, index);                           \
        }



    CREATE_HASH_TABLE(1)
    CREATE_HASH_TABLE(2)
    CREATE_HASH_TABLE(3)
    CREATE_HASH_TABLE(4)

    apply {
        if(qtrp.isValid() && (drop_ctl != 1)) {
            @atomic {
                join_key.apply(qtrp, qtrp.fld04_uint16);                                                             

                #define CREATE_JOIN_LOGIC(N)                                      \
                    if(qtrp.fld07_uint16 == 1){                                       \
                        if(qtrp.fld05_uint32 == 0){                                   \
                            qtrp.fld05_uint32 = build_##N.execute(qtrp.fld04_uint16, qtrp.fld01_uint32); \
                        }                                                             \
                    }else{                                                            \
                        if(qtrp.fld05_uint32 != qtrp.fld01_uint32){                   \
                            qtrp.fld05_uint32 = probe_##N.execute(qtrp.fld04_uint16); \
                        }                                                             \
                    }  

                CREATE_JOIN_LOGIC(1)
                CREATE_JOIN_LOGIC(2)
                CREATE_JOIN_LOGIC(3)
                CREATE_JOIN_LOGIC(4)

              /* key not found in probe */
                if(qtrp.fld05_uint32 != qtrp.fld01_uint32){
                    tb_drop.apply();
                }else if(qtrp.fld07_uint16 == 1){
                    tb_drop.apply();
                }
                qtrp.fld07_uint16 = qtrp.fld07_uint16 - 1;


            } // @atomic hint
        } // Packet validation 
    } // Apply


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