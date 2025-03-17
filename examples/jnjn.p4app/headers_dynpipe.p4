
#ifndef _HEADERS_
    #define _HEADERS_

// typedef bit<0> unused_t;
typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> ip4Addr_t;


/********************************************
*
* Constants
*
********************************************/

/* Ethernet constants */
const ether_type_t ETHERTYPE_ROCE = 16w0x8915;
const ether_type_t ETHERTYPE_RQTRP = 16w0x8FFF;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;


/********************************************
*
* Ethernet Header
*
********************************************/

header ethernet_h {
    mac_addr_t  dst_addr;
    mac_addr_t  src_addr;
    bit<16>     ether_type;
}

/********************************************
*
* QTRP headers based on the CIDR NetAccel paper
*
********************************************/

/* Generic header considering a 6-field table with different types */
header qtrp_h {
    bit<32>     fld01_uint32; 
    bit<32>     fld02_uint32;
    bit<32>     fld03_uint32;
    bit<16>     fld04_uint16;   // Hash key for max 65k table size in tofino-2
    bit<32>     fld05_uint32;
    bit<32>     fld06_uint32;   // former fld06_date field, now used for group key (moved to field 10)
    bit<16>     fld07_uint16;   /* Field 7 build/probe flag */
    bit<16>     fld08_uint16;   /* Field 8 group hash */
    bit<16>     fld09_uint16;   /* Field 9 choose operation */
    bit<16>     fld10_uint16;   /* Field 10 groupkey */    
    bit<16>     fld11_uint16;   /* Query id */ 
}

struct headers {
    ethernet_h  ethernet;
    qtrp_h      qtrp;
}

struct metadata {}

#endif /* _HEADERS_ */
