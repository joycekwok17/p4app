#define TABLE_SIZE 100
#define HASH_SIZE 32  
#define HASH_ALG HashAlgorithm.crc16

// ---------------------------------------------------------------------------
// Calculating Hash
// ---------------------------------------------------------------------------
// control join_hash(  
//     //in  header_t   hdr,
//     in qtrp_h      qtrp,
//     out bit<HASH_SIZE>    sel_hash)
// {
//     hash<bit<HASH_SIZE>>(HASH_ALG) key_hash;
    
//     apply {
//         sel_hash = key_hash.get((bit<HASH_SIZE>)qtrp.fld01_uint32);  //  get the hash of field 1, store the hash key in sel_hash acturally is fld04_uint16
//     } 
// }


control join_hash(in qtrp_h qtrp, out bit<HASH_SIZE> sel_hash){
    bit<32> nbase=0;
    bit<64> ncount=4294967296*2;
    apply {
        hash(sel_hash, HASH_ALG, nbase, {qtrp.fld01_uint32}, ncount);
    }
}
