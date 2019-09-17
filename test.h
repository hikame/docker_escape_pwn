// struct test_stc {    // size is 320!
// 	uint8_t nr_frags;	// unsigned char
// 	uint8_t tx_flags;	// __u8
// 	uint16_t gso_size;	// unsigned short
// 	uint16_t gso_segs;	// unsigned short
// 	uint16_t gso_type;	// unsigned short
// 	uint64_t frag_list;	// struct sk_buff *
// 	uint64_t hwtstamps;	// struct skb_shared_hwtstamps
// 	uint32_t tskey;		// u32
// 	uint32_t ip6_frag_id;	// __be32
// 	uint32_t dataref;	// atomic_t
// 	uint64_t destructor_arg; // void *   
// 	uint8_t frags[16][17];	// skb_frag_t frags[MAX_SKB_FRAGS];
// };

void test(){
    // struct test_stc ts;
    // printf("%lu.\n", ((long)&ts.destructor_arg) - (long)(&ts));
    // exit(-1);
}