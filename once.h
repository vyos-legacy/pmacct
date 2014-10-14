#if defined __PMACCTD_C || defined __NFACCTD_C 
#define EXT 
#else
#define EXT extern
#endif

EXT u_int32_t NBO_One;
EXT int PdataSz, ChBufHdrSz, CharPtrSz;
EXT int NfHdrV5Sz, NfHdrV1Sz;

#undef EXT
