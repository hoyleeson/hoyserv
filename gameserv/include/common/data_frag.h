#ifndef _COMMON_DATA_FRAG_
#define _COMMON_DATA_FRAG_

#include <stdint.h>

#define DEFRAG_TIMEOUT      (10 * NSEC2SEC)
/* Reference */
typedef struct _frag {
    uint16_t id;
    uint32_t frag:1;
    uint32_t mf:1;
    uint32_t frag_ofs:20;    /* max data len: 1MB */
    uint32_t datalen:10;     /* packet len */
    uint8_t data[0];
} frag_t;

typedef struct _data_vec {
    int seq;
    int mf;
    int ofs;
    void *data;
    int len;
} data_vec_t;


typedef struct data_frags data_frags_t;

data_frags_t *data_frag_init(int fraglen, 
        void (*input)(void *, void *, int),
        void (*output)(void *, data_vec_t *v),
        void (*free_pkt)(void *opaque, void *frag_pkt),
        void *opaque);

void data_frag_release(data_frags_t *frags);

int data_frag(data_frags_t *frags, void *data, int len);
int data_defrag(data_frags_t *frags, data_vec_t *v, void *frag_pkt);

#endif

