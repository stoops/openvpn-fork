
struct multi_address
{
    int indx, cons, stat;
    char lans[64];
    char wans[64];
    char usrs[64];
    time_t last;
    in_addr_t ladr[MAX_THREADS];
};

struct multi_info
{
    int maxt, maxc;
    int *indx;
    struct ifconfig_pool *pool;
    pthread_mutex_t *lock;
    struct multi_address *addr;
};

struct multi_pointer
{
    int h, n, x, z;
    int *i;
    struct context *c;
    struct multi_context **m;
    struct multi_context *p;
    struct multi_address *a;
    pthread_mutex_t *l;
};

struct multi_args
{
    int i, n;
    struct context *c;
    struct multi_pointer *p;
};
