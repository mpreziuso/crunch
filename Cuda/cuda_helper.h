#define __LDG_PTR "l"
typedef struct __align__(32) uint8
{
        unsigned int s0, s1, s2, s3, s4, s5, s6, s7;
} uint8;

typedef struct __align__(64) uint16
{
        union {
                struct {unsigned int  s0, s1, s2, s3, s4, s5, s6, s7;};
                uint8 lo;
        };
        union {
                struct {unsigned int s8, s9, sa, sb, sc, sd, se, sf;};
                uint8 hi;
        };
} uint16;

typedef struct __align__(128) uint32
{

                uint16 lo,hi;
} uint32;

typedef struct __align__(64) ulonglong2to8
{
        ulonglong2 l0,l1,l2,l3;
} ulonglong2to8;

static __forceinline__ __device__ ulonglong2 operator^ (ulonglong2 a, ulonglong2 b) { return make_ulonglong2(a.x ^ b.x, a.y ^ b.y); }
static __forceinline__ __device__ ulonglong2 operator+ (ulonglong2 a, ulonglong2 b) { return make_ulonglong2(a.x + b.x, a.y + b.y); }


static __inline__ __device__ ulonglong2to8 make_ulonglong2to8(ulonglong2 s0, ulonglong2 s1, ulonglong2 s2, ulonglong2 s3)
{
ulonglong2to8 t; t.l0=s0; t.l1=s1; t.l2=s2; t.l3=s3;
return t;
}

static __forceinline__ __device__
ulonglong2to8 operator^ (const ulonglong2to8 &a, const ulonglong2to8 &b)
{
        return make_ulonglong2to8(a.l0 ^ b.l0, a.l1 ^ b.l1, a.l2 ^ b.l2, a.l3 ^ b.l3);
}

static __forceinline__ __device__
ulonglong2to8 operator+ (const ulonglong2to8 &a, const ulonglong2to8 &b)
{
        return make_ulonglong2to8(a.l0 + b.l0, a.l1 + b.l1, a.l2 + b.l2, a.l3 + b.l3);
}

static __forceinline__ __device__ void operator^= (ulonglong2to8 &a, const ulonglong2to8 &b) { a = a ^ b; }

static __forceinline__ __device__ void operator^= (ulonglong2 &a, const ulonglong2 &b) { a = a ^ b; }


static __inline__ __host__ __device__ uint16 make_uint16(
        unsigned int s0, unsigned int s1, unsigned int s2, unsigned int s3, unsigned int s4, unsigned int s5, unsigned int s6, unsigned int s7,
        unsigned int s8, unsigned int s9, unsigned int sa, unsigned int sb, unsigned int sc, unsigned int sd, unsigned int se, unsigned int sf)
{
        uint16 t; t.s0 = s0; t.s1 = s1; t.s2 = s2; t.s3 = s3; t.s4 = s4; t.s5 = s5; t.s6 = s6; t.s7 = s7;
        t.s8 = s8; t.s9 = s9; t.sa = sa; t.sb = sb; t.sc = sc; t.sd = sd; t.se = se; t.sf = sf;
        return t;
}

static __inline__ __host__ __device__ uint16 make_uint16(const uint8 &a, const uint8 &b)
{
        uint16 t; t.lo=a; t.hi=b; return t;
}

static __inline__ __host__ __device__ uint32 make_uint32(const uint16 &a, const uint16 &b)
{
        uint32 t; t.lo = a; t.hi = b; return t;
}

static __forceinline__ __device__  __host__ uint16 operator+ (const uint16 &a, const uint16 &b) {
        return make_uint16(a.s0 + b.s0, a.s1 + b.s1, a.s2 + b.s2, a.s3 + b.s3, a.s4 + b.s4, a.s5 + b.s5, a.s6 + b.s6, a.s7 + b.s7,
                a.s8 + b.s8, a.s9 + b.s9, a.sa + b.sa, a.sb + b.sb, a.sc + b.sc, a.sd + b.sd, a.se + b.se, a.sf + b.sf);
}

static __forceinline__ __device__ __host__ uint16 operator^ (const uint16 &a, const uint16 &b) {
        return make_uint16(a.s0 ^ b.s0, a.s1 ^ b.s1, a.s2 ^ b.s2, a.s3 ^ b.s3, a.s4 ^ b.s4, a.s5 ^ b.s5, a.s6 ^ b.s6, a.s7 ^ b.s7,
                a.s8 ^ b.s8, a.s9 ^ b.s9, a.sa ^ b.sa, a.sb ^ b.sb, a.sc ^ b.sc, a.sd ^ b.sd, a.se ^ b.se, a.sf ^ b.sf);
}

static __forceinline__ __device__  __host__ void operator^= (uint16 &a, const uint16 &b) { a = a ^ b; }

static __forceinline__ __device__  uint32 operator^ (const uint32 &a, const uint32 &b) {
        return make_uint32(a.lo ^ b.lo, a.hi ^ b.hi);
}

static __forceinline__ __device__  __host__ void operator+= (uint16 &a, const uint16 &b) { a = a + b; }


static __device__ __inline__ ulonglong2 __ldg2(const ulonglong2 *ptr)
{
        ulonglong2 ret;
        asm("ld.global.nc.v2.u64 {%0,%1}, [%2];"  : "=l"(ret.x), "=l"(ret.y) : __LDG_PTR(ptr));
return ret;
}

__device__ __forceinline__ uint2 vectorize(uint64_t x)
{
	uint2 result;
	asm("mov.b64 {%0,%1},%2; \n\t"
		: "=r"(result.x), "=r"(result.y) : "l"(x));
	return result;
}

static __device__ __forceinline__ void madd4long2(ulonglong2 &a, ulonglong2 b)
 {
	
		asm("{\n\t"
		 ".reg .u32 a0,a1,a2,a3,b0,b1,b2,b3;\n\t"
		 "mov.b64 {a0,a1}, %0;\n\t"
		 "mov.b64 {a2,a3}, %1;\n\t"
		 "mov.b64 {b0,b1}, %2;\n\t"
		 "mov.b64 {b2,b3}, %3;\n\t"
		 "mad.lo.cc.u32        b0,a0,a1,b0;  \n\t"
		 "madc.hi.u32          b1,a0,a1,b1;  \n\t"
		 "mad.lo.cc.u32        b2,a2,a3,b2;  \n\t"
		 "madc.hi.u32          b3,a2,a3,b3;  \n\t"
		 "mov.b64 %0, {b0,b1};\n\t"
		 "mov.b64 %1, {b2,b3};\n\t"
		 "}\n\t"
		 : "+l"(a.x), "+l"(a.y) : "l"(b.x), "l"(b.y));
	
}
