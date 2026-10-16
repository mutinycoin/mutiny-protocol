#include <fenv.h>
#if defined(__x86_64__) || defined(_M_X64)
#include <xmmintrin.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
int build8_crypto_windows_random(unsigned char *out, size_t length) {
    if (length > UINT32_MAX) return 0;
    return BCryptGenRandom(NULL, out, (ULONG)length,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}
#elif defined(__linux__)
#include <sys/prctl.h>
#include <sys/resource.h>
#endif
/* Process-local crash reporting protection, no registry/OS-policy mutation. */
int build8_crypto_custody_process_ready(void){
#if defined(_WIN32)
    unsigned mode=GetErrorMode();
    SetErrorMode(mode|SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    return (GetErrorMode()&SEM_NOGPFAULTERRORBOX)!=0;
#elif defined(__linux__)
    struct rlimit limit={0,0};
    return setrlimit(RLIMIT_CORE,&limit)==0&&prctl(PR_SET_DUMPABLE,0,0,0,0)==0;
#else
    return 0;
#endif
}
/* Native FN-DSA requires the qualified IEEE-754 environment, not merely the
 * language runtime's rounding setting. SSE rounding can differ from x87; DAZ,
 * FTZ and unmasked exceptions must not silently change/fault private arithmetic.
 * Sticky exception status is deliberately ignored (ordinary prior arithmetic
 * may set inexact). Unsupported signing targets require explicit qualification.
 */
int build8_crypto_rounding_ready(void){
    if(fegetround()!=FE_TONEAREST)return 0;
#if defined(__x86_64__) || defined(_M_X64)
    unsigned csr=_mm_getcsr();
    return (csr & (0x6000u|0x8000u|0x0040u))==0
        && (csr & 0x1f80u)==0x1f80u;
#else
    return 0;
#endif
}
/* Used only by the qualification test executable to test fail-closed behavior. */
#ifdef BUILD8_QUALIFICATION
int build8_crypto_test_rounding_down(void){return fesetround(FE_DOWNWARD);}
int build8_crypto_test_rounding_restore(void){return fesetround(FE_TONEAREST);}
#if defined(__x86_64__) || defined(_M_X64)
unsigned build8_crypto_test_mxcsr_get(void){return _mm_getcsr();}
void build8_crypto_test_mxcsr_set(unsigned value){_mm_setcsr(value);}
#endif
#endif
