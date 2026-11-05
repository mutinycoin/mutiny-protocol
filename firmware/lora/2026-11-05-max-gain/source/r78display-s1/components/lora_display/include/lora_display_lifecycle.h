/* Cross-task publication only; no GPIO, RTOS, authority or work-policy API. */
#ifndef MUTINY_LORA_DISPLAY_LIFECYCLE_H
#define MUTINY_LORA_DISPLAY_LIFECYCLE_H
#include <stdbool.h>
#include <stdatomic.h>
#ifdef ESP_PLATFORM
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "display gate requires lock-free bool");
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "display state requires lock-free pointer");
#endif
typedef struct {
    atomic_bool accepting;
    _Atomic(const char *) state;
} lora_display_lifecycle_t;
#define LORA_DISPLAY_LIFECYCLE_INITIALIZER {false, "disabled"}
static inline void lora_display_accept(lora_display_lifecycle_t *v, bool on)
{ atomic_store_explicit(&v->accepting, on, memory_order_release); }
static inline bool lora_display_accepting(const lora_display_lifecycle_t *v)
{ return atomic_load_explicit(&v->accepting, memory_order_acquire); }
/* State strings must have static lifetime. This is not an atomic pair snapshot. */
static inline void lora_display_set_state(lora_display_lifecycle_t *v, const char *s)
{ atomic_store_explicit(&v->state, s, memory_order_release); }
static inline const char *lora_display_get_state(const lora_display_lifecycle_t *v)
{ return atomic_load_explicit(&v->state, memory_order_acquire); }
#endif
