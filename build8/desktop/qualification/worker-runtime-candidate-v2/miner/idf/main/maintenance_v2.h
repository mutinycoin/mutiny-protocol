#ifndef BUILD8_MAINTENANCE_V2_H
#define BUILD8_MAINTENANCE_V2_H
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
/* Initialize once during single-task startup, before radio/tasks. All V2
 * enrollment changes, update transfers/boot settlement and policy rotations
 * share this mutex. An update task holds it through its whole transfer, not
 * merely one flash callback. No interrupt-context use or recursive acquisition. */
int build8_maintenance_v2_init(void);
SemaphoreHandle_t build8_maintenance_v2_guard(void);
int build8_maintenance_v2_owned(void);
#endif
