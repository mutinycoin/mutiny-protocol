#pragma once
#include "FreeRTOS.h"
#define pdTRUE 1
SemaphoreHandle_t xSemaphoreCreateMutex(void);int xSemaphoreTake(SemaphoreHandle_t,unsigned);int xSemaphoreGive(SemaphoreHandle_t);
