#if defined(_WIN32)
#include <windows.h>
#include <tbs.h>
/* Read-only TPM2_GetRandom. No key, NV, provisioning or physical-presence API. */
int build8_wallet_tpm_open(void **out) {
    TPM_DEVICE_INFO info = {0};
    TBS_CONTEXT_PARAMS2 params = {0};
    TBS_HCONTEXT context = NULL;
    TBS_RESULT result;
    *out = NULL;
    result = Tbsi_GetDeviceInfo(sizeof(info), &info);
    if (result == TBS_E_TPM_NOT_FOUND) return 0;
    if (result != TBS_SUCCESS || info.structVersion != 1 ||
        info.tpmVersion != TPM_VERSION_20 ||
        info.tpmInterfaceType == TPM_IFTYPE_EMULATOR) return -1;
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;
    result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &context);
    if (result != TBS_SUCCESS) return -1;
    *out = context;
    return 1;
}
int build8_wallet_tpm_random(void *context, unsigned count,
                           unsigned char *out, unsigned *length) {
    unsigned char command[12] = {0x80,1,0,0,0,12,0,0,1,0x7b,0,0};
    if (!context || count == 0 || count > 32 || *length != 44) return 0;
    command[11] = (unsigned char)count;
    return Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL, command, sizeof(command), out, length) == TBS_SUCCESS;
}
void build8_wallet_tpm_close(void *context) {
    if (context) Tbsip_Context_Close(context);
}
#endif
