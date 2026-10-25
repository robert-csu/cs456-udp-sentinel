#include <stdio.h>
#include "protocol.h"


int main(void){
    if (PKT_PORT <= 0 || PKT_PORT > 65535 ||
    HEARTBEAT_PORT <= 0 || HEARTBEAT_PORT > 65535 ||
    T_MS <= 0 || MAX_MISSED_HEARTBEAT <= 0) {
        fprintf(stderr, "protocol.h constants invalid\n");
        return 1;
    }
    return 0;
}