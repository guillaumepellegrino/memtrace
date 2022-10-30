#ifndef EVLP_H
#define EVLP_H

#include "types.h"

evlp_t *evlp_create();
void evlp_destroy(evlp_t *evlp);
bool evlp_add_handler(evlp_t *evlp, evlp_handler_t *handler, int fd, int events);
bool evlp_main(evlp_t *evlp);
void evlp_stop(evlp_t *evlp);

#endif
