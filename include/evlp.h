/*
 * Copyright (C) 2022 Guillaume Pellegrino
 * This file is part of memtrace <https://github.com/guillaumepellegrino/memtrace>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef EVLP_H
#define EVLP_H

#include "types.h"

evlp_t *evlp_create();
void evlp_destroy(evlp_t *evlp);
bool evlp_add_handler(evlp_t *evlp, evlp_handler_t *handler, int fd, int events);
void evlp_remove_handler(evlp_t *evlp, int fd);
bool evlp_main(evlp_t *evlp);
void evlp_stop(evlp_t *evlp);
void evlp_exit_onsignal();
bool evlp_stopped();
void evlp_block_signals(evlp_t *evlp, bool sigblocked);

#endif
