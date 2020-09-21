// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *
 */

#include <ell/ell.h>

#include "timeout.h"

struct timeout_data {
	timeout_func_t func;
	timeout_destroy_func_t destroy;
	unsigned int timeout;
	void *user_data;
};

static void timeout_callback(struct l_timeout *timeout, void *user_data)
{
	struct timeout_data *data = user_data;

	if (data->func)
		data->func(data->user_data);

	l_timeout_modify(timeout, data->timeout);
}

static void timeout_destroy(void *user_data)
{
	struct timeout_data *data = user_data;

	if (data->destroy)
		data->destroy(data->user_data);

	l_free(data);
}

unsigned int timeout_add(unsigned int timeout, timeout_func_t func,
			void *user_data, timeout_destroy_func_t destroy)
{
	struct timeout_data *data;
	uint32_t id;

	data = l_new(struct timeout_data, 1);

	data->func = func;
	data->destroy = destroy;
	data->user_data = user_data;
	data->timeout = timeout;

	id = L_PTR_TO_UINT(l_timeout_create(timeout, timeout_callback,
						user_data, timeout_destroy));
	return id;
}

void timeout_remove(unsigned int id)
{
	l_timeout_remove(L_UINT_TO_PTR(id));
}
