/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include <test_runner.h>

#define TEST_SUITE(x) test_suite_t *x(void);
#include "tests.h"
#undef TEST_SUITE

static test_configuration_t tests[] = {
#define TEST_SUITE(x) { .suite = x, },
#include "tests.h"
	{ .suite = NULL, }
};

int main(int argc, char *argv[])
{
	return test_runner_run("kernel-libipsec-socks", tests, NULL);
}
