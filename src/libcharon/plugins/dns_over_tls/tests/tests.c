/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include <test_runner.h>

#include <signal.h>

#include <daemon.h>

#define TEST_SUITE(x) test_suite_t *x(void);
#include "tests.h"
#undef TEST_SUITE

static test_configuration_t tests[] = {
#define TEST_SUITE(x) { .suite = x, },
#include "tests.h"
	{ .suite = NULL, }
};

static bool test_runner_init(bool init)
{
	if (init)
	{
		char *plugins;

		signal(SIGPIPE, SIG_IGN);
		if (!libcharon_init())
		{
			return FALSE;
		}
		plugins = getenv("TESTS_PLUGINS") ?:
					lib->settings->get_str(lib->settings, "tests.load", PLUGINS);
		plugin_loader_add_plugindirs(PLUGINDIR, plugins);
		if (!lib->plugins->load(lib->plugins, plugins))
		{
			libcharon_deinit();
			return FALSE;
		}
		return TRUE;
	}
	lib->credmgr->flush_cache(lib->credmgr, CERT_ANY);
	libcharon_deinit();
	return TRUE;
}

int main(int argc, char *argv[])
{
	return test_runner_run("dns-over-tls", tests, test_runner_init);
}
