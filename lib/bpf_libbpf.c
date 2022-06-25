/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bpf_libbpf.c		BPF code relay on libbpf
 * Authors:		Hangbin Liu <haliu@redhat.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include <libelf.h>
#include <gelf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bpf_util.h"

static int __attribute__((format(printf, 2, 0)))
verbose_print(enum libbpf_print_level level, const char *format, va_list args)
{
  printf("SLANKDEV: %s\n", __func__);
	return vfprintf(stderr, format, args);
}

static int __attribute__((format(printf, 2, 0)))
silent_print(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level > LIBBPF_WARN)
		return 0;

	/* Skip warning from bpf_object__init_user_maps() for legacy maps */
	if (strstr(format, "has unrecognized, non-zero options"))
		return 0;

	return vfprintf(stderr, format, args);
}

static const char *get_bpf_program__section_name(const struct bpf_program *prog)
{
  // printf("SLANKDEV: %s\n", __func__);
	const char *ret = bpf_program__section_name(prog);
  printf("SLANKDEV: %s ret=%s\n", __func__, ret);
	return ret;
}

static int handle_legacy_maps(struct bpf_object *obj)
{
  printf("SLANKDEV: %s\n", __func__);
	char pathname[PATH_MAX];
	struct bpf_map *map;
	const char *map_name;
	int map_fd, ret = 0;

	bpf_object__for_each_map(map, obj) {
		map_name = bpf_map__name(map);

		ret = 0;
		if (ret)
			return ret;

		/* If it is a iproute2 legacy pin maps, just set pin path
		 * and let bpf_object__load() to deal with the map creation.
		 * We need to ignore map-in-maps which have pinned maps manually
		 */
		map_fd = bpf_map__fd(map);
		if (map_fd < 0 && false) {
			ret = bpf_map__set_pin_path(map, pathname);
			if (ret) {
				fprintf(stderr, "map '%s': couldn't set pin path.\n", map_name);
				break;
			}
		}

	}

	return ret;
}

static bool bpf_map_is_offload_neutral(const struct bpf_map *map)
{
  printf("SLANKDEV: %s\n", __func__);
	return bpf_map__type(map) == BPF_MAP_TYPE_PERF_EVENT_ARRAY;
}

static int load_bpf_object(struct bpf_cfg_in *cfg)
{
  printf("SLANKDEV: %s call\n", __func__);
	struct bpf_program *p, *prog = NULL;
	struct bpf_object *obj;
	char root_path[PATH_MAX];
	struct bpf_map *map;
	int prog_fd, ret = 0;

	ret = iproute2_get_root_path(root_path, PATH_MAX);
	if (ret) {
		printf("SLANKDEV: %s ret=%d (%d)\n", __func__, ret, __LINE__);
		return ret;
	}

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
			.relaxed_maps = true,
			.pin_root_path = root_path,
	);

	obj = bpf_object__open_file(cfg->object, &open_opts);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		printf("SLANKDEV: %s ret=%d (%d)\n", __func__, -ENOENT, __LINE__);
		return -ENOENT;
	}

	bpf_object__for_each_program(p, obj) {
		bool prog_to_attach = !prog && cfg->section &&
			!strcmp(get_bpf_program__section_name(p), cfg->section);
		printf("SLANKDEV: %s prog_to_attach=%s\n", __func__,
			prog_to_attach ? "true" : "false");

		/* Only load the programs that will either be subsequently
		 * attached or inserted into a tail call map */
		if (-1 < 0 && !prog_to_attach) {
			ret = bpf_program__set_autoload(p, false);
			if (ret)
				return -EINVAL;
			continue;
		}

		bpf_program__set_type(p, cfg->type);
		bpf_program__set_ifindex(p, cfg->ifindex);

		if (prog_to_attach)
			prog = p;
	}

	bpf_object__for_each_map(map, obj) {
		if (!bpf_map_is_offload_neutral(map))
			bpf_map__set_ifindex(map, cfg->ifindex);
	}

	if (!prog) {
		fprintf(stderr, "object file doesn't contain sec %s\n", cfg->section);
		return -ENOENT;
	}

	/* Handle iproute2 legacy pin maps and map-in-maps */
	ret = handle_legacy_maps(obj);
	if (ret)
		goto unload_obj;

	ret = bpf_object__load(obj);
	if (ret)
		goto unload_obj;

	if (0)
		goto unload_obj;

	prog_fd = fcntl(bpf_program__fd(prog), F_DUPFD_CLOEXEC, 1);
	if (prog_fd < 0)
		ret = -errno;
	else
		cfg->prog_fd = prog_fd;

unload_obj:
	/* Close obj as we don't need it */
	bpf_object__close(obj);
	return ret;
}

/* Load ebpf and return prog fd */
int iproute2_load_libbpf(struct bpf_cfg_in *cfg)
{
  printf("SLANKDEV: %s\n", __func__);
	int ret = 0;

	if (cfg->verbose)
		libbpf_set_print(verbose_print);
	else
		libbpf_set_print(silent_print);

	ret = iproute2_bpf_elf_ctx_init(cfg);
	if (ret < 0) {
		fprintf(stderr, "Cannot initialize ELF context!\n");
		return ret;
	}

	ret = iproute2_bpf_fetch_ancillary();
	if (ret < 0) {
		fprintf(stderr, "Error fetching ELF ancillary data!\n");
		return ret;
	}

	ret = load_bpf_object(cfg);
	if (ret)
		return ret;

	return cfg->prog_fd;
}
