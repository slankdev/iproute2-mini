/*
 * bpf.c	BPF common code
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Daniel Borkmann <daniel@iogearbox.net>
 *		Jiri Pirko <jiri@resnulli.us>
 *		Alexei Starovoitov <ast@kernel.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <limits.h>
#include <assert.h>

#ifdef HAVE_ELF
#include <libelf.h>
#include <gelf.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/resource.h>

#include <arpa/inet.h>

#include "utils.h"
#include "json_print.h"

#include "bpf_util.h"
#include "bpf_elf.h"
#include "bpf_scm.h"

struct bpf_prog_meta {
	const char *type;
	const char *subdir;
	const char *section;
	bool may_uds_export;
};

static const enum bpf_prog_type __bpf_types[] = {
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
};

static const struct bpf_prog_meta __bpf_prog_meta[] = {
	[BPF_PROG_TYPE_SCHED_CLS] = {
		.type		= "cls",
		.subdir		= "tc",
		.section	= ELF_SECTION_CLASSIFIER,
		.may_uds_export	= true,
	},
	[BPF_PROG_TYPE_SCHED_ACT] = {
		.type		= "act",
		.subdir		= "tc",
		.section	= ELF_SECTION_ACTION,
		.may_uds_export	= true,
	},
	[BPF_PROG_TYPE_XDP] = {
		.type		= "xdp",
		.subdir		= "xdp",
		.section	= ELF_SECTION_PROG,
	},
	[BPF_PROG_TYPE_LWT_IN] = {
		.type		= "lwt_in",
		.subdir		= "ip",
		.section	= ELF_SECTION_PROG,
	},
	[BPF_PROG_TYPE_LWT_OUT] = {
		.type		= "lwt_out",
		.subdir		= "ip",
		.section	= ELF_SECTION_PROG,
	},
	[BPF_PROG_TYPE_LWT_XMIT] = {
		.type		= "lwt_xmit",
		.subdir		= "ip",
		.section	= ELF_SECTION_PROG,
	},
	[BPF_PROG_TYPE_LWT_SEG6LOCAL] = {
		.type		= "lwt_seg6local",
		.subdir		= "ip",
		.section	= ELF_SECTION_PROG,
	},
};

static const char *bpf_prog_to_subdir(enum bpf_prog_type type)
{
	printf("SLANKDEV: %s\n", __func__);
	assert(type < ARRAY_SIZE(__bpf_prog_meta) &&
	       __bpf_prog_meta[type].subdir);
	return __bpf_prog_meta[type].subdir;
}

const char *bpf_prog_to_default_section(enum bpf_prog_type type)
{
	printf("SLANKDEV: %s\n", __func__);
	assert(type < ARRAY_SIZE(__bpf_prog_meta) &&
	       __bpf_prog_meta[type].section);
	return __bpf_prog_meta[type].section;
}

static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
	printf("SLANKDEV: %s\n", __func__);
	return (__u64)(unsigned long)ptr;
}

static int bpf_map_update(int fd, const void *key, const void *value,
			  uint64_t flags)
{
	printf("SLANKDEV: %s\n", __func__);
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = bpf_ptr_to_u64(key);
	attr.value = bpf_ptr_to_u64(value);
	attr.flags = flags;

	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_prog_fd_by_id(uint32_t id)
{
	printf("SLANKDEV: %s\n", __func__);
	union bpf_attr attr = {};

	attr.prog_id = id;

	return bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
}

static int bpf_prog_info_by_fd(int fd, struct bpf_prog_info *info,
			       uint32_t *info_len)
{
	printf("SLANKDEV: %s\n", __func__);
	union bpf_attr attr = {};
	int ret;

	attr.info.bpf_fd = fd;
	attr.info.info = bpf_ptr_to_u64(info);
	attr.info.info_len = *info_len;

	*info_len = 0;
	ret = bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
	if (!ret)
		*info_len = attr.info.info_len;

	return ret;
}

int bpf_dump_prog_info(FILE *f, uint32_t id)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_prog_info info = {};
	uint32_t len = sizeof(info);
	int fd, ret, dump_ok = 0;
	SPRINT_BUF(tmp);

	open_json_object("prog");
	print_uint(PRINT_ANY, "id", "id %u ", id);

	fd = bpf_prog_fd_by_id(id);
	if (fd < 0)
		goto out;

	ret = bpf_prog_info_by_fd(fd, &info, &len);
	if (!ret && len) {
		int jited = !!info.jited_prog_len;

		print_string(PRINT_ANY, "name", "name %s ", info.name);
		print_string(PRINT_ANY, "tag", "tag %s ",
			     hexstring_n2a(info.tag, sizeof(info.tag),
					   tmp, sizeof(tmp)));
		print_uint(PRINT_JSON, "jited", NULL, jited);
		if (jited && !is_json_context())
			fprintf(f, "jited ");

		if (show_details) {
			if (info.load_time) {
				/* ns since boottime */
				print_lluint(PRINT_ANY, "load_time",
					     "load_time %llu ", info.load_time);

				print_luint(PRINT_ANY, "created_by_uid",
					    "created_by_uid %lu ",
					    info.created_by_uid);
			}

			if (info.btf_id)
				print_luint(PRINT_ANY, "btf_id", "btf_id %lu ",
					    info.btf_id);
		}

		dump_ok = 1;
	}

	close(fd);
out:
	close_json_object();
	return dump_ok;
}

static int bpf_parse_string(char *arg, bool from_file, __u16 *bpf_len,
			    char **bpf_string, bool *need_release,
			    const char separator)
{
	printf("SLANKDEV: %s\n", __func__);
	char sp;

	if (from_file) {
		size_t tmp_len, op_len = sizeof("65535 255 255 4294967295,");
		char *tmp_string, *pos, c_prev = ' ';
		FILE *fp;
		int c;

		tmp_len = sizeof("4096,") + BPF_MAXINSNS * op_len;
		tmp_string = pos = calloc(1, tmp_len);
		if (tmp_string == NULL)
			return -ENOMEM;

		fp = fopen(arg, "r");
		if (fp == NULL) {
			perror("Cannot fopen");
			free(tmp_string);
			return -ENOENT;
		}

		while ((c = fgetc(fp)) != EOF) {
			switch (c) {
			case '\n':
				if (c_prev != ',')
					*(pos++) = ',';
				c_prev = ',';
				break;
			case ' ':
			case '\t':
				if (c_prev != ' ')
					*(pos++) = c;
				c_prev = ' ';
				break;
			default:
				*(pos++) = c;
				c_prev = c;
			}
			if (pos - tmp_string == tmp_len)
				break;
		}

		if (!feof(fp)) {
			free(tmp_string);
			fclose(fp);
			return -E2BIG;
		}

		fclose(fp);
		*pos = 0;

		*need_release = true;
		*bpf_string = tmp_string;
	} else {
		*need_release = false;
		*bpf_string = arg;
	}

	if (sscanf(*bpf_string, "%hu%c", bpf_len, &sp) != 2 ||
	    sp != separator) {
		if (*need_release)
			free(*bpf_string);
		return -EINVAL;
	}

	return 0;
}

static int bpf_ops_parse(int argc, char **argv, struct sock_filter *bpf_ops,
			 bool from_file)
{
	printf("SLANKDEV: %s\n", __func__);
	char *bpf_string, *token, separator = ',';
	int ret = 0, i = 0;
	bool need_release;
	__u16 bpf_len = 0;

	if (argc < 1)
		return -EINVAL;
	if (bpf_parse_string(argv[0], from_file, &bpf_len, &bpf_string,
			     &need_release, separator))
		return -EINVAL;
	if (bpf_len == 0 || bpf_len > BPF_MAXINSNS) {
		ret = -EINVAL;
		goto out;
	}

	token = bpf_string;
	while ((token = strchr(token, separator)) && (++token)[0]) {
		if (i >= bpf_len) {
			fprintf(stderr, "Real program length exceeds encoded length parameter!\n");
			ret = -EINVAL;
			goto out;
		}

		if (sscanf(token, "%hu %hhu %hhu %u,",
			   &bpf_ops[i].code, &bpf_ops[i].jt,
			   &bpf_ops[i].jf, &bpf_ops[i].k) != 4) {
			fprintf(stderr, "Error at instruction %d!\n", i);
			ret = -EINVAL;
			goto out;
		}

		i++;
	}

	if (i != bpf_len) {
		fprintf(stderr, "Parsed program length is less than encoded length parameter!\n");
		ret = -EINVAL;
		goto out;
	}
	ret = bpf_len;
out:
	if (need_release)
		free(bpf_string);

	return ret;
}

void bpf_print_ops(struct rtattr *bpf_ops, __u16 len)
{
	printf("SLANKDEV: %s\n", __func__);
	struct sock_filter *ops = RTA_DATA(bpf_ops);
	int i;

	if (len == 0)
		return;

	open_json_object("bytecode");
	print_uint(PRINT_ANY, "length", "bytecode \'%u,", len);
	open_json_array(PRINT_JSON, "insns");

	for (i = 0; i < len; i++) {
		open_json_object(NULL);
		print_hu(PRINT_ANY, "code", "%hu ", ops[i].code);
		print_hhu(PRINT_ANY, "jt", "%hhu ", ops[i].jt);
		print_hhu(PRINT_ANY, "jf", "%hhu ", ops[i].jf);
		if (i == len - 1)
			print_uint(PRINT_ANY, "k", "%u\'", ops[i].k);
		else
			print_uint(PRINT_ANY, "k", "%u,", ops[i].k);
		close_json_object();
	}

	close_json_array(PRINT_JSON, NULL);
	close_json_object();
}

static void bpf_map_pin_report(const struct bpf_elf_map *pin,
			       const struct bpf_elf_map *obj)
{
	printf("SLANKDEV: %s\n", __func__);
	fprintf(stderr, "Map specification differs from pinned file!\n");

	if (obj->type != pin->type)
		fprintf(stderr, " - Type:         %u (obj) != %u (pin)\n",
			obj->type, pin->type);
	if (obj->size_key != pin->size_key)
		fprintf(stderr, " - Size key:     %u (obj) != %u (pin)\n",
			obj->size_key, pin->size_key);
	if (obj->size_value != pin->size_value)
		fprintf(stderr, " - Size value:   %u (obj) != %u (pin)\n",
			obj->size_value, pin->size_value);
	if (obj->max_elem != pin->max_elem)
		fprintf(stderr, " - Max elems:    %u (obj) != %u (pin)\n",
			obj->max_elem, pin->max_elem);
	if (obj->flags != pin->flags)
		fprintf(stderr, " - Flags:        %#x (obj) != %#x (pin)\n",
			obj->flags, pin->flags);

	fprintf(stderr, "\n");
}

struct bpf_prog_data {
	unsigned int type;
	unsigned int jited;
};

struct bpf_map_ext {
	struct bpf_prog_data owner;
	unsigned int btf_id_key;
	unsigned int btf_id_val;
};

static int bpf_derive_elf_map_from_fdinfo(int fd, struct bpf_elf_map *map,
					  struct bpf_map_ext *ext)
{
	printf("SLANKDEV: %s\n", __func__);
	unsigned int val, owner_type = 0, owner_jited = 0;
	char file[PATH_MAX], buff[4096];
	FILE *fp;

	snprintf(file, sizeof(file), "/proc/%d/fdinfo/%d", getpid(), fd);
	memset(map, 0, sizeof(*map));

	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "No procfs support?!\n");
		return -EIO;
	}

	while (fgets(buff, sizeof(buff), fp)) {
		if (sscanf(buff, "map_type:\t%u", &val) == 1)
			map->type = val;
		else if (sscanf(buff, "key_size:\t%u", &val) == 1)
			map->size_key = val;
		else if (sscanf(buff, "value_size:\t%u", &val) == 1)
			map->size_value = val;
		else if (sscanf(buff, "max_entries:\t%u", &val) == 1)
			map->max_elem = val;
		else if (sscanf(buff, "map_flags:\t%i", &val) == 1)
			map->flags = val;
		else if (sscanf(buff, "owner_prog_type:\t%i", &val) == 1)
			owner_type = val;
		else if (sscanf(buff, "owner_jited:\t%i", &val) == 1)
			owner_jited = val;
	}

	fclose(fp);
	if (ext) {
		memset(ext, 0, sizeof(*ext));
		ext->owner.type  = owner_type;
		ext->owner.jited = owner_jited;
	}

	return 0;
}

static int bpf_map_selfcheck_pinned(int fd, const struct bpf_elf_map *map,
				    struct bpf_map_ext *ext, int length,
				    enum bpf_prog_type type)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_elf_map tmp, zero = {};
	int ret;

	ret = bpf_derive_elf_map_from_fdinfo(fd, &tmp, ext);
	if (ret < 0)
		return ret;

	/* The decision to reject this is on kernel side eventually, but
	 * at least give the user a chance to know what's wrong.
	 */
	if (ext->owner.type && ext->owner.type != type)
		fprintf(stderr, "Program array map owner types differ: %u (obj) != %u (pin)\n",
			type, ext->owner.type);

	if (!memcmp(&tmp, map, length)) {
		return 0;
	} else {
		/* If kernel doesn't have eBPF-related fdinfo, we cannot do much,
		 * so just accept it. We know we do have an eBPF fd and in this
		 * case, everything is 0. It is guaranteed that no such map exists
		 * since map type of 0 is unloadable BPF_MAP_TYPE_UNSPEC.
		 */
		if (!memcmp(&tmp, &zero, length))
			return 0;

		bpf_map_pin_report(&tmp, map);
		return -EINVAL;
	}
}

static int bpf_mnt_fs(const char *target)
{
	printf("SLANKDEV: %s\n", __func__);
	bool bind_done = false;

	while (mount("", target, "none", MS_PRIVATE | MS_REC, NULL)) {
		if (errno != EINVAL || bind_done) {
			fprintf(stderr, "mount --make-private %s failed: %s\n",
				target,	strerror(errno));
			return -1;
		}

		if (mount(target, target, "none", MS_BIND, NULL)) {
			fprintf(stderr, "mount --bind %s %s failed: %s\n",
				target,	target, strerror(errno));
			return -1;
		}

		bind_done = true;
	}

	if (mount("bpf", target, "bpf", 0, "mode=0700")) {
		fprintf(stderr, "mount -t bpf bpf %s failed: %s\n",
			target,	strerror(errno));
		return -1;
	}

	return 0;
}

static int bpf_mnt_check_target(const char *target)
{
	printf("SLANKDEV: %s\n", __func__);
	int ret;

	ret = mkdir(target, S_IRWXU);
	if (ret) {
		if (errno == EEXIST)
			return 0;
		fprintf(stderr, "mkdir %s failed: %s\n", target,
			strerror(errno));
	}

	return ret;
}

static int bpf_valid_mntpt(const char *mnt, unsigned long magic)
{
	printf("SLANKDEV: %s\n", __func__);
	struct statfs st_fs;

	if (statfs(mnt, &st_fs) < 0)
		return -ENOENT;
	if ((unsigned long)st_fs.f_type != magic)
		return -ENOENT;

	return 0;
}

static const char *bpf_find_mntpt_single(unsigned long magic, char *mnt,
					 int len, const char *mntpt)
{
	printf("SLANKDEV: %s\n", __func__);
	int ret;

	ret = bpf_valid_mntpt(mntpt, magic);
	if (!ret) {
		strlcpy(mnt, mntpt, len);
		return mnt;
	}

	return NULL;
}

static const char *bpf_find_mntpt(const char *fstype, unsigned long magic,
				  char *mnt, int len,
				  const char * const *known_mnts)
{
	printf("SLANKDEV: %s\n", __func__);
	const char * const *ptr;
	char type[100];
	FILE *fp;

	if (known_mnts) {
		ptr = known_mnts;
		while (*ptr) {
			if (bpf_find_mntpt_single(magic, mnt, len, *ptr))
				return mnt;
			ptr++;
		}
	}

	if (len != PATH_MAX)
		return NULL;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL)
		return NULL;

	while (fscanf(fp, "%*s %" textify(PATH_MAX) "s %99s %*s %*d %*d\n",
		      mnt, type) == 2) {
		if (strcmp(type, fstype) == 0)
			break;
	}

	fclose(fp);
	if (strcmp(type, fstype) != 0)
		return NULL;

	return mnt;
}

int bpf_trace_pipe(void)
{
	printf("SLANKDEV: %s\n", __func__);
	char tracefs_mnt[PATH_MAX] = TRACE_DIR_MNT;
	static const char * const tracefs_known_mnts[] = {
		TRACE_DIR_MNT,
		"/sys/kernel/debug/tracing",
		"/tracing",
		"/trace",
		0,
	};
	int fd_in, fd_out = STDERR_FILENO;
	char tpipe[PATH_MAX];
	const char *mnt;

	mnt = bpf_find_mntpt("tracefs", TRACEFS_MAGIC, tracefs_mnt,
			     sizeof(tracefs_mnt), tracefs_known_mnts);
	if (!mnt) {
		fprintf(stderr, "tracefs not mounted?\n");
		return -1;
	}

	snprintf(tpipe, sizeof(tpipe), "%s/trace_pipe", mnt);

	fd_in = open(tpipe, O_RDONLY);
	if (fd_in < 0)
		return -1;

	fprintf(stderr, "Running! Hang up with ^C!\n\n");
	while (1) {
		static char buff[4096];
		ssize_t ret;

		ret = read(fd_in, buff, sizeof(buff));
		if (ret > 0 && write(fd_out, buff, ret) == ret)
			continue;
		break;
	}

	close(fd_in);
	return -1;
}

static int bpf_gen_global(const char *bpf_sub_dir)
{
	printf("SLANKDEV: %s\n", __func__);
	char bpf_glo_dir[PATH_MAX];
	int ret;

	snprintf(bpf_glo_dir, sizeof(bpf_glo_dir), "%s/%s/",
		 bpf_sub_dir, BPF_DIR_GLOBALS);

	ret = mkdir(bpf_glo_dir, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", bpf_glo_dir,
			strerror(errno));
		return ret;
	}

	return 0;
}

static int bpf_gen_master(const char *base, const char *name)
{
	printf("SLANKDEV: %s\n", __func__);
	char bpf_sub_dir[PATH_MAX + NAME_MAX + 1];
	int ret;

	snprintf(bpf_sub_dir, sizeof(bpf_sub_dir), "%s%s/", base, name);

	ret = mkdir(bpf_sub_dir, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", bpf_sub_dir,
			strerror(errno));
		return ret;
	}

	return bpf_gen_global(bpf_sub_dir);
}

static int bpf_slave_via_bind_mnt(const char *full_name,
				  const char *full_link)
{
	printf("SLANKDEV: %s\n", __func__);
	int ret;

	ret = mkdir(full_name, S_IRWXU);
	if (ret) {
		assert(errno != EEXIST);
		fprintf(stderr, "mkdir %s failed: %s\n", full_name,
			strerror(errno));
		return ret;
	}

	ret = mount(full_link, full_name, "none", MS_BIND, NULL);
	if (ret) {
		rmdir(full_name);
		fprintf(stderr, "mount --bind %s %s failed: %s\n",
			full_link, full_name, strerror(errno));
	}

	return ret;
}

static int bpf_gen_slave(const char *base, const char *name,
			 const char *link)
{
	printf("SLANKDEV: %s base=%s name=%s\n", __func__, base, name);
	char bpf_lnk_dir[PATH_MAX + NAME_MAX + 1];
	char bpf_sub_dir[PATH_MAX + NAME_MAX];
	struct stat sb = {};
	int ret;

	snprintf(bpf_lnk_dir, sizeof(bpf_lnk_dir), "%s%s/", base, link);
	snprintf(bpf_sub_dir, sizeof(bpf_sub_dir), "%s%s",  base, name);

	ret = symlink(bpf_lnk_dir, bpf_sub_dir);
	if (ret) {
		if (errno != EEXIST) {
			if (errno != EPERM) {
				fprintf(stderr, "symlink %s failed: %s\n",
					bpf_sub_dir, strerror(errno));
				return ret;
			}

			return bpf_slave_via_bind_mnt(bpf_sub_dir,
						      bpf_lnk_dir);
		}

		ret = lstat(bpf_sub_dir, &sb);
		if (ret) {
			fprintf(stderr, "lstat %s failed: %s\n",
				bpf_sub_dir, strerror(errno));
			return ret;
		}

		if ((sb.st_mode & S_IFMT) != S_IFLNK)
			return bpf_gen_global(bpf_sub_dir);
	}

	return 0;
}

static int bpf_gen_hierarchy(const char *base)
{
	printf("SLANKDEV: %s\n", __func__);
	int ret, i;

	ret = bpf_gen_master(base, bpf_prog_to_subdir(__bpf_types[0]));
	for (i = 1; i < ARRAY_SIZE(__bpf_types) && !ret; i++)
		ret = bpf_gen_slave(base,
				    bpf_prog_to_subdir(__bpf_types[i]),
				    bpf_prog_to_subdir(__bpf_types[0]));
	return ret;
}

static const char *bpf_get_work_dir(enum bpf_prog_type type)
{
	printf("SLANKDEV: %s\n", __func__);
	static char bpf_tmp[PATH_MAX] = BPF_DIR_MNT;
	static char bpf_wrk_dir[PATH_MAX];
	static const char *mnt;
	static bool bpf_mnt_cached;
	const char *mnt_env = getenv(BPF_ENV_MNT);
	static const char * const bpf_known_mnts[] = {
		BPF_DIR_MNT,
		"/bpf",
		0,
	};
	int ret;

	if (bpf_mnt_cached) {
		const char *out = mnt;

		if (out && type) {
			snprintf(bpf_tmp, sizeof(bpf_tmp), "%s%s/",
				 out, bpf_prog_to_subdir(type));
			out = bpf_tmp;
		}
		return out;
	}

	if (mnt_env)
		mnt = bpf_find_mntpt_single(BPF_FS_MAGIC, bpf_tmp,
					    sizeof(bpf_tmp), mnt_env);
	else
		mnt = bpf_find_mntpt("bpf", BPF_FS_MAGIC, bpf_tmp,
				     sizeof(bpf_tmp), bpf_known_mnts);
	if (!mnt) {
		mnt = mnt_env ? : BPF_DIR_MNT;
		ret = bpf_mnt_check_target(mnt);
		if (!ret)
			ret = bpf_mnt_fs(mnt);
		if (ret) {
			mnt = NULL;
			goto out;
		}
	}

	ret = snprintf(bpf_wrk_dir, sizeof(bpf_wrk_dir), "%s/", mnt);
	if (ret < 0 || ret >= sizeof(bpf_wrk_dir)) {
		mnt = NULL;
		goto out;
	}

	ret = bpf_gen_hierarchy(bpf_wrk_dir);
	if (ret) {
		mnt = NULL;
		goto out;
	}

	mnt = bpf_wrk_dir;
out:
	bpf_mnt_cached = true;
	return mnt;
}

static int bpf_obj_get(const char *pathname, enum bpf_prog_type type)
{
	printf("SLANKDEV: %s\n", __func__);
	union bpf_attr attr = {};
	char tmp[PATH_MAX];

	if (strlen(pathname) > 2 && pathname[0] == 'm' &&
	    pathname[1] == ':' && bpf_get_work_dir(type)) {
		snprintf(tmp, sizeof(tmp), "%s/%s",
			 bpf_get_work_dir(type), pathname + 2);
		pathname = tmp;
	}

	attr.pathname = bpf_ptr_to_u64(pathname);

	return bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_obj_pinned(const char *pathname, enum bpf_prog_type type)
{
	printf("SLANKDEV: %s\n", __func__);
	int prog_fd = bpf_obj_get(pathname, type);

	if (prog_fd < 0)
		fprintf(stderr, "Couldn\'t retrieve pinned program \'%s\': %s\n",
			pathname, strerror(errno));
	return prog_fd;
}

static int bpf_do_parse(struct bpf_cfg_in *cfg, const bool *opt_tbl)
{
	printf("SLANKDEV: %s\n", __func__);
	const char *file, *section, *uds_name;
	bool verbose = false;
	int i, ret, argc;
	char **argv;

	argv = cfg->argv;
	argc = cfg->argc;

	if (opt_tbl[CBPF_BYTECODE] &&
	    (matches(*argv, "bytecode") == 0 ||
	     strcmp(*argv, "bc") == 0)) {
		cfg->mode = CBPF_BYTECODE;
	} else if (opt_tbl[CBPF_FILE] &&
		   (matches(*argv, "bytecode-file") == 0 ||
		    strcmp(*argv, "bcf") == 0)) {
		cfg->mode = CBPF_FILE;
	} else if (opt_tbl[EBPF_OBJECT] &&
		   (matches(*argv, "object-file") == 0 ||
		    strcmp(*argv, "obj") == 0)) {
		cfg->mode = EBPF_OBJECT;
	} else if (opt_tbl[EBPF_PINNED] &&
		   (matches(*argv, "object-pinned") == 0 ||
		    matches(*argv, "pinned") == 0 ||
		    matches(*argv, "fd") == 0)) {
		cfg->mode = EBPF_PINNED;
	} else {
		fprintf(stderr, "What mode is \"%s\"?\n", *argv);
		return -1;
	}

	NEXT_ARG();
	file = section = uds_name = NULL;
	if (cfg->mode == EBPF_OBJECT || cfg->mode == EBPF_PINNED) {
		file = *argv;
		NEXT_ARG_FWD();

		if (cfg->type == BPF_PROG_TYPE_UNSPEC) {
			if (argc > 0 && matches(*argv, "type") == 0) {
				NEXT_ARG();
				for (i = 0; i < ARRAY_SIZE(__bpf_prog_meta);
				     i++) {
					if (!__bpf_prog_meta[i].type)
						continue;
					if (!matches(*argv,
						     __bpf_prog_meta[i].type)) {
						cfg->type = i;
						break;
					}
				}

				if (cfg->type == BPF_PROG_TYPE_UNSPEC) {
					fprintf(stderr, "What type is \"%s\"?\n",
						*argv);
					return -1;
				}
				NEXT_ARG_FWD();
			} else {
				cfg->type = BPF_PROG_TYPE_SCHED_CLS;
			}
		}

		section = bpf_prog_to_default_section(cfg->type);
		if (argc > 0 && matches(*argv, "section") == 0) {
			NEXT_ARG();
			section = *argv;
			NEXT_ARG_FWD();
		}

		if (__bpf_prog_meta[cfg->type].may_uds_export) {
			uds_name = getenv(BPF_ENV_UDS);
			if (argc > 0 && !uds_name &&
			    matches(*argv, "export") == 0) {
				NEXT_ARG();
				uds_name = *argv;
				NEXT_ARG_FWD();
			}
		}

		if (argc > 0 && matches(*argv, "verbose") == 0) {
			verbose = true;
			NEXT_ARG_FWD();
		}

		PREV_ARG();
	}

	if (cfg->mode == CBPF_BYTECODE || cfg->mode == CBPF_FILE) {
		ret = bpf_ops_parse(argc, argv, cfg->opcodes,
				    cfg->mode == CBPF_FILE);
		cfg->n_opcodes = ret;
	} else if (cfg->mode == EBPF_OBJECT) {
		ret = 0; /* program will be loaded by load stage */
	} else if (cfg->mode == EBPF_PINNED) {
		ret = bpf_obj_pinned(file, cfg->type);
		cfg->prog_fd = ret;
	} else {
		return -1;
	}

	cfg->object  = file;
	cfg->section = section;
	cfg->uds     = uds_name;
	cfg->argc    = argc;
	cfg->argv    = argv;
	cfg->verbose = verbose;

	return ret;
}

static int bpf_do_load(struct bpf_cfg_in *cfg)
{
	printf("SLANKDEV: %s\n", __func__);
	if (cfg->mode == EBPF_OBJECT) {
		return iproute2_load_libbpf(cfg);
	}
	return 0;
}

int bpf_load_common(struct bpf_cfg_in *cfg, const struct bpf_cfg_ops *ops,
		    void *nl)
{
	printf("SLANKDEV: %s\n", __func__);
	char annotation[256];
	int ret;

	ret = bpf_do_load(cfg);
	if (ret < 0)
		return ret;

	if (cfg->mode == CBPF_BYTECODE || cfg->mode == CBPF_FILE)
		ops->cbpf_cb(nl, cfg->opcodes, cfg->n_opcodes);
	if (cfg->mode == EBPF_OBJECT || cfg->mode == EBPF_PINNED) {
		snprintf(annotation, sizeof(annotation), "%s:[%s]",
			 basename(cfg->object), cfg->mode == EBPF_PINNED ?
			 "*fsobj" : cfg->section);
		ops->ebpf_cb(nl, cfg->prog_fd, annotation);
	}

	return 0;
}

int bpf_parse_common(struct bpf_cfg_in *cfg, const struct bpf_cfg_ops *ops)
{
	printf("SLANKDEV: %s\n", __func__);
	bool opt_tbl[BPF_MODE_MAX] = {};

	if (ops->cbpf_cb) {
		opt_tbl[CBPF_BYTECODE] = true;
		opt_tbl[CBPF_FILE]     = true;
	}

	if (ops->ebpf_cb) {
		opt_tbl[EBPF_OBJECT]   = true;
		opt_tbl[EBPF_PINNED]   = true;
	}

	return bpf_do_parse(cfg, opt_tbl);
}

int bpf_parse_and_load_common(struct bpf_cfg_in *cfg,
			      const struct bpf_cfg_ops *ops, void *nl)
{
	printf("SLANKDEV: %s\n", __func__);
	int ret;

	ret = bpf_parse_common(cfg, ops);
	if (ret < 0)
		return ret;

	return bpf_load_common(cfg, ops, nl);
}

int bpf_graft_map(const char *map_path, uint32_t *key, int argc, char **argv)
{
	printf("SLANKDEV: %s\n", __func__);
	const bool opt_tbl[BPF_MODE_MAX] = {
		[EBPF_OBJECT]	= true,
		[EBPF_PINNED]	= true,
	};
	const struct bpf_elf_map test = {
		.type		= BPF_MAP_TYPE_PROG_ARRAY,
		.size_key	= sizeof(int),
		.size_value	= sizeof(int),
	};
	struct bpf_cfg_in cfg = {
		.type		= BPF_PROG_TYPE_UNSPEC,
		.argc		= argc,
		.argv		= argv,
	};
	struct bpf_map_ext ext = {};
	int ret, prog_fd, map_fd;
	uint32_t map_key;

	ret = bpf_do_parse(&cfg, opt_tbl);
	if (ret < 0)
		return ret;

	ret = bpf_do_load(&cfg);
	if (ret < 0)
		return ret;

	prog_fd = cfg.prog_fd;

	if (key) {
		map_key = *key;
	} else {
		ret = sscanf(cfg.section, "%*i/%i", &map_key);
		if (ret != 1) {
			fprintf(stderr, "Couldn\'t infer map key from section name! Please provide \'key\' argument!\n");
			ret = -EINVAL;
			goto out_prog;
		}
	}

	map_fd = bpf_obj_get(map_path, cfg.type);
	if (map_fd < 0) {
		fprintf(stderr, "Couldn\'t retrieve pinned map \'%s\': %s\n",
			map_path, strerror(errno));
		ret = map_fd;
		goto out_prog;
	}

	ret = bpf_map_selfcheck_pinned(map_fd, &test, &ext,
				       offsetof(struct bpf_elf_map, max_elem),
				       cfg.type);
	if (ret < 0) {
		fprintf(stderr, "Map \'%s\' self-check failed!\n", map_path);
		goto out_map;
	}

	ret = bpf_map_update(map_fd, &map_key, &prog_fd, BPF_ANY);
	if (ret < 0)
		fprintf(stderr, "Map update failed: %s\n", strerror(errno));
out_map:
	close(map_fd);
out_prog:
	close(prog_fd);
	return ret;
}

// int bpf_prog_attach_fd(int prog_fd, int target_fd, enum bpf_attach_type type)
// {
// 	printf("SLANKDEV: %s\n", __func__);
// 	union bpf_attr attr = {};

// 	attr.target_fd = target_fd;
// 	attr.attach_bpf_fd = prog_fd;
// 	attr.attach_type = type;

// 	return bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
// }

// int bpf_prog_detach_fd(int target_fd, enum bpf_attach_type type)
// {
// 	printf("SLANKDEV: %s\n", __func__);
// 	union bpf_attr attr = {};

// 	attr.target_fd = target_fd;
// 	attr.attach_type = type;

// 	return bpf(BPF_PROG_DETACH, &attr, sizeof(attr));
// }

int bpf_prog_load_dev(enum bpf_prog_type type, const struct bpf_insn *insns,
		      size_t size_insns, const char *license, __u32 ifindex,
		      char *log, size_t size_log)
{
	printf("SLANKDEV: %s\n", __func__);
	union bpf_attr attr = {};

	attr.prog_type = type;
	attr.insns = bpf_ptr_to_u64(insns);
	attr.insn_cnt = size_insns / sizeof(struct bpf_insn);
	attr.license = bpf_ptr_to_u64(license);
	attr.prog_ifindex = ifindex;

	if (size_log > 0) {
		attr.log_buf = bpf_ptr_to_u64(log);
		attr.log_size = size_log;
		attr.log_level = 1;
	}

	return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_program_load(enum bpf_prog_type type, const struct bpf_insn *insns,
		     size_t size_insns, const char *license, char *log,
		     size_t size_log)
{
	printf("SLANKDEV: %s\n", __func__);
	return bpf_prog_load_dev(type, insns, size_insns, license, 0, log, size_log);
}

#ifdef HAVE_ELF
struct bpf_elf_prog {
	enum bpf_prog_type	type;
	struct bpf_insn		*insns;
	unsigned int		insns_num;
	size_t			size;
	const char		*license;
};

struct bpf_hash_entry {
	unsigned int		pinning;
	const char		*subpath;
	struct bpf_hash_entry	*next;
};

struct bpf_config {
	unsigned int		jit_enabled;
};

struct bpf_btf {
	const struct btf_header	*hdr;
	const void		*raw;
	const char		*strings;
	const struct btf_type	**types;
	int			types_num;
};

struct bpf_elf_ctx {
	struct bpf_config	cfg;
	Elf			*elf_fd;
	GElf_Ehdr		elf_hdr;
	Elf_Data		*sym_tab;
	Elf_Data		*str_tab;
	Elf_Data		*btf_data;
	char			obj_uid[64];
	int			obj_fd;
	int			btf_fd;
	int			map_fds[ELF_MAX_MAPS];
	struct bpf_elf_map	maps[ELF_MAX_MAPS];
	struct bpf_map_ext	maps_ext[ELF_MAX_MAPS];
	struct bpf_elf_prog	prog_text;
	struct bpf_btf		btf;
	int			sym_num;
	int			map_num;
	int			map_len;
	bool			*sec_done;
	int			sec_maps;
	int			sec_text;
	int			sec_btf;
	char			license[ELF_MAX_LICENSE_LEN];
	enum bpf_prog_type	type;
	__u32			ifindex;
	bool			verbose;
	bool			noafalg;
	struct bpf_elf_st	stat;
	struct bpf_hash_entry	*ht[256];
	char			*log;
	size_t			log_size;
};

struct bpf_elf_sec_data {
	GElf_Shdr		sec_hdr;
	Elf_Data		*sec_data;
	const char		*sec_name;
};

struct bpf_map_data {
	int			*fds;
	const char		*obj;
	struct bpf_elf_st	*st;
	struct bpf_elf_map	*ent;
};

static int bpf_log_realloc(struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	const size_t log_max = UINT_MAX >> 8;
	size_t log_size = ctx->log_size;
	char *ptr;

	if (!ctx->log) {
		log_size = 65536;
	} else if (log_size < log_max) {
		log_size <<= 1;
		if (log_size > log_max)
			log_size = log_max;
	} else {
		return -EINVAL;
	}

	ptr = realloc(ctx->log, log_size);
	if (!ptr)
		return -ENOMEM;

	ptr[0] = 0;
	ctx->log = ptr;
	ctx->log_size = log_size;

	return 0;
}

static int bpf_obj_hash(const char *object, uint8_t *out, size_t len)
{
	printf("SLANKDEV: %s\n", __func__);
	struct sockaddr_alg alg = {
		.salg_family	= AF_ALG,
		.salg_type	= "hash",
		.salg_name	= "sha1",
	};
	int ret, cfd, ofd, ffd;
	struct stat stbuff;
	ssize_t size;

	if (!object || len != 20)
		return -EINVAL;

	cfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (cfd < 0)
		return cfd;

	ret = bind(cfd, (struct sockaddr *)&alg, sizeof(alg));
	if (ret < 0)
		goto out_cfd;

	ofd = accept(cfd, NULL, 0);
	if (ofd < 0) {
		ret = ofd;
		goto out_cfd;
	}

	ffd = open(object, O_RDONLY);
	if (ffd < 0) {
		fprintf(stderr, "Error opening object %s: %s\n",
			object, strerror(errno));
		ret = ffd;
		goto out_ofd;
	}

	ret = fstat(ffd, &stbuff);
	if (ret < 0) {
		fprintf(stderr, "Error doing fstat: %s\n",
			strerror(errno));
		goto out_ffd;
	}

	size = sendfile(ofd, ffd, NULL, stbuff.st_size);
	if (size != stbuff.st_size) {
		fprintf(stderr, "Error from sendfile (%zd vs %zu bytes): %s\n",
			size, stbuff.st_size, strerror(errno));
		ret = -1;
		goto out_ffd;
	}

	size = read(ofd, out, len);
	if (size != len) {
		fprintf(stderr, "Error from read (%zd vs %zu bytes): %s\n",
			size, len, strerror(errno));
		ret = -1;
	} else {
		ret = 0;
	}
out_ffd:
	close(ffd);
out_ofd:
	close(ofd);
out_cfd:
	close(cfd);
	return ret;
}

static void bpf_init_env(void)
{
	printf("SLANKDEV: %s\n", __func__);
	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	/* Don't bother in case we fail! */
	setrlimit(RLIMIT_MEMLOCK, &limit);

	if (!bpf_get_work_dir(BPF_PROG_TYPE_UNSPEC))
		fprintf(stderr, "Continuing without mounted eBPF fs. Too old kernel?\n");
}

static const char *bpf_custom_pinning(const struct bpf_elf_ctx *ctx,
				      uint32_t pinning)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_hash_entry *entry;

	entry = ctx->ht[pinning & (ARRAY_SIZE(ctx->ht) - 1)];
	while (entry && entry->pinning != pinning)
		entry = entry->next;

	return entry ? entry->subpath : NULL;
}

static bool bpf_no_pinning(const struct bpf_elf_ctx *ctx,
			   uint32_t pinning)
{
	printf("SLANKDEV: %s\n", __func__);
	switch (pinning) {
	case PIN_OBJECT_NS:
	case PIN_GLOBAL_NS:
		return false;
	case PIN_NONE:
		return true;
	default:
		return !bpf_custom_pinning(ctx, pinning);
	}
}

static void bpf_make_pathname(char *pathname, size_t len, const char *name,
			      const struct bpf_elf_ctx *ctx, uint32_t pinning)
{
	printf("SLANKDEV: %s\n", __func__);
	switch (pinning) {
	case PIN_OBJECT_NS:
		snprintf(pathname, len, "%s/%s/%s",
			 bpf_get_work_dir(ctx->type),
			 ctx->obj_uid, name);
		break;
	case PIN_GLOBAL_NS:
		snprintf(pathname, len, "%s/%s/%s",
			 bpf_get_work_dir(ctx->type),
			 BPF_DIR_GLOBALS, name);
		break;
	default:
		snprintf(pathname, len, "%s/../%s/%s",
			 bpf_get_work_dir(ctx->type),
			 bpf_custom_pinning(ctx, pinning), name);
		break;
	}
}

static int bpf_make_obj_path(const struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	char tmp[PATH_MAX];
	int ret;

	snprintf(tmp, sizeof(tmp), "%s/%s", bpf_get_work_dir(ctx->type),
		 ctx->obj_uid);

	ret = mkdir(tmp, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", tmp, strerror(errno));
		return ret;
	}

	return 0;
}

static int bpf_make_custom_path(const struct bpf_elf_ctx *ctx,
				const char *todo)
{
	printf("SLANKDEV: %s\n", __func__);
	char tmp[PATH_MAX], rem[PATH_MAX], *sub;
	int ret;

	snprintf(tmp, sizeof(tmp), "%s/../", bpf_get_work_dir(ctx->type));
	snprintf(rem, sizeof(rem), "%s/", todo);
	sub = strtok(rem, "/");

	while (sub) {
		if (strlen(tmp) + strlen(sub) + 2 > PATH_MAX)
			return -EINVAL;

		strcat(tmp, sub);
		strcat(tmp, "/");

		ret = mkdir(tmp, S_IRWXU);
		if (ret && errno != EEXIST) {
			fprintf(stderr, "mkdir %s failed: %s\n", tmp,
				strerror(errno));
			return ret;
		}

		sub = strtok(NULL, "/");
	}

	return 0;
}

static bool bpf_is_map_in_map_type(const struct bpf_elf_map *map)
{
	printf("SLANKDEV: %s\n", __func__);
	return map->type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
	       map->type == BPF_MAP_TYPE_HASH_OF_MAPS;
}

static const char *bpf_str_tab_name(const struct bpf_elf_ctx *ctx,
				    const GElf_Sym *sym)
{
	printf("SLANKDEV: %s\n", __func__);
	return ctx->str_tab->d_buf + sym->st_name;
}

static int bpf_btf_find(struct bpf_elf_ctx *ctx, const char *name)
{
	printf("SLANKDEV: %s\n", __func__);
	const struct btf_type *type;
	const char *res;
	int id;

	for (id = 1; id < ctx->btf.types_num; id++) {
		type = ctx->btf.types[id];
		if (type->name_off >= ctx->btf.hdr->str_len)
			continue;
		res = &ctx->btf.strings[type->name_off];
		if (!strcmp(res, name))
			return id;
	}

	return -ENOENT;
}

static int bpf_btf_find_kv(struct bpf_elf_ctx *ctx, const struct bpf_elf_map *map,
			   const char *name, uint32_t *id_key, uint32_t *id_val)
{
	printf("SLANKDEV: %s\n", __func__);
	const struct btf_member *key, *val;
	const struct btf_type *type;
	char btf_name[512];
	const char *res;
	int id;

	snprintf(btf_name, sizeof(btf_name), "____btf_map_%s", name);
	id = bpf_btf_find(ctx, btf_name);
	if (id < 0)
		return id;

	type = ctx->btf.types[id];
	if (BTF_INFO_KIND(type->info) != BTF_KIND_STRUCT)
		return -EINVAL;
	if (BTF_INFO_VLEN(type->info) != 2)
		return -EINVAL;

	key = ((void *) type) + sizeof(*type);
	val = key + 1;
	if (!key->type || key->type >= ctx->btf.types_num ||
	    !val->type || val->type >= ctx->btf.types_num)
		return -EINVAL;

	if (key->name_off >= ctx->btf.hdr->str_len ||
	    val->name_off >= ctx->btf.hdr->str_len)
		return -EINVAL;

	res = &ctx->btf.strings[key->name_off];
	if (strcmp(res, "key"))
		return -EINVAL;

	res = &ctx->btf.strings[val->name_off];
	if (strcmp(res, "value"))
		return -EINVAL;

	*id_key = key->type;
	*id_val = val->type;
	return 0;
}

static void bpf_btf_annotate(struct bpf_elf_ctx *ctx, int which, const char *name)
{
	printf("SLANKDEV: %s\n", __func__);
	uint32_t id_key = 0, id_val = 0;

	if (!bpf_btf_find_kv(ctx, &ctx->maps[which], name, &id_key, &id_val)) {
		ctx->maps_ext[which].btf_id_key = id_key;
		ctx->maps_ext[which].btf_id_val = id_val;
	}
}

static const char *bpf_map_fetch_name(struct bpf_elf_ctx *ctx, int which)
{
	printf("SLANKDEV: %s\n", __func__);
	const char *name;
	GElf_Sym sym;
	int i;

	for (i = 0; i < ctx->sym_num; i++) {
		int type;

		if (gelf_getsym(ctx->sym_tab, i, &sym) != &sym)
			continue;

		type = GELF_ST_TYPE(sym.st_info);
		if (GELF_ST_BIND(sym.st_info) != STB_GLOBAL ||
		    (type != STT_NOTYPE && type != STT_OBJECT) ||
		    sym.st_shndx != ctx->sec_maps ||
		    sym.st_value / ctx->map_len != which)
			continue;

		name = bpf_str_tab_name(ctx, &sym);
		bpf_btf_annotate(ctx, which, name);
		return name;
	}

	return NULL;
}

static int bpf_map_num_sym(struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	int i, num = 0;
	GElf_Sym sym;

	for (i = 0; i < ctx->sym_num; i++) {
		int type;

		if (gelf_getsym(ctx->sym_tab, i, &sym) != &sym)
			continue;

		type = GELF_ST_TYPE(sym.st_info);
		if (GELF_ST_BIND(sym.st_info) != STB_GLOBAL ||
		    (type != STT_NOTYPE && type != STT_OBJECT) ||
		    sym.st_shndx != ctx->sec_maps)
			continue;
		num++;
	}

	return num;
}

static int bpf_fill_section_data(struct bpf_elf_ctx *ctx, int section,
				 struct bpf_elf_sec_data *data)
{
	printf("SLANKDEV: %s\n", __func__);
	Elf_Data *sec_edata;
	GElf_Shdr sec_hdr;
	Elf_Scn *sec_fd;
	char *sec_name;

	memset(data, 0, sizeof(*data));

	sec_fd = elf_getscn(ctx->elf_fd, section);
	if (!sec_fd)
		return -EINVAL;
	if (gelf_getshdr(sec_fd, &sec_hdr) != &sec_hdr)
		return -EIO;

	sec_name = elf_strptr(ctx->elf_fd, ctx->elf_hdr.e_shstrndx,
			      sec_hdr.sh_name);
	if (!sec_name || !sec_hdr.sh_size)
		return -ENOENT;

	sec_edata = elf_getdata(sec_fd, NULL);
	if (!sec_edata || elf_getdata(sec_fd, sec_edata))
		return -EIO;

	memcpy(&data->sec_hdr, &sec_hdr, sizeof(sec_hdr));

	data->sec_name = sec_name;
	data->sec_data = sec_edata;
	return 0;
}

struct bpf_elf_map_min {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
};

static int bpf_fetch_maps_begin(struct bpf_elf_ctx *ctx, int section,
				struct bpf_elf_sec_data *data)
{
	printf("SLANKDEV: %s\n", __func__);
	ctx->map_num = data->sec_data->d_size;
	ctx->sec_maps = section;
	ctx->sec_done[section] = true;

	if (ctx->map_num > sizeof(ctx->maps)) {
		fprintf(stderr, "Too many BPF maps in ELF section!\n");
		return -ENOMEM;
	}

	memcpy(ctx->maps, data->sec_data->d_buf, ctx->map_num);
	return 0;
}

static int bpf_map_verify_all_offs(struct bpf_elf_ctx *ctx, int end)
{
	printf("SLANKDEV: %s\n", __func__);
	GElf_Sym sym;
	int off, i;

	for (off = 0; off < end; off += ctx->map_len) {
		/* Order doesn't need to be linear here, hence we walk
		 * the table again.
		 */
		for (i = 0; i < ctx->sym_num; i++) {
			int type;

			if (gelf_getsym(ctx->sym_tab, i, &sym) != &sym)
				continue;

			type = GELF_ST_TYPE(sym.st_info);
			if (GELF_ST_BIND(sym.st_info) != STB_GLOBAL ||
			    (type != STT_NOTYPE && type != STT_OBJECT) ||
			    sym.st_shndx != ctx->sec_maps)
				continue;
			if (sym.st_value == off)
				break;
			if (i == ctx->sym_num - 1)
				return -1;
		}
	}

	return off == end ? 0 : -1;
}

static int bpf_fetch_maps_end(struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_elf_map fixup[ARRAY_SIZE(ctx->maps)] = {};
	int i, sym_num = bpf_map_num_sym(ctx);
	__u8 *buff;

	if (sym_num == 0 || sym_num > ARRAY_SIZE(ctx->maps)) {
		fprintf(stderr, "%u maps not supported in current map section!\n",
			sym_num);
		return -EINVAL;
	}

	if (ctx->map_num % sym_num != 0 ||
	    ctx->map_num % sizeof(__u32) != 0) {
		fprintf(stderr, "Number BPF map symbols are not multiple of struct bpf_elf_map!\n");
		return -EINVAL;
	}

	ctx->map_len = ctx->map_num / sym_num;
	if (bpf_map_verify_all_offs(ctx, ctx->map_num)) {
		fprintf(stderr, "Different struct bpf_elf_map in use!\n");
		return -EINVAL;
	}

	if (ctx->map_len == sizeof(struct bpf_elf_map)) {
		ctx->map_num = sym_num;
		return 0;
	} else if (ctx->map_len > sizeof(struct bpf_elf_map)) {
		fprintf(stderr, "struct bpf_elf_map not supported, coming from future version?\n");
		return -EINVAL;
	} else if (ctx->map_len < sizeof(struct bpf_elf_map_min)) {
		fprintf(stderr, "struct bpf_elf_map too small, not supported!\n");
		return -EINVAL;
	}

	ctx->map_num = sym_num;
	for (i = 0, buff = (void *)ctx->maps; i < ctx->map_num;
	     i++, buff += ctx->map_len) {
		/* The fixup leaves the rest of the members as zero, which
		 * is fine currently, but option exist to set some other
		 * default value as well when needed in future.
		 */
		memcpy(&fixup[i], buff, ctx->map_len);
	}

	memcpy(ctx->maps, fixup, sizeof(fixup));
	if (ctx->verbose)
		printf("%zu bytes struct bpf_elf_map fixup performed due to size mismatch!\n",
		       sizeof(struct bpf_elf_map) - ctx->map_len);
	return 0;
}

static int bpf_fetch_symtab(struct bpf_elf_ctx *ctx, int section,
			    struct bpf_elf_sec_data *data)
{
	printf("SLANKDEV: %s\n", __func__);
	ctx->sym_tab = data->sec_data;
	ctx->sym_num = data->sec_hdr.sh_size / data->sec_hdr.sh_entsize;
	ctx->sec_done[section] = true;
	return 0;
}

static int bpf_fetch_strtab(struct bpf_elf_ctx *ctx, int section,
			    struct bpf_elf_sec_data *data)
{
	printf("SLANKDEV: %s\n", __func__);
	ctx->str_tab = data->sec_data;
	ctx->sec_done[section] = true;
	return 0;
}

static bool bpf_has_map_data(const struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	return ctx->sym_tab && ctx->str_tab && ctx->sec_maps;
}

struct bpf_relo_props {
	struct bpf_tail_call {
		unsigned int total;
		unsigned int jited;
	} tc;
	int main_num;
};

struct bpf_jited_aux {
	int prog_fd;
	int map_fd;
	struct bpf_prog_data prog;
	struct bpf_map_ext map;
};

static void bpf_save_finfo(struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	struct stat st;
	int ret;

	memset(&ctx->stat, 0, sizeof(ctx->stat));

	ret = fstat(ctx->obj_fd, &st);
	if (ret < 0) {
		fprintf(stderr, "Stat of elf file failed: %s\n",
			strerror(errno));
		return;
	}

	ctx->stat.st_dev = st.st_dev;
	ctx->stat.st_ino = st.st_ino;
}

static int bpf_read_pin_mapping(FILE *fp, uint32_t *id, char *path)
{
	printf("SLANKDEV: %s\n", __func__);
	char buff[PATH_MAX];

	while (fgets(buff, sizeof(buff), fp)) {
		char *ptr = buff;

		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		if (*ptr == '#' || *ptr == '\n' || *ptr == 0)
			continue;

		if (sscanf(ptr, "%i %s\n", id, path) != 2 &&
		    sscanf(ptr, "%i %s #", id, path) != 2) {
			strcpy(path, ptr);
			return -1;
		}

		return 1;
	}

	return 0;
}

static bool bpf_pinning_reserved(uint32_t pinning)
{
	printf("SLANKDEV: %s\n", __func__);
	switch (pinning) {
	case PIN_NONE:
	case PIN_OBJECT_NS:
	case PIN_GLOBAL_NS:
		return true;
	default:
		return false;
	}
}

static void bpf_hash_init(struct bpf_elf_ctx *ctx, const char *db_file)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_hash_entry *entry;
	char subpath[PATH_MAX] = {};
	uint32_t pinning;
	FILE *fp;
	int ret;

	fp = fopen(db_file, "r");
	if (!fp)
		return;

	while ((ret = bpf_read_pin_mapping(fp, &pinning, subpath))) {
		if (ret == -1) {
			fprintf(stderr, "Database %s is corrupted at: %s\n",
				db_file, subpath);
			fclose(fp);
			return;
		}

		if (bpf_pinning_reserved(pinning)) {
			fprintf(stderr, "Database %s, id %u is reserved - ignoring!\n",
				db_file, pinning);
			continue;
		}

		entry = malloc(sizeof(*entry));
		if (!entry) {
			fprintf(stderr, "No memory left for db entry!\n");
			continue;
		}

		entry->pinning = pinning;
		entry->subpath = strdup(subpath);
		if (!entry->subpath) {
			fprintf(stderr, "No memory left for db entry!\n");
			free(entry);
			continue;
		}

		entry->next = ctx->ht[pinning & (ARRAY_SIZE(ctx->ht) - 1)];
		ctx->ht[pinning & (ARRAY_SIZE(ctx->ht) - 1)] = entry;
	}

	fclose(fp);
}

static int bpf_elf_check_ehdr(const struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	if (ctx->elf_hdr.e_type != ET_REL ||
	    (ctx->elf_hdr.e_machine != EM_NONE &&
	     ctx->elf_hdr.e_machine != EM_BPF) ||
	    ctx->elf_hdr.e_version != EV_CURRENT) {
		fprintf(stderr, "ELF format error, ELF file not for eBPF?\n");
		return -EINVAL;
	}

	switch (ctx->elf_hdr.e_ident[EI_DATA]) {
	default:
		fprintf(stderr, "ELF format error, wrong endianness info?\n");
		return -EINVAL;
	case ELFDATA2LSB:
		if (htons(1) == 1) {
			fprintf(stderr,
				"We are big endian, eBPF object is little endian!\n");
			return -EIO;
		}
		break;
	case ELFDATA2MSB:
		if (htons(1) != 1) {
			fprintf(stderr,
				"We are little endian, eBPF object is big endian!\n");
			return -EIO;
		}
		break;
	}

	return 0;
}

static void bpf_get_cfg(struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	static const char *path_jit = "/proc/sys/net/core/bpf_jit_enable";
	int fd;

	fd = open(path_jit, O_RDONLY);
	if (fd >= 0) {
		char tmp[16] = {};

		if (read(fd, tmp, sizeof(tmp)) > 0)
			ctx->cfg.jit_enabled = atoi(tmp);
		close(fd);
	}
}

static int bpf_elf_ctx_init(struct bpf_elf_ctx *ctx, const char *pathname,
			    enum bpf_prog_type type, __u32 ifindex,
			    bool verbose)
{
	printf("SLANKDEV: %s\n", __func__);
	uint8_t tmp[20];
	int ret;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return -EINVAL;

	bpf_init_env();

	memset(ctx, 0, sizeof(*ctx));
	bpf_get_cfg(ctx);

	ret = bpf_obj_hash(pathname, tmp, sizeof(tmp));
	if (ret)
		ctx->noafalg = true;
	else
		hexstring_n2a(tmp, sizeof(tmp), ctx->obj_uid,
			      sizeof(ctx->obj_uid));

	ctx->verbose = verbose;
	ctx->type    = type;
	ctx->ifindex = ifindex;

	ctx->obj_fd = open(pathname, O_RDONLY);
	if (ctx->obj_fd < 0)
		return ctx->obj_fd;

	ctx->elf_fd = elf_begin(ctx->obj_fd, ELF_C_READ, NULL);
	if (!ctx->elf_fd) {
		ret = -EINVAL;
		goto out_fd;
	}

	if (elf_kind(ctx->elf_fd) != ELF_K_ELF) {
		ret = -EINVAL;
		goto out_fd;
	}

	if (gelf_getehdr(ctx->elf_fd, &ctx->elf_hdr) !=
	    &ctx->elf_hdr) {
		ret = -EIO;
		goto out_elf;
	}

	ret = bpf_elf_check_ehdr(ctx);
	if (ret < 0)
		goto out_elf;

	ctx->sec_done = calloc(ctx->elf_hdr.e_shnum,
			       sizeof(*(ctx->sec_done)));
	if (!ctx->sec_done) {
		ret = -ENOMEM;
		goto out_elf;
	}

	if (ctx->verbose && bpf_log_realloc(ctx)) {
		ret = -ENOMEM;
		goto out_free;
	}

	bpf_save_finfo(ctx);
	bpf_hash_init(ctx, CONFDIR "/bpf_pinning");

	return 0;
out_free:
	free(ctx->sec_done);
out_elf:
	elf_end(ctx->elf_fd);
out_fd:
	close(ctx->obj_fd);
	return ret;
}

static int bpf_maps_count(struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	int i, count = 0;

	for (i = 0; i < ARRAY_SIZE(ctx->map_fds); i++) {
		if (!ctx->map_fds[i])
			break;
		count++;
	}

	return count;
}

static void bpf_maps_teardown(struct bpf_elf_ctx *ctx)
{
	printf("SLANKDEV: %s\n", __func__);
	int i;

	for (i = 0; i < ARRAY_SIZE(ctx->map_fds); i++) {
		if (ctx->map_fds[i])
			close(ctx->map_fds[i]);
	}

	if (ctx->btf_fd)
		close(ctx->btf_fd);
	free(ctx->btf.types);
}

static struct bpf_elf_ctx __ctx;

static int
bpf_map_set_send(int fd, struct sockaddr_un *addr, unsigned int addr_len,
		 const struct bpf_map_data *aux, unsigned int entries)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_map_set_msg msg = {
		.aux.uds_ver = BPF_SCM_AUX_VER,
		.aux.num_ent = entries,
	};
	int *cmsg_buf, min_fd;
	char *amsg_buf;
	int i;

	strlcpy(msg.aux.obj_name, aux->obj, sizeof(msg.aux.obj_name));
	memcpy(&msg.aux.obj_st, aux->st, sizeof(msg.aux.obj_st));

	cmsg_buf = bpf_map_set_init(&msg, addr, addr_len);
	amsg_buf = (char *)msg.aux.ent;

	for (i = 0; i < entries; i += min_fd) {
		int ret;

		min_fd = min(BPF_SCM_MAX_FDS * 1U, entries - i);
		bpf_map_set_init_single(&msg, min_fd);

		memcpy(cmsg_buf, &aux->fds[i], sizeof(aux->fds[0]) * min_fd);
		memcpy(amsg_buf, &aux->ent[i], sizeof(aux->ent[0]) * min_fd);

		ret = sendmsg(fd, &msg.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;
	}

	return 0;
}

static int
bpf_map_set_recv(int fd, int *fds,  struct bpf_map_aux *aux,
		 unsigned int entries)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_map_set_msg msg;
	int *cmsg_buf, min_fd;
	char *amsg_buf, *mmsg_buf;
	unsigned int needed = 1;
	int i;

	cmsg_buf = bpf_map_set_init(&msg, NULL, 0);
	amsg_buf = (char *)msg.aux.ent;
	mmsg_buf = (char *)&msg.aux;

	for (i = 0; i < min(entries, needed); i += min_fd) {
		struct cmsghdr *cmsg;
		int ret;

		min_fd = min(entries, entries - i);
		bpf_map_set_init_single(&msg, min_fd);

		ret = recvmsg(fd, &msg.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;

		cmsg = CMSG_FIRSTHDR(&msg.hdr);
		if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS)
			return -EINVAL;
		if (msg.hdr.msg_flags & MSG_CTRUNC)
			return -EIO;
		if (msg.aux.uds_ver != BPF_SCM_AUX_VER)
			return -ENOSYS;

		min_fd = (cmsg->cmsg_len - sizeof(*cmsg)) / sizeof(fd);
		if (min_fd > entries || min_fd <= 0)
			return -EINVAL;

		memcpy(&fds[i], cmsg_buf, sizeof(fds[0]) * min_fd);
		memcpy(&aux->ent[i], amsg_buf, sizeof(aux->ent[0]) * min_fd);
		memcpy(aux, mmsg_buf, offsetof(struct bpf_map_aux, ent));

		needed = aux->num_ent;
	}

	return 0;
}

int bpf_send_map_fds(const char *path, const char *obj)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_elf_ctx *ctx = &__ctx;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct bpf_map_data bpf_aux = {
		.fds = ctx->map_fds,
		.ent = ctx->maps,
		.st  = &ctx->stat,
		.obj = obj,
	};
	int fd, ret = -1;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot open socket: %s\n",
			strerror(errno));
		goto out;
	}

	strlcpy(addr.sun_path, path, sizeof(addr.sun_path));

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		fprintf(stderr, "Cannot connect to %s: %s\n",
			path, strerror(errno));
		goto out;
	}

	ret = bpf_map_set_send(fd, &addr, sizeof(addr), &bpf_aux,
			       bpf_maps_count(ctx));
	if (ret < 0)
		fprintf(stderr, "Cannot send fds to %s: %s\n",
			path, strerror(errno));

	bpf_maps_teardown(ctx);
out:
	if (fd >= 0)
		close(fd);
	return ret;
}

int bpf_recv_map_fds(const char *path, int *fds, struct bpf_map_aux *aux,
		     unsigned int entries)
{
	printf("SLANKDEV: %s\n", __func__);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd, ret = -1;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot open socket: %s\n",
			strerror(errno));
		goto out;
	}

	strlcpy(addr.sun_path, path, sizeof(addr.sun_path));

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		fprintf(stderr, "Cannot bind to socket: %s\n",
			strerror(errno));
		goto out;
	}

	ret = bpf_map_set_recv(fd, fds, aux, entries);
	if (ret < 0)
		fprintf(stderr, "Cannot recv fds from %s: %s\n",
			path, strerror(errno));

	unlink(addr.sun_path);

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

/* The following functions are wrapper functions for libbpf code to be
 * compatible with the legacy format. So all the functions have prefix
 * with iproute2_
 */
int iproute2_bpf_elf_ctx_init(struct bpf_cfg_in *cfg)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_elf_ctx *ctx = &__ctx;

	return bpf_elf_ctx_init(ctx, cfg->object, cfg->type, cfg->ifindex, cfg->verbose);
}

int iproute2_bpf_fetch_ancillary(void)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_elf_ctx *ctx = &__ctx;
	struct bpf_elf_sec_data data;
	int i, ret = 0;

	for (i = 1; i < ctx->elf_hdr.e_shnum; i++) {
		ret = bpf_fill_section_data(ctx, i, &data);
		if (ret < 0)
			continue;

		if (data.sec_hdr.sh_type == SHT_PROGBITS &&
		    !strcmp(data.sec_name, ELF_SECTION_MAPS))
			ret = bpf_fetch_maps_begin(ctx, i, &data);
		else if (data.sec_hdr.sh_type == SHT_SYMTAB &&
			 !strcmp(data.sec_name, ".symtab"))
			ret = bpf_fetch_symtab(ctx, i, &data);
		else if (data.sec_hdr.sh_type == SHT_STRTAB &&
			 !strcmp(data.sec_name, ".strtab"))
			ret = bpf_fetch_strtab(ctx, i, &data);
		if (ret < 0) {
			fprintf(stderr, "Error parsing section %d! Perhaps check with readelf -a?\n",
				i);
			return ret;
		}
	}

	if (bpf_has_map_data(ctx)) {
		ret = bpf_fetch_maps_end(ctx);
		if (ret < 0) {
			fprintf(stderr, "Error fixing up map structure, incompatible struct bpf_elf_map used?\n");
			return ret;
		}
	}

	return ret;
}

int iproute2_get_root_path(char *root_path, size_t len)
{
	// printf("SLANKDEV: %s root_path=%s\n", __func__, root_path);
	struct bpf_elf_ctx *ctx = &__ctx;
	int ret = 0;

	snprintf(root_path, len, "%s/%s",
		 bpf_get_work_dir(ctx->type), BPF_DIR_GLOBALS);

	printf("SLANKDEV: %s root_path=%s\n", __func__, root_path);

	ret = mkdir(root_path, S_IRWXU);
	if (ret && errno != EEXIST) {
		fprintf(stderr, "mkdir %s failed: %s\n", root_path, strerror(errno));
		return ret;
	}

	return 0;
}

bool iproute2_is_pin_map(const char *libbpf_map_name, char *pathname)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_elf_ctx *ctx = &__ctx;
	const char *map_name, *tmp;
	unsigned int pinning;
	int i, ret = 0;

	for (i = 0; i < ctx->map_num; i++) {
		if (ctx->maps[i].pinning == PIN_OBJECT_NS &&
		    ctx->noafalg) {
			fprintf(stderr, "Missing kernel AF_ALG support for PIN_OBJECT_NS!\n");
			return false;
		}

		map_name = bpf_map_fetch_name(ctx, i);
		if (!map_name) {
			return false;
		}

		if (strcmp(libbpf_map_name, map_name))
			continue;

		pinning = ctx->maps[i].pinning;

		if (bpf_no_pinning(ctx, pinning) || !bpf_get_work_dir(ctx->type))
			return false;

		if (pinning == PIN_OBJECT_NS)
			ret = bpf_make_obj_path(ctx);
		else if ((tmp = bpf_custom_pinning(ctx, pinning)))
			ret = bpf_make_custom_path(ctx, tmp);
		if (ret < 0)
			return false;

		bpf_make_pathname(pathname, PATH_MAX, map_name, ctx, pinning);

		return true;
	}

	return false;
}

bool iproute2_is_map_in_map(const char *libbpf_map_name, struct bpf_elf_map *imap,
			    struct bpf_elf_map *omap, char *omap_name)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_elf_ctx *ctx = &__ctx;
	const char *inner_map_name, *outer_map_name;
	int i, j;

	for (i = 0; i < ctx->map_num; i++) {
		inner_map_name = bpf_map_fetch_name(ctx, i);
		if (!inner_map_name) {
			return false;
		}

		if (strcmp(libbpf_map_name, inner_map_name))
			continue;

		if (!ctx->maps[i].id ||
		    ctx->maps[i].inner_id)
			continue;

		*imap = ctx->maps[i];

		for (j = 0; j < ctx->map_num; j++) {
			if (!bpf_is_map_in_map_type(&ctx->maps[j]))
				continue;
			if (ctx->maps[j].inner_id != ctx->maps[i].id)
				continue;

			*omap = ctx->maps[j];
			outer_map_name = bpf_map_fetch_name(ctx, j);
			if (!outer_map_name)
				return false;

			memcpy(omap_name, outer_map_name, strlen(outer_map_name) + 1);

			return true;
		}
	}

	return false;
}

int iproute2_find_map_name_by_id(unsigned int map_id, char *name)
{
	printf("SLANKDEV: %s\n", __func__);
	struct bpf_elf_ctx *ctx = &__ctx;
	const char *map_name;
	int i, idx = -1;

	for (i = 0; i < ctx->map_num; i++) {
		if (ctx->maps[i].id == map_id &&
		    ctx->maps[i].type == BPF_MAP_TYPE_PROG_ARRAY) {
			idx = i;
			break;
		}
	}

	if (idx < 0)
		return -1;

	map_name = bpf_map_fetch_name(ctx, idx);
	if (!map_name)
		return -1;

	memcpy(name, map_name, strlen(map_name) + 1);
	return 0;
}
#endif /* HAVE_ELF */
