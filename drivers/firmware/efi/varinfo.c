// SPDX-License-Identifier: GPL-2.0-only
/*
 * varinfo.c - Provide information about EFI variable storage
 *
 * Copyright 2019 Peter Jones <pjones@redhat.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/efi.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/ucs2_string.h>

static struct ratelimit_state ratelimit;

static const char * const names[] = {
	"bs",
	"rt",
	"bs_rt",
	"bs_nv",
	"rt_nv",
	"bs_rt_nv",
	NULL,
};

static struct efi_varinfo_table rt_table = {
	.info = {
		[efi_varinfo_attrs_bs] = {
			.attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS,
		},
		[efi_varinfo_attrs_rt] = {
			.attrs = EFI_VARIABLE_RUNTIME_ACCESS,
		},
		[efi_varinfo_attrs_bs_rt] = {
			.attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS
				 | EFI_VARIABLE_RUNTIME_ACCESS,
		},
		[efi_varinfo_attrs_bs_nv] = {
			.attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS
				 | EFI_VARIABLE_NON_VOLATILE,
		},
		[efi_varinfo_attrs_rt_nv] = {
			.attrs = EFI_VARIABLE_RUNTIME_ACCESS
				 | EFI_VARIABLE_NON_VOLATILE,
		},
		[efi_varinfo_attrs_bs_rt_nv] = {
			.attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS
				 | EFI_VARIABLE_RUNTIME_ACCESS
				 | EFI_VARIABLE_NON_VOLATILE,
		},
	}
};

static inline struct efi_varinfo_table *map_bstable(void)
{
	struct efi_varinfo_table *table;

	if (!efi.variable_info)
		return NULL;

	table = memremap(efi.variable_info, sizeof(*table), MEMREMAP_WB);
	if (table == NULL) {
		pr_err("memremap(%pa, %zu) failed.\n",
		       (void *)efi.variable_info, sizeof(*table));
		return NULL;
	}

	return table;
}

static inline struct efi_varinfo *map_bsinfo(void)
{
	struct efi_varinfo_table *table;

	table = map_bstable();
	if (table)
		return &table->info[0];

	return NULL;
}

static inline void unmap_bsinfo(struct efi_varinfo *bsinfo)
{
	struct efi_variable_info_table *table;

	/*
	 * strictly probably not needed, but I've changed the layout a couple
	 * of times and it keeps working...
	 */
	table = (void *)((uintptr_t)bsinfo
			 - offsetof(struct efi_varinfo_table, info));

	memunmap(table);
}

static const char * const name(struct efi_varinfo *needle)
{
	unsigned int i;
	struct efi_varinfo *rtinfo = &rt_table.info[0];

	for (i = efi_varinfo_attrs_bs; i < efi_varinfo_attrs_max; i++)
		if (&rtinfo[i] == needle)
			return names[i];

	return NULL;
}

static inline bool is_rtinfo(struct efi_varinfo *needle)
{
	unsigned int i;
	struct efi_varinfo *rtinfo = &rt_table.info[0];

	for (i = efi_varinfo_attrs_bs; i < efi_varinfo_attrs_max; i++)
		if (&rtinfo[i] == needle)
			return true;

	return false;
};

static void query_info(struct efi_varinfo *info)
{
	info->status = efi.query_variable_info(info->attrs, &info->maxstor,
					       &info->remstor, &info->maxvar);
	if (info->status != EFI_SUCCESS) {
		pr_err("%s QueryVariableInfo(%s): %pe\n",
		       is_rtinfo(info) ? "runtime" : "preboot",
		       name(info), &info->status);
		info->maxstor = info->remstor = info->maxvar = ~0;
	}

	return;
}

static struct efi_varinfo_table *to_table(struct kobject *kobj)
{
	return container_of(kobj, struct efi_varinfo_table, kobj);
}

static ssize_t efi_varinfo_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct efi_varinfo_table *table;
	struct efi_varinfo *info;
	unsigned int i;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	table = to_table(kobj);

	for (i = efi_varinfo_attrs_bs; i < efi_varinfo_attrs_max; i++)
		if (!strcmp(attr->attr.name, names[i]))
			break;
	if (i == efi_varinfo_attrs_max)
		return -EINVAL;

	info = &table->info[i];

	if (table == &rt_table) {
		while (!__ratelimit(&ratelimit)) {
			if (!msleep_interruptible(50))
				return -EINTR;
		}

		query_info(info);
	}

	return sprintf(buf, "max storage:%llu\nfree storage:%llu\nmax variable:%llu\n",
		       info->maxstor, info->remstor, info->maxvar);
}
#define efi_varinfo_attr_decl(name) \
static struct kobj_attribute efi_varinfo_##name = \
	__ATTR(name, 0400, efi_varinfo_show, NULL); \

efi_varinfo_attr_decl(bs);
efi_varinfo_attr_decl(bs_nv);
efi_varinfo_attr_decl(rt);
efi_varinfo_attr_decl(rt_nv);
efi_varinfo_attr_decl(bs_rt);
efi_varinfo_attr_decl(bs_rt_nv);

static struct attribute *efi_varinfo_attrs[] = {
	&efi_varinfo_bs.attr,
	&efi_varinfo_bs_nv.attr,
	&efi_varinfo_rt.attr,
	&efi_varinfo_rt_nv.attr,
	&efi_varinfo_bs_rt.attr,
	&efi_varinfo_bs_rt_nv.attr,
	NULL,
};

static struct attribute_group efi_varinfo_attr_group = {
	.attrs = efi_varinfo_attrs,
};

static struct kobject *efi_varinfo_kobj,
		      *efi_varinfo_bs_kobj,
		      *efi_varinfo_rt_kobj;

void efi_update_varinfo(void)
{
	unsigned int i;

	for (i = efi_varinfo_attrs_bs; i < efi_varinfo_attrs_max; i++)
		query_info(&rt_table.info[i]);
}

static int __init create_varinfo_dir(const char * const name,
				     struct efi_varinfo_table *table,
				     struct kobject **kobj,
				     struct kobject *parent)
{
	int error = 0;
	unsigned int i;

	*kobj = kobject_create_and_add(name, parent);
	if (!*kobj) {
		pr_err("Failed to create %s kobject.\n", name);
		return -ENOMEM;
	}

	error = sysfs_create_group(*kobj, &efi_varinfo_attr_group);
	if (error) {
		pr_err("creating %s attribute group failed: %d\n", name, error);
		kobject_put(*kobj);
		*kobj = NULL;
		return error;
	}

	for (i = efi_varinfo_attrs_bs; i < efi_varinfo_attrs_max; i++) {
		if (table->info[i].status != EFI_SUCCESS)
			pr_info("%s %s max storage:0x%08llx free storage:0x%08llx max variable:0x%08llx\n",
				name, names[i], table->info[i].maxstor,
				table->info[i].remstor, table->info[i].maxvar);
	}

	return 0;
}

static int __init efi_varinfo_init(void)
{
	struct efi_varinfo_table *bs_table;
	int error = 0;

	ratelimit_state_init(&ratelimit, HZ, 100);
	ratelimit_set_flags(&ratelimit, RATELIMIT_MSG_ON_RELEASE);

	efi_varinfo_kobj = kobject_create_and_add("variable-info",
						  efi_kobj);
	if (!efi_varinfo_kobj) {
		pr_err("kobj creation failed.\n");
		return -ENOMEM;
	}

	bs_table = map_bstable();

	if (bs_table) {
		error = create_varinfo_dir("preboot", bs_table,
					   &efi_varinfo_bs_kobj,
					   efi_varinfo_kobj);
		if (error) {
			kobject_put(efi_varinfo_kobj);
			goto err;
		}
	}

	if (efi_enabled(EFI_RUNTIME_SERVICES)) {
		efi_update_varinfo();

		error = create_varinfo_dir("runtime", &rt_table,
					   &efi_varinfo_rt_kobj,
					   efi_varinfo_kobj);
		/*
		 * If creating the boot services entries /worked/, we should
		 * at least leave them around for reference, so don't _put()
		 * the kobj in this case.
		 */
		if (error)
			goto err;
	}

err:
	unmap_bsinfo(&bs_table->info[0]);

	return 0;
}
device_initcall(efi_varinfo_init);

#define EFI_VARIABLE_ATTRIBUTE_MASK (EFI_VARIABLE_BOOTSERVICE_ACCESS | \
				     EFI_VARIABLE_RUNTIME_ACCESS | \
				     EFI_VARIABLE_NON_VOLATILE)

void efi_log_set_variable_failure(const efi_char16_t *name,
				  efi_guid_t *guid, u32 attrs,
				  unsigned long datasize,
				  efi_status_t status)
{
	char *attrstr = NULL;
	unsigned int i = efi_varinfo_attrs_max;
	struct efi_varinfo *bsinfo;

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return;

	if ((attrs & EFI_VARIABLE_ATTRIBUTE_MASK) &&
	    !(attrs & ~EFI_VARIABLE_ATTRIBUTE_MASK)) {
		u32 masked = attrs & EFI_VARIABLE_ATTRIBUTE_MASK;

		attrs &= EFI_VARIABLE_ATTRIBUTE_MASK;
		for (i = efi_varinfo_attrs_bs; i < efi_varinfo_attrs_max; i++)
			if (masked == rt_table.info[i].attrs)
				break;

		if (i != efi_varinfo_attrs_max)
			attrstr = kstrdup(names[i], GFP_KERNEL);
	}
	if (!attrstr) {
		attrstr = kstrdup("0x0123456789abcdef", GFP_KERNEL);
		if (!attrstr) {
			kfree(name);
			pr_err("memory allocation failure\n");
			return;
		}
		sprintf(attrstr, "0x%08x", attrs);
	}

	bsinfo = map_bsinfo();

	pr_err("EFI SetVariable(%pu-%pU, %s, datasize=0x%08lx) = %pe\n",
	       name, guid, attrstr, datasize, &status);
	if (i != efi_varinfo_attrs_max) {
		if (bsinfo)
			pr_err("bs max storage:0x%08llx free storage:0x%08llx max variable:0x%08llx\n",
			       bsinfo[i].maxstor,
			       bsinfo[i].remstor,
			       bsinfo[i].maxvar);
		pr_err("rt max storage:0x%08llx free storage:0x%08llx max variable:0x%08llx\n",
		       rt_table.info[i].maxstor,
		       rt_table.info[i].remstor,
		       rt_table.info[i].maxvar);
	}

	unmap_bsinfo(bsinfo);

	kfree(name);
	kfree(attrstr);
}

/*
 * MODULE_AUTHOR("Peter Jones <pjones@redhat.com>");
 * MODULE_DESCRIPTION("EFI Variable Error Reporting");
 * MODULE_LICENSE("GPL");
 */
