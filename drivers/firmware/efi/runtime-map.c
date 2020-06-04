// SPDX-License-Identifier: GPL-2.0
/*
 * linux/drivers/efi/runtime-map.c
 * Copyright (C) 2013 Red Hat, Inc., Dave Young <dyoung@redhat.com>
 */

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/efi.h>
#include <linux/slab.h>

#include <asm/setup.h>

struct efi_runtime_map_entry {
	efi_memory_desc_t md;
	u64 perms;
	struct kobject kobj;   /* kobject for each entry */
};

static struct efi_runtime_map_entry **map_entries;

struct map_attribute {
	struct attribute attr;
	ssize_t (*show)(struct efi_runtime_map_entry *entry, char *buf);
};

static inline struct map_attribute *to_map_attr(struct attribute *attr)
{
	return container_of(attr, struct map_attribute, attr);
}

static ssize_t type_show(struct efi_runtime_map_entry *entry, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "0x%x\n", entry->md.type);
}

static ssize_t perms_show(struct efi_runtime_map_entry *entry, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "0x%llx\n", entry->perms);
}

#define EFI_RUNTIME_FIELD(var) entry->md.var

#define EFI_RUNTIME_U64_ATTR_SHOW(name) \
static ssize_t name##_show(struct efi_runtime_map_entry *entry, char *buf) \
{ \
	return snprintf(buf, PAGE_SIZE, "0x%llx\n", EFI_RUNTIME_FIELD(name)); \
}

EFI_RUNTIME_U64_ATTR_SHOW(phys_addr);
EFI_RUNTIME_U64_ATTR_SHOW(virt_addr);
EFI_RUNTIME_U64_ATTR_SHOW(num_pages);
EFI_RUNTIME_U64_ATTR_SHOW(attribute);

static inline struct efi_runtime_map_entry *to_map_entry(struct kobject *kobj)
{
	return container_of(kobj, struct efi_runtime_map_entry, kobj);
}

static ssize_t map_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct efi_runtime_map_entry *entry = to_map_entry(kobj);
	struct map_attribute *map_attr = to_map_attr(attr);

	return map_attr->show(entry, buf);
}

static struct map_attribute map_type_attr = __ATTR_RO_MODE(type, 0400);
static struct map_attribute map_phys_addr_attr = __ATTR_RO_MODE(phys_addr, 0400);
static struct map_attribute map_virt_addr_attr = __ATTR_RO_MODE(virt_addr, 0400);
static struct map_attribute map_num_pages_attr = __ATTR_RO_MODE(num_pages, 0400);
static struct map_attribute map_attribute_attr = __ATTR_RO_MODE(attribute, 0400);
static struct map_attribute map_perms_attr = __ATTR_RO_MODE(perms, 0400);

/*
 * These are default attributes that are added for every memmap entry.
 */
static struct attribute *def_attrs[] = {
	&map_type_attr.attr,
	&map_phys_addr_attr.attr,
	&map_virt_addr_attr.attr,
	&map_num_pages_attr.attr,
	&map_attribute_attr.attr,
	&map_perms_attr.attr,
	NULL
};

static const struct sysfs_ops map_attr_ops = {
	.show = map_attr_show,
};

static void map_release(struct kobject *kobj)
{
	struct efi_runtime_map_entry *entry;

	entry = to_map_entry(kobj);
	kfree(entry);
}

static struct kobj_type __refdata map_ktype = {
	.sysfs_ops	= &map_attr_ops,
	.default_attrs	= def_attrs,
	.release	= map_release,
};

static struct kset *map_kset;

static struct efi_runtime_map_entry *
add_sysfs_runtime_map_entry(struct kobject *kobj, int nr,
			    const efi_memory_desc_t *md,
			    const efi_memory_desc_t *matd)
{
	int ret;
	struct efi_runtime_map_entry *entry;

	if (!map_kset) {
		map_kset = kset_create_and_add("runtime-map", NULL, kobj);
		if (!map_kset)
			return ERR_PTR(-ENOMEM);
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		kset_unregister(map_kset);
		map_kset = NULL;
		return ERR_PTR(-ENOMEM);
	}

	memcpy(&entry->md, md, sizeof(efi_memory_desc_t));
	entry->perms = matd->attribute;

	kobject_init(&entry->kobj, &map_ktype);
	entry->kobj.kset = map_kset;
	ret = kobject_add(&entry->kobj, NULL, "%d", nr);
	if (ret) {
		kobject_put(&entry->kobj);
		kset_unregister(map_kset);
		map_kset = NULL;
		return ERR_PTR(ret);
	}

	return entry;
}

int efi_get_runtime_map_size(void)
{
	return efi.memmap.nr_map * efi.memmap.desc_size;
}

int efi_get_runtime_map_desc_size(void)
{
	return efi.memmap.desc_size;
}

int efi_runtime_map_copy(void *buf, size_t bufsz)
{
	size_t sz = efi_get_runtime_map_size();

	if (sz > bufsz)
		sz = bufsz;

	memcpy(buf, efi.memmap.map, sz);
	return 0;
}

static int __init count_memattr_entries(const efi_memory_desc_t *matd,
					const efi_memory_desc_t *md,
					void *state)
{
	struct range range;
	int *nr_map = (int *)state;

	range.start = matd->phys_addr;
	range.end = range.start + (matd->num_pages << EFI_PAGE_SHIFT) - 1;

	*nr_map += efi_memmap_split_count(md, &range);
	return 0;
}

static int __init add_runtime_map_entries(const efi_memory_desc_t *matd,
					  const efi_memory_desc_t *md,
					  void *state)
{
	int *i = (int *)state;
	struct efi_runtime_map_entry *entry;

	entry = add_sysfs_runtime_map_entry(efi_kobj, *i, md, matd);
	if (IS_ERR(entry))
		return PTR_ERR(entry);
	map_entries[(*i)++] = entry;
	return 0;
}

int __init efi_runtime_map_init(struct kobject *efi_kobj)
{
	struct efi_runtime_map_entry *entry;
	int i = 0, j, ret = 0;
	int nr_map = 0;

	if (!efi_enabled(EFI_MEMMAP))
		return 0;

	efi_memattr_visit_valid(count_memattr_entries, &nr_map);

	map_entries = kcalloc(nr_map, sizeof(*entry), GFP_KERNEL);
	if (!map_entries) {
		ret = -ENOMEM;
		goto out;
	}

	ret = efi_memattr_visit_valid(add_runtime_map_entries, &i);
	if (ret == 0)
		return 0;

	for (j = i - 1; j >= 0; j--) {
		entry = map_entries[j];
		kobject_put(&entry->kobj);
	}
out:
	return ret;
}
