/*
 * ieit.c
 *
 * This module exports the EFI Image Execution Information Table.  This table
 * is generated during system startup, and contains details of the chain of
 * events that occurred during booting, such as which binaries were executed,
 * what signatures they included, and which db/dbx entries applied to those
 * signatures.
 *
 * Data is currently found below /sys/firmware/efi/ieit/...
 */
#define pr_fmt(fmt) "ieit: " fmt

#include <linux/capability.h>
#include <linux/device.h>
#include <linux/efi.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/ucs2_string.h>

#include <asm/io.h>
#include <asm/early_ioremap.h>

/*
 * These are the structure of the config variable itself
 */
typedef u32 image_execution_action;

/*
 * This is a mask of which bits represent an enum of actions which could be
 * logged.
 */
#define EFI_IMAGE_EXECUTION_AUTHENTICATION 0x00000007

/*
 * These are the actions.
 */
#define EFI_IMAGE_EXECUTION_AUTH_UNTESTED 0x00000000
#define EFI_IMAGE_EXECUTION_AUTH_SIG_FAILED 0x00000001
#define EFI_IMAGE_EXECUTION_AUTH_SIG_PASSED 0x00000002
#define EFI_IMAGE_EXECUTION_AUTH_SIG_NOT_FOUND 0x00000003
#define EFI_IMAGE_EXECUTION_AUTH_SIG_FOUND 0x00000004
#define EFI_IMAGE_EXECUTION_POLICY_FAILED 0x00000005

/*
 * This bit describes whether the image was executed after verification.
 */
#define EFI_IMAGE_EXECUTION_INITIALIZED 0x00000008

struct image_execution_info {
	image_execution_action	action;
	u32			size;
	/*
	 * data is really:
	 *   CHAR16 Name[];
	 *   EFI_DEVICE_PATH_PROTOCOL DevicePath;
	 *   EFI_SIGNATURE_LIST Signature;
	 * All of which are complex data structures.
	 */
	u8			data[];
};

struct image_execution_info_table {
	unsigned long			num_entries;
	struct image_execution_info	info[];
};

/*
 * And now signature lists...
 */
struct efi_sig_list {
	efi_guid_t	signature_type;
	u32		signature_list_size;
	u32		signature_header_size;
	u32		signature_size;
	u8		signatures[];
};

struct efi_sig_data {
	efi_guid_t	signature_owner;
	u8		signature_data[];
};

#define WIN_CERT_TYPE_PKCS_SIGNED_DATA	0x0002
#define WIN_CERT_TYPE_EFI_PKCS115	0x0EF0
#define WIN_CERT_TYPE_EFI_GUID		0x0EF1

struct win_certificate {
	u32		length;
	u16		revision;
	u16		certificate_type;
	u8		data[];
};

struct ieit_entry {
	image_execution_action		action;
	size_t				name_size;
	efi_char16_t			*name;
	size_t				dp_size;
	struct efi_generic_dev_path	*dp;

	bool				has_sig;
	efi_guid_t			sig_type;
	efi_guid_t			sig_owner;
	size_t				sig_data_size;
	u8				*sig_data;

#if 0
	struct bin_attribute		*sig_data_bin_attr;
	struct bin_attribute		*dp_bin_attr;
#endif

	struct kobject			kobj;
	struct list_head		list;
};

static phys_addr_t ieit_data;
static size_t ieit_data_size;

static struct image_execution_info_table *ieit;

/*
 * global list of ieit_entry structs.
 */
static LIST_HEAD(entry_list);

static inline int ieit_exists(void)
{
	if (!efi_enabled(EFI_CONFIG_TABLES))
		return 0;
	if (efi.ieit == EFI_INVALID_TABLE_ADDR)
		return 0;
	return 1;
}

/* entry attribute */
struct iei_attribute {
	struct attribute attr;
	ssize_t (*show)(struct ieit_entry *entry, char *buf);
	ssize_t (*store)(struct ieit_entry *entry,
			 const char *buf, size_t count);
};

static struct ieit_entry *to_entry(struct kobject *kobj)
{
	return container_of(kobj, struct ieit_entry, kobj);
}

static struct iei_attribute *to_attr(struct attribute *attr)
{
	return container_of(attr, struct iei_attribute, attr);
}

static ssize_t iei_attr_show(struct kobject *kobj,
			      struct attribute *_attr, char *buf)
{
	struct ieit_entry *entry = to_entry(kobj);
	struct iei_attribute *attr = to_attr(_attr);

	/* Don't tell normal users what images got loaded. */
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	return attr->show(entry, buf);
}

static const struct sysfs_ops iei_attr_ops = {
	.show = iei_attr_show,
};

/* Generic IEIT Entry ("IEIT") support. */
static const char * const actions[] = {
	"auth-untested",
	"sig-failed",
	"sig-passed",
	"sig-missing",
	"sig-found",
	"policy-failed",
	"invalid-0x00000006",
	"invalid-0x00000007",
	NULL
};

static ssize_t iei_action_show(struct ieit_entry *entry, char *buf)
{
	char *str = buf;

	u32 action = entry->action & EFI_IMAGE_EXECUTION_AUTHENTICATION;

	str += sprintf(str, "%s %s 0x%08x", actions[action],
		       entry->action & EFI_IMAGE_EXECUTION_INITIALIZED
			? "initialized" : "uninitialized",
			entry->action);

	return buf - str;
}

static struct iei_attribute iei_action = __ATTR(action, 0400,
						iei_action_show, NULL);

static ssize_t iei_name_show(struct ieit_entry *entry, char *buf)
{
	char *str = buf;

	str += ucs2_as_utf8(str, entry->name, PAGE_SIZE - 2);
	str += sprintf(str, "\n");

	return str - buf;
}

static struct iei_attribute iei_name = __ATTR(name, 0400,
					      iei_name_show, NULL);

static ssize_t iei_sig_owner_show(struct ieit_entry *entry, char *buf)
{
	char *str = buf;

	if (entry->has_sig != true)
		return -1;

	efi_guid_to_str(&entry->sig_owner, str);
	str += strlen(str);
	str += sprintf(str, "\n");

	return str - buf;
};

static struct iei_attribute iei_sig_owner = __ATTR(signature_owner, 0400,
						   iei_sig_owner_show, NULL);

static ssize_t iei_sig_type_show(struct ieit_entry *entry, char *buf)
{
	char *str = buf;

	if (entry->has_sig != true)
		return -1;

	efi_guid_to_str(&entry->sig_type, str);
	str += strlen(str);
	str += sprintf(str, "\n");

	return str - buf;
};

static struct iei_attribute iei_sig_type = __ATTR(signature_type, 0400,
						  iei_sig_type_show, NULL);

static struct attribute *iei_attrs[] = {
	&iei_action.attr,
	&iei_name.attr,
	&iei_sig_owner.attr,
	&iei_sig_type.attr,
	NULL
};

#if 0
static ssize_t iei_sig_data_read(struct file *file, struct kobject *kobj,
				 struct bin_attribute *attr, char *buf,
				 loff_t off, size_t count)
{
	struct ieit_entry *entry = to_entry(kobj);
	size_t limit = min(entry->sig_data_size - (size_t)off, count);

	memcpy(buf, entry->sig_data + off, limit);
	return limit;
}

static ssize_t iei_dp_read(struct file *file, struct kobject *kobj,
			   struct bin_attribute *attr, char *buf,
			   loff_t off, size_t count)
{
	struct ieit_entry *entry = to_entry(kobj);
	size_t limit = min(entry->dp_size - (size_t)off, count);

	memcpy(buf, entry->dp + off, limit);
	return limit;
}
#endif

static void iei_release(struct kobject *kobj)
{
	struct ieit_entry *entry = to_entry(kobj);

	list_del(&entry->list);
#if 0
	if (entry->sig_data_bin_attr)
		sysfs_remove_bin_file(&entry->kobj, entry->sig_data_bin_attr);
	if (entry->dp_bin_attr)
		sysfs_remove_bin_file(&entry->kobj, entry->dp_bin_attr);
#endif
	kfree(entry->name);
	kfree(entry->dp);
	kfree(entry->sig_data);
	kfree(entry);
}

static struct kobj_type iei_ktype = {
	.release = iei_release,
	.sysfs_ops = &iei_attr_ops,
	.default_attrs = iei_attrs,
};


static struct kobject *ieit_kobj;

static void dump_iei(struct image_execution_info *iei, int entry_num)
{
	unsigned long addr = (unsigned long)iei;
	u8 *array = (u8 *)iei;
	char line[80];
	char *str = line;
	int x, p = 0;
	memset(line, '\0', 80);

	pr_debug("entry%d at %p (%d bytes):\n", entry_num, iei, iei->size);
	str += sprintf(str, "%02x: ", (unsigned int)addr & 0xff);
	for (x = 0; x < addr % 32; x++) {
		str += sprintf(str, "  ");
		if (x == 15) {
			str += sprintf(str, " ");
		}
	}
	while (p < iei->size && p < 200) {
		if (x == 0) {
			str += sprintf(str, "%02x: ",
				       ((unsigned int)addr + p) & 0xff);
		}
		for (; x < 32 && p < iei->size && p < 200; x++, p++) {
			str += sprintf(str, "%02x", array[p]);
			if (x == 15) {
				str += sprintf(str, " ");
			}
		}
		*str = '\0';
		pr_debug("%s\n", line);
		str = line;
		x = 0;
	}
}

static int ieit_create_sysfs_entry(struct image_execution_info *iei,
				   int entry_num)
{
	struct ieit_entry *entry;
	int ret = -ENOMEM;
	size_t minimum = sizeof(iei->action) + sizeof(iei->size)
			  + sizeof(u16) /* minimum name field */
			  + sizeof(struct efi_generic_dev_path); /* minimum device path */
	ssize_t limit;
	int len;
	struct efi_sig_list *esl;

	u8 *addr = (u8 *)iei;
	pr_debug("attempting to add entry%d\n", entry_num);

	if (iei->size < minimum) {
		pr_err("entry%d has invalid size %d; minimum is %zd\n",
		       entry_num, iei->size, minimum);
		return -EINVAL;
	}
	dump_iei(iei, entry_num);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

#if 0
	entry = kzalloc(sizeof(*entry->sig_data_bin_attr), GFP_KERNEL);
	if (!entry)
		goto err_free;

	entry = kzalloc(sizeof(*entry->dp_bin_attr), GFP_KERNEL);
	if (!entry)
		goto err_free;
#endif

	entry->action = iei->action;

	/* compute the address of the "name" field and the limit for it */
	addr += sizeof(iei->action) + sizeof(iei->size);
	limit = iei->size - (sizeof(iei->action) + sizeof(iei->size));

	/* now grab our values */
	len = ucs2_strnlen((ucs2_char_t *)addr, limit / sizeof(efi_char16_t));
	entry->name_size = (len+1) * sizeof(efi_char16_t);
	pr_debug("entry%d name at %p is %zd bytes (%d chars)\n", entry_num,
		 addr, (len+1) * sizeof(efi_char16_t), len);
	if (limit <= entry->name_size) {
		pr_err("entry%d name has impossible size %zd; maximum is %zd\n",
		       entry_num, entry->name_size, limit);
		ret = -EINVAL;
		goto err_free;
	}

	entry->name = kmalloc(entry->name_size, GFP_KERNEL);
	if (!entry->name)
		goto err_free;

	memcpy(entry->name, addr, entry->name_size);
	entry->name[len] = (efi_char16_t)0;

	/* compute the device path address and limit */
	addr += entry->name_size;
	limit -= entry->name_size;

	entry->dp_size = efi_dev_path_size((struct efi_generic_dev_path *)addr,
					   iei->size);
	if (entry->dp_size < 0) {
		pr_err("entry%d device path has invalid size (%zd)\n",
		       entry_num, entry->dp_size);
		ret = -EINVAL;
		goto err_free;
	}
	if (entry->dp_size >= limit) {
		pr_err("entry%d device path is %zd bytes; limit is %zd\n",
		       entry_num, entry->dp_size, limit);
		ret = -EINVAL;
		goto err_free;
	}

	entry->dp = kmalloc(entry->dp_size, GFP_KERNEL);
	if (!entry->dp)
		goto err_free;

	memcpy(entry->dp, addr, entry->dp_size);

	/*
	 * Compute the signature address and limit.  Note that on UEFI builds
	 * before tiano commit 213cc1000e6af3c90aefdef2f0f9d5aa99f758d1 ,
	 * this will not work - the size wrongly omits the size of the
	 * EFI_SIGNATURE_LIST.
	 *
	 * It's also unclear how the signature fields will be formatted.  In
	 * 30.4.2, the spec says:
	 *   The contents of Action for each element are determined by
	 *   comparing that specific element’s Signature (which will contain
	 *   exactly 1 EFI_SIGNATURE_DATA)..."
	 * but then later it says:
	 *   Signature
	 *     Zero or more image signatures. If the image contained no
	 *     signatures, then this field is empty.The type WIN_CERTIFICATE
	 *     is defined in chapter 26.
	 * But it doesn't define what "empty" means - does the structure end
	 * here?  Does it have a EFI_SIGNATURE_LIST with signature owner as
	 * all zeros and nothing else?  Does it have that but also a
	 * EFI_SIGNATURE_DATA with all zeroes as well?  It's also not clear
	 * why it mentions WIN_CERTIFICATE at all.  So that's great.
	 *
	 * Since more than one signature would seem to indicate more than one
	 * entry in the IEIT (that is, if the binary is signed 3 times, it
	 * should have 3 entries, each with one signature), I'm reading that
	 * as saying we can have zero or one signature.  If it's zero, it
	 * might be an EFI_SIGNATURE_LIST with all the sizes as zero, or it
	 * might be the end of the structure.
	 */
	addr += entry->dp_size;
	limit -= entry->dp_size;

	esl = (struct efi_sig_list *)addr;
	if (unlikely(limit == 0)) {
		pr_debug("entry%d has no signature\n", entry_num);
		entry->sig_data_size = 0;
		entry->has_sig = false;
	} else if (unlikely(limit == sizeof(struct efi_sig_list) ||
			    limit == sizeof(struct efi_sig_list)
				     + sizeof(struct efi_sig_data))) {
		pr_debug("entry%d has efi_sig_list with no efi_sig_data\n",
			 entry_num);
		if (esl->signature_list_size != 0) {
			pr_err("entry%d has bad sig list size %d, limit %zd\n",
		       entry_num, esl->signature_list_size, limit);
			ret = -EINVAL;
			goto err_free;
		}
		if (esl->signature_header_size != 0) {
			pr_err("entry%d has bad sig header size %d, limit %zd\n",
			       entry_num, esl->signature_header_size, limit);
			ret = -EINVAL;
			goto err_free;
		}
		if ((limit == sizeof(struct efi_sig_list) &&
		     esl->signature_size != 0) ||
		    esl->signature_size != sizeof(struct efi_sig_data)) {
			pr_err("entry%d has bad sig size %d, limit %zd\n",
			       entry_num, esl->signature_size, limit);
			ret = -EINVAL;
			goto err_free;
		}
		pr_debug("entry%d has no signature\n", entry_num);
		entry->sig_data_size = 0;
		entry->has_sig = false;
	} else if (unlikely(limit < sizeof(struct efi_sig_list)
			    + sizeof(struct efi_sig_data))) {
		pr_err("entry%d sig list cannot fit: minimum size %lu limit %zd\n",
		       entry_num,
		       sizeof(struct efi_sig_list) +sizeof(struct efi_sig_data),
		       limit);
		ret = -EINVAL;
		goto err_free;
	} else {
		/*
		 * limit > sizeof(struct efi_sig_list)
		 *         + sizeof(struct efi_sig_data)
		 */
		struct efi_sig_data *esd;
		size_t computed_size = sizeof(struct efi_sig_list)
				       + sizeof(struct efi_sig_data)
				       + esl->signature_header_size
				       + esl->signature_size;

		printk("ieit: addr: %p computed_size: %zd limit: %zd\n",
		       addr, computed_size, limit);

		if (esl->signature_list_size > limit) {
			pr_err("entry%d sig list size %d, limit %zd\n",
			       entry_num, esl->signature_list_size, limit);
			goto err_free;
		}

		if (computed_size > esl->signature_list_size) {
			pr_err("entry%d sig to big: size %zd, list size %d\n",
				entry_num,
				computed_size, esl->signature_list_size);
			goto err_free;
		}

		if (computed_size < esl->signature_list_size) {
			pr_warn("entry%d has %zd bytes of excess signature space\n",
				entry_num,
				esl->signature_list_size - computed_size);
		}

		addr += sizeof(struct efi_sig_list) + esl->signature_header_size;
		limit -= sizeof(struct efi_sig_list) + esl->signature_header_size;

		esd = (struct efi_sig_data *)addr;

		entry->sig_owner = esd->signature_owner;

		addr += sizeof(struct efi_sig_data);
		limit -= sizeof(struct efi_sig_data);

		if (limit != esl->signature_size) {
			pr_warn("entry%d %u sig bytes expected, buffer is %zd\n",
				entry_num, esl->signature_size, limit);
		}

		entry->sig_data = kmalloc(esl->signature_size, GFP_KERNEL);
		if (!entry->sig_data)
			goto err_free;

		memcpy(entry->sig_data, esd->signature_data,
		       esl->signature_size);
		entry->sig_data_size = esl->signature_size;
	}

	/* so now that we've got all our data, instantiate the kobj */
#if 0
	entry->sig_data_bin_attr->attr.name = "sig_data";
	entry->sig_data_bin_attr->attr.mode = 0400;
	entry->sig_data_bin_attr->read = iei_sig_data_read;
	entry->sig_data_bin_attr->size = entry->sig_data_size;
	entry->sig_data_bin_attr->private = entry;
	sysfs_bin_attr_init(entry->sig_data_bin_attr);

	entry->dp_bin_attr->attr.name = "dp";
	entry->dp_bin_attr->attr.mode = 0400;
	entry->dp_bin_attr->read = iei_dp_read;
	entry->dp_bin_attr->size = entry->dp_size;
	entry->dp_bin_attr->private = entry;
	sysfs_bin_attr_init(entry->dp_bin_attr);
#endif

	entry->kobj.kset = ieit_kobj->kset;

	ret = kobject_init_and_add(&entry->kobj, &iei_ktype, ieit_kobj,
				   "entry%d", entry_num);
	if (ret < 0)
		goto err_free;

#if 0
	ret = sysfs_create_bin_file(&entry->kobj, entry->sig_data_bin_attr);
	if (ret < 0)
		goto err_kobject;

	ret = sysfs_create_bin_file(&entry->kobj, entry->dp_bin_attr);
	if (ret < 0)
		goto err_kobject;
#endif

	list_add_tail(&entry->list, &entry_list);
	return 0;
#if 0
err_kobject:
	kobject_put(&entry->kobj);
	return ret;
#endif
err_free:
	kfree(entry->name);
	kfree(entry->dp);
	kfree(entry->sig_data);
#if 0
	kfree(entry->dp_bin_attr);
	entry->dp_bin_attr = NULL;
	kfree(entry->sig_data_bin_attr);
	entry->sig_data_bin_attr = NULL;
#endif
	kfree(entry);
	return ret;
}

static umode_t ieit_attr_is_visible(struct kobject *kobj,
				    struct attribute *attr, int n)
{
	if (!ieit_exists())
		return 0;
	return attr->mode;
}

static struct attribute *ieit_attrs[] = {
	NULL,
};

static struct attribute_group ieit_attr_group = {
	.is_visible = ieit_attr_is_visible,
	.attrs = ieit_attrs,
};

/*
 * remap the table, copy it to kmalloced pages, and unmap it.
 */
void __init efi_ieit_init(void)
{
	void *va;
	struct image_execution_info_table tmpieit;
	efi_memory_desc_t md;
	unsigned long num_entries;
	unsigned int i;
	size_t min_entry_size = sizeof(struct image_execution_info) +
				sizeof(efi_char16_t) +
				sizeof(struct efi_generic_dev_path);
	size_t size, max;
	size_t entries_size;
	int rc;
	phys_addr_t end;

	pr_debug("loading.\n");
	if (!ieit_exists())
		return;

	rc = efi_mem_desc_lookup(efi.ieit, &md);
	if (rc < 0) {
		pr_err("IEIT header is not in the memory map.\n");
		return;
	}

	max = efi_mem_desc_end(&md);
	if (max < efi.ieit) {
		pr_err("EFI memory descriptor is invalid. (ieit: %p max: %p)\n",
		       (void *)efi.ieit, (void *)max);
		return;
	}

	size = sizeof(*ieit);
	max -= efi.ieit;

	if (max < size) {
		pr_err("IEIT header doen't fit on single memory map entry. (size: %zu max: %zu)\n",
		       size, max);
		return;
	}

	ieit_data_size = size;
	pr_debug("mapping (%p, %zu) for table header\n", (void *)efi.ieit, ieit_data_size);
	va = early_memremap(efi.ieit, ieit_data_size);
	if (!va) {
		pr_err("early_memremap(%p, %zu) failed.\n", (void *)efi.ieit,
		       size);
		return;
	}

	memcpy(&tmpieit, va, sizeof(tmpieit));
	num_entries = tmpieit.num_entries;

	pr_info("IEIT claims to have %lu entries\n", num_entries);
	if (max < size + min_entry_size * num_entries) {
		pr_err("IEIT memory cannot hold %lu entries\n",
		       num_entries);
		goto err_memunmap;
	}

	entries_size = 0;
	for (i = 0; i < num_entries; i++) {
		struct image_execution_info tmpentry;

		/* check and be sure the minimal (empty) entry can fit */
		if (size + entries_size + min_entry_size > max) {
			pr_err("IEIT memory cannot hold IEIT entry %d\n", i);
			goto err_memunmap;
		}
		/* and map it enough to get the size */
		ieit_data_size = size + entries_size + min_entry_size;
		pr_debug("mapping (%p, %zu) for entry %d\n", (void *)efi.ieit, ieit_data_size, i);
		va = early_memremap(efi.ieit, ieit_data_size);
		if (!va) {
			pr_err("early_memremap(%p, %zu) failed.\n",
			       (void *)efi.ieit, ieit_data_size);
			return;
		}

		/* grab a copy of it so we're not mucking in iomem */
		memcpy(&tmpentry, va
				  + sizeof(struct image_execution_info_table)
				  + entries_size, sizeof(tmpentry));

		/* check and be sure the whole entry can fit */
		if (size + entries_size + tmpentry.size > max) {
			pr_err("IEIT entry %d has unreasonable size %d\n", i,
			       tmpentry.size);
			goto err_memunmap;
		}
		/* and then change our map to include the whole entry */
		entries_size += tmpentry.size;
		ieit_data_size = size + entries_size;
		pr_debug("remapping (%p, %zu) for entry %d\n", (void *)efi.ieit, ieit_data_size, i);
		va = early_memremap(efi.ieit, ieit_data_size);
		if (!va) {
			pr_err("early_memremap(%p, %zu) failed.\n",
			       (void *)efi.ieit, ieit_data_size);
			return;
		}
	}

	ieit_data = (phys_addr_t)efi.ieit;
	end = ieit_data + ieit_data_size;
	pr_info("Reserving IEIT space from %pa to %pa.\n", &ieit_data, &end);
	memblock_reserve(ieit_data, ieit_data_size);

	pr_debug("loaded.\n");
err_memunmap:
	pr_debug("unmapping (%p, %zu)\n", (void *)efi.ieit, ieit_data_size);
	early_memunmap(va, ieit_data_size);
}

static int __init register_entries(void)
{
	int i = 0;

	if (!ieit_exists())
		return 0;

	for (i = 0; i < le32_to_cpu(ieit->num_entries); i++) {
		int rc = ieit_create_sysfs_entry(&ieit->info[i], i);

		if (rc < 0) {
			pr_err("IEIT entry creation failed with error %d.\n",
			       rc);
			return rc;
		}
	}
	return 0;
}

static void cleanup_entry_list(void)
{
	struct ieit_entry *entry, *next;

	list_for_each_entry_safe(entry, next, &entry_list, list) {
		kobject_put(&entry->kobj);
	}
}

static int __init ieit_sysfs_init(void)
{
	int error;
	struct image_execution_info_table __iomem *ioieit;

	pr_debug("sysfs loading.\n");
	if (!ieit_data || !ieit_data_size)
		return -ENODEV;

	pr_debug("mapping (%pa, %zu)\n", &ieit_data, ieit_data_size);
	ioieit = ioremap(ieit_data, ieit_data_size);
	if (!ioieit) {
		pr_err("ioremap(%pa, %zu) failed.\n", &ieit_data,
		       ieit_data_size);
		return -ENOMEM;
	}

	ieit = kmalloc(ieit_data_size, GFP_KERNEL);
	if (!ieit) {
		iounmap(ioieit);
		return -ENOMEM;
	}

	memcpy_fromio(ieit, ioieit, ieit_data_size);

	ieit_kobj = kobject_create_and_add("ieit", efi_kobj);
	if (!ieit_kobj) {
		pr_err("Firmware table registration failed.\n");
		error = -ENOMEM;
		goto err;
	}

	error = sysfs_create_group(ieit_kobj, &ieit_attr_group);
	if (error) {
		pr_err("Sysfs attribute export failed with error %d.\n",
		       error);
		goto err_remove_ieit;
	}

	error = register_entries();
	if (error)
		goto err_cleanup_list;

	memblock_remove(ieit_data, ieit_data_size);

	pr_debug("ieit-sysfs: loaded.\n");

	return 0;
err_cleanup_list:
	cleanup_entry_list();
	sysfs_remove_group(ieit_kobj, &ieit_attr_group);
err_remove_ieit:
	kobject_put(ieit_kobj);
err:
	kfree(ieit);
	ieit = NULL;
	return error;
}
device_initcall(ieit_sysfs_init);

/*
 * MODULE_AUTHOR("Peter Jones <pjones@redhat.com>");
 * MODULE_DESCRIPTION("EFI Image Execution Information Table support");
 * MODULE_LICENSE("GPL");
 */
