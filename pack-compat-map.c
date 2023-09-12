#include "git-compat-util.h"
#include "gettext.h"
#include "hex.h"
#include "hash-ll.h"
#include "hash.h"
#include "object-store.h"
#include "object-file.h"
#include "packfile.h"
#include "pack-compat-map.h"
#include "packfile.h"

struct pack_compat_map_header {
	uint8_t sig[4];
	uint8_t version;
	uint8_t first_oid_version;
	uint8_t second_oid_version;
	uint8_t mbz1;
	uint32_t nr_objects;
	uint8_t first_abbrev_len;
	uint8_t mbz2;
	uint8_t second_abbrev_len;
	uint8_t mbz3;
};

static char *pack_compat_map_filename(struct packed_git *p)
{
	size_t len;
	if (!strip_suffix(p->pack_name, ".pack", &len))
		BUG("pack_name does not end in .pack");
	return xstrfmt("%.*s.compat", (int)len, p->pack_name);
}

static int oid_version_match(const char *filename,
			     unsigned oid_version,
			     const struct git_hash_algo *algo)
{
	const struct git_hash_algo *found = NULL;
	int ret = 0;

	if (oid_version == 1) {
		found = &hash_algos[GIT_HASH_SHA1];
	} else if (oid_version == 2) {
		found = &hash_algos[GIT_HASH_SHA256];
	}
	if (found == NULL) {
		ret = error(_("compat map file %s hash version %u unknown"),
			    filename, oid_version);
	}
	else if (found != algo) {
		ret = error(_("compat map file %s found hash %s expected hash %s"),
			    filename, found->name, algo->name);
	}
	return ret;
}


static int load_pack_compat_map_file(char *compat_map_file,
				     struct repository *repo,
				     struct packed_git *p)
{
	const struct pack_compat_map_header *hdr;
	unsigned compat_map_objects = 0;
	const uint8_t *data = NULL;
	const uint8_t *packs_hash = NULL;
	int fd, ret = 0;
	struct stat st;
	size_t size, map1sz, map2sz, expected_size;

	fd = git_open(compat_map_file);

	if (fd < 0) {
		ret = -1;
		goto cleanup;
	}
	if (fstat(fd, &st)) {
		ret = error_errno(_("failed to read %s"), compat_map_file);
		goto cleanup;
	}

	size = xsize_t(st.st_size);

	if (size < sizeof(struct pack_compat_map_header)) {
		ret = error(_("compat map file %s is too small"), compat_map_file);
		goto cleanup;
	}

	data = xmmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);

	hdr = (const struct pack_compat_map_header *)data;
	if ((hdr->sig[0] != 'C') ||
	    (hdr->sig[1] != 'M') ||
	    (hdr->sig[2] != 'A') ||
	    (hdr->sig[3] != 'P')) {
		ret = error(_("compat map file %s has unknown signature"),
			    compat_map_file);
		goto cleanup;
	}

	if (hdr->version != 1) {
		ret = error(_("compat map file %s has unsupported version %"PRIu8),
			    compat_map_file, hdr->version);
		goto cleanup;
	}

	ret = oid_version_match(compat_map_file, hdr->first_oid_version, repo->hash_algo);
	if (ret)
		goto cleanup;
	ret = oid_version_match(compat_map_file, hdr->second_oid_version, repo->compat_hash_algo);
	if (ret)
		goto cleanup;
	compat_map_objects = ntohl(hdr->nr_objects);
	if (compat_map_objects != p->num_objects) {
		ret = error(_("compat map file %s number of objects found %u wanted %u"),
			    compat_map_file, compat_map_objects, p->num_objects);
		goto cleanup;
	}

	map1sz = st_mult(repo->hash_algo->rawsz + 4, compat_map_objects);
	map2sz = st_mult(repo->compat_hash_algo->rawsz + 4, compat_map_objects);

	expected_size = sizeof(struct pack_compat_map_header);
	expected_size = st_add(expected_size, map1sz);
	expected_size = st_add(expected_size, map2sz);
	expected_size = st_add(expected_size, 2 * repo->hash_algo->rawsz);

	if (size != expected_size) {
		ret = error(_("compat map file %s is corrupt size %zu expected %zu objects %u sz1 %zu sz2 %zu"),
			    compat_map_file, size, expected_size, compat_map_objects,
			    map1sz, map2sz
			);
		goto cleanup;
	}

	packs_hash = data + sizeof(struct pack_compat_map_header) + map1sz + map2sz;
	if (hashcmp(packs_hash, p->hash)) {
		ret = error(_("compat map file %s does not match pack %s\n"),
			      compat_map_file, hash_to_hex(p->hash));
	}


	p->compat_mapping = data;
	p->compat_mapping_size = size;

	p->hash_map = data + sizeof(struct pack_compat_map_header);
	p->compat_hash_map = p->hash_map + map1sz;

cleanup:
	if (ret) {
		if (data) {
			munmap((void *)data, size);
		}
	}
	if (fd >= 0)
		close(fd);
	return ret;
}

int load_pack_compat_map(struct repository *repo, struct packed_git *p)
{
	char *compat_map_name = NULL;
	int ret = 0;

	if (p->compat_mapping)
		return ret;	/* already loaded */

	if (!repo->compat_hash_algo)
		return 1;		/* Nothing to do */

	ret = open_pack_index(p);
	if (ret < 0)
		goto cleanup;

	compat_map_name = pack_compat_map_filename(p);
	ret = load_pack_compat_map_file(compat_map_name, repo, p);
cleanup:
	free(compat_map_name);
	return ret;
}

static int keycmp(const unsigned char *a, const unsigned char *b,
		  size_t key_hex_size)
{
	size_t key_byte_size = key_hex_size / 2;
	unsigned a_last, b_last, mask = (key_hex_size & 1) ? 0xf0 : 0;
	int cmp = memcmp(a, b, key_byte_size);
	if (cmp)
		return cmp;

	a_last = a[key_byte_size] & mask;
	b_last = b[key_byte_size] & mask;

	if (a_last == b_last)
		cmp = 0;
	else if (a_last < b_last)
		cmp = -1;
	else
		cmp = 1;

	return cmp;
}

static const uint8_t *bsearch_map(const unsigned char *hash,
				  const uint8_t *table, unsigned nr,
				  size_t entry_size, size_t key_hex_size)
{
	uint32_t hi, lo;

	hi = nr - 1;
	lo = 0;
	while (lo < hi) {
		unsigned mi = lo + ((hi - lo) / 2);
		const unsigned char *entry = table + (mi * entry_size);
		int cmp = keycmp(entry, hash, key_hex_size);
		if (!cmp)
			return entry;
		if (cmp > 0)
			hi = mi;
		else
			lo = mi + 1;
	}
	if (lo == hi) {
		const unsigned char *entry = table + (lo * entry_size);
		int cmp = keycmp(entry, hash, key_hex_size);
		if (!cmp)
			return entry;
	}
	return NULL;
}

static void map_each(const struct git_hash_algo *compat,
		     const unsigned char *prefix, size_t prefix_hexsz,
		     const uint8_t *table, unsigned nr, size_t entry_bytes,
		     compat_map_iter_t iter, void *data)
{
	const uint8_t *found, *last = table + (entry_bytes * nr);

	found = bsearch_map(prefix, table, nr, entry_bytes, prefix_hexsz);
	if (!found)
		return;

	/* Visit each matching key */
	do {
		struct object_id oid;

		if (keycmp(found, prefix, prefix_hexsz) != 0)
			break;

		oidread_algop(&oid, found, compat);
		if (iter(&oid, data) == CB_BREAK)
			break;

		found = found + entry_bytes;
	} while (found < last);
}

void pack_compat_map_each(struct repository *repo, struct packed_git *p,
			 const unsigned char *prefix, size_t prefix_hexsz,
			 compat_map_iter_t iter, void *data)
{
	const struct git_hash_algo *compat = repo->compat_hash_algo;

	if (!p->num_objects ||
	    (!p->compat_mapping && load_pack_compat_map(repo, p)))
		return;

	if (prefix_hexsz > compat->hexsz)
		prefix_hexsz = compat->hexsz;

	map_each(compat, prefix, prefix_hexsz,
		 p->compat_hash_map, p->num_objects, compat->rawsz + 4,
		 iter, data);
}

static int compat_map_to_algop(const struct object_id *src,
			       const struct git_hash_algo *to,
			       const struct git_hash_algo *from,
			       const uint8_t *to_table,
			       const uint8_t *from_table,
			       unsigned nr,
			       struct object_id *dest)
{
	const uint8_t *found;
	uint32_t index;

	if (src->algo != hash_algo_by_ptr(from))
		return -1;

	found = bsearch_map(src->hash,
			    from_table, nr,
			    from->rawsz + 4,
			    from->hexsz);
	if (!found)
		return -1;

	index = ntohl(*(uint32_t *)(found + from->rawsz));
	oidread_algop(dest, to_table + index * (to->rawsz + 4), to);
	return 0;
}

static int pack_to_algop(struct repository *repo, struct packed_git *p,
			 const struct object_id *src,
			 const struct git_hash_algo *to, struct object_id *dest)
{
	if (!p->compat_mapping && load_pack_compat_map(repo, p))
		return -1;

	if (to == repo->hash_algo) {
		return compat_map_to_algop(src, to, repo->compat_hash_algo,
					   p->hash_map,
					   p->compat_hash_map,
					   p->num_objects, dest);
	}
	else if (to == repo->compat_hash_algo) {
		return compat_map_to_algop(src, to, repo->hash_algo,
					   p->compat_hash_map,
					   p->hash_map,
					   p->num_objects, dest);
	}
	else
		return -1;
}

int repo_packed_oid_to_algop(struct repository *repo,
			     const struct object_id *src,
			     const struct git_hash_algo *to,
			     struct object_id *dest)
{
	struct packed_git *p;
	for (p = get_packed_git(repo); p; p = p->next) {
		if (!pack_to_algop(repo, p, src, to, dest))
			return 0;
	}
	return -1;
}
