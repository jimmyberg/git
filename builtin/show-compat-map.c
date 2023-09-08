#include "builtin.h"
#include "gettext.h"
#include "hash.h"
#include "hex.h"
#include "pack.h"
#include "parse-options.h"
#include "repository.h"

static const char *const show_compat_map_usage[] = {
	"git show-compat-map [--verbose] ",
	NULL
};

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

struct map_entry {
	struct object_id oid;
	uint32_t index;
};

static const struct git_hash_algo *from_oid_version(unsigned oid_version)
{
	if (oid_version == 1) {
		return &hash_algos[GIT_HASH_SHA1];
	} else if (oid_version == 2) {
		return &hash_algos[GIT_HASH_SHA256];
	}
	die("unknown oid version %u\n", oid_version);
}

static void read_half_map(struct map_entry *map, unsigned nr,
		     const struct git_hash_algo *algo)
{
	unsigned i;
	for (i = 0; i < nr; i++) {
		uint32_t index;
		if (fread(map[i].oid.hash, algo->rawsz, 1, stdin) != 1)
			die("unable to read hash of %s entry %u/%u",
			    algo->name, i, nr);
		if (fread(&index, 4, 1, stdin) != 1)
			die("unable to read index of %s entry %u/%u",
			    algo->name, i, nr);
		map[i].oid.algo = hash_algo_by_ptr(algo);
		map[i].index = ntohl(index);
	}
}

static void print_half_map(const struct map_entry *map,
			   unsigned nr)
{
	unsigned i;
	for (i = 0; i < nr; i++) {
		printf("%s %"PRIu32"\n",
		       oid_to_hex(&map[i].oid),
		       map[i].index);
	}
}

static void print_map(const struct map_entry *map,
		      const struct map_entry *compat_map,
		      unsigned nr)
{
	unsigned i;
	for (i = 0; i < nr; i++) {
		printf("%s ",
		       oid_to_hex(&map[i].oid));
		printf("%s\n",
		       oid_to_hex(&compat_map[map[i].index].oid));
	}
}

int cmd_show_compat_map(int argc, const char **argv, const char *prefix)
{
	const struct git_hash_algo *algo = NULL, *compat = NULL;
	unsigned nr;
	struct pack_compat_map_header hdr;
	struct map_entry *map, *compat_map;
	int verbose = 0;
	const struct option show_comapt_map_options[] = {
		OPT_BOOL(0, "verbose", &verbose,
			 N_("print implementation details of the map file")),
		OPT_END()
	};

	argc = parse_options(argc, argv, prefix, show_comapt_map_options,
			     show_compat_map_usage, 0);

	if (fread(&hdr, sizeof(hdr), 1, stdin) != 1)
		die("unable to read header");
	if ((hdr.sig[0] != 'C') ||
	    (hdr.sig[1] != 'M') ||
	    (hdr.sig[2] != 'A') ||
	    (hdr.sig[3] != 'P'))
		die("Missing map signature");
	if (hdr.version != 1)
		die("Unknown map version");
	if ((hdr.mbz1 != 0) ||
	    (hdr.mbz2 != 0) ||
	    (hdr.mbz3 != 0))
		die("Must be zero fields non-zero");

	nr = ntohl(hdr.nr_objects);

	algo = from_oid_version(hdr.first_oid_version);
	compat = from_oid_version(hdr.second_oid_version);


	if (verbose) {
		printf("Map v%u for %u objects from %s to %s abbrevs (%u:%u)\n",
		       hdr.version,
		       nr,
		       algo->name, compat->name,
		       hdr.first_abbrev_len,
		       hdr.second_abbrev_len);
	}
	ALLOC_ARRAY(map, nr);
	ALLOC_ARRAY(compat_map, nr);
	read_half_map(map, nr, algo);
	read_half_map(compat_map, nr, compat);
	if (verbose) {
		print_half_map(map, nr);
		print_half_map(compat_map, nr);
	}
	print_map(map, compat_map, nr);
	free(compat_map);
	free(map);
	return 0;
}
