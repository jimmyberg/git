#ifndef PACK_COMPAT_MAP_H
#define PACK_COMPAT_MAP_H

#include "cbtree.h"
struct repository;
struct packed_git;
struct object_id;
struct git_hash_algo;
struct pack_idx_entry;

int load_pack_compat_map(struct repository *repo, struct packed_git *p);

typedef enum cb_next (*compat_map_iter_t)(const struct object_id *, void *data);
void pack_compat_map_each(struct repository *repo, struct packed_git *p,
			 const unsigned char *prefix, size_t prefix_hexsz,
			 compat_map_iter_t, void *data);

int repo_packed_oid_to_algop(struct repository *repo,
			     const struct object_id *src,
			     const struct git_hash_algo *to,
			     struct object_id *dest);

const char *write_compat_map_file(const char *compat_map_name,
				  struct pack_idx_entry **objects,
				  int nr_objects, const unsigned char *hash);

#endif /* PACK_COMPAT_MAP_H */
