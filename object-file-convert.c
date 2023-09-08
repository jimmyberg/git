#include "git-compat-util.h"
#include "gettext.h"
#include "strbuf.h"
#include "hex.h"
#include "repository.h"
#include "hash-ll.h"
#include "hash.h"
#include "object.h"
#include "loose.h"
#include "commit.h"
#include "gpg-interface.h"
#include "pack-compat-map.h"
#include "object-file-convert.h"
#include "read-cache.h"
#include "submodule-config.h"

int repo_submodule_oid_to_algop(struct repository *repo,
				const struct object_id *src,
				const struct git_hash_algo *to,
				struct object_id *dest)
{
	int i;

	if (repo_read_index(repo) < 0)
		die(_("index file corrupt"));

	for (i = 0; i < repo->index->cache_nr; i++) {
		const struct cache_entry *ce = repo->index->cache[i];
		struct repository subrepo = {};
		int ret;

		if (!S_ISGITLINK(ce->ce_mode))
			continue;

		while (i + 1 < repo->index->cache_nr &&
		       !strcmp(ce->name, repo->index->cache[i + 1]->name))
			/*
			 * Skip entries with the same name in different stages
			 * to make sure an entry is returned only once.
			 */
			i++;

		if (repo_submodule_init(&subrepo, repo, ce->name, null_oid()))
			continue;

		ret = repo_oid_to_algop(&subrepo, src, to, dest);
		repo_clear(&subrepo);
		if (ret == 0)
			return 0;
	}
	return -1;
}

int repo_oid_to_algop(struct repository *repo, const struct object_id *src,
		      const struct git_hash_algo *to, struct object_id *dest)
{
	/*
	 * If the source alogirthm is not set, then we're using the
	 * default hash algorithm for that object.
	 */
	const struct git_hash_algo *from =
		src->algo ? &hash_algos[src->algo] : repo->hash_algo;

	if (from == to) {
		if (src != dest)
			oidcpy(dest, src);
		return 0;
	}
	if (repo_loose_object_map_oid(repo, dest, to, src)) {
		/*
		 * It's not in the loose object map, so let's see if it's in a
		 * pack.
		 */
		if (!repo_packed_oid_to_algop(repo, src, to, dest))
			return 0;

		/*
		 * We may have loaded the object map at repo initialization but
		 * another process (perhaps upstream of a pipe from us) may have
		 * written a new object into the map.  If the object is missing,
		 * let's reload the map to see if the object has appeared.
		 */
		repo_read_loose_object_map(repo);
		if (repo_loose_object_map_oid(repo, dest, to, src))
			return -1;
	}
	return 0;
}

static int decode_tree_entry_raw(struct object_id *oid, const char **path,
				 size_t *len, const struct git_hash_algo *algo,
				 const char *buf, unsigned long size)
{
	uint16_t mode;
	const unsigned hashsz = algo->rawsz;

	if (size < hashsz + 3 || buf[size - (hashsz + 1)]) {
		return -1;
	}

	*path = parse_mode(buf, &mode);
	if (!*path || !**path)
		return -1;
	*len = strlen(*path) + 1;

	oidread_algop(oid, (const unsigned char *)*path + *len, algo);
	return 0;
}

static int convert_tree_object_step(struct object_file_convert_state *state)
{
	const char *buf = state->buf, *p, *end = buf + state->buf_len;
	const struct git_hash_algo *from = state->from;
	const struct git_hash_algo *to = state->to;
	struct strbuf *out = state->outbuf;

	/* The current position */
	p = buf + state->buf_pos;

	while (p < end) {
		struct object_id entry_oid;
		const char *path = NULL;
		size_t pathlen;

		if (decode_tree_entry_raw(&entry_oid, &path, &pathlen, from, p,
					  end - p))
			return error(_("failed to decode tree entry"));

		if (!state->mapped_oid.algo) {
			oidcpy(&state->oid, &entry_oid);
			return 1;
		}
		else if (!oideq(&entry_oid, &state->oid))
			return error(_("bad object_file_convert_state oid"));

		strbuf_add(out, p, path - p);
		strbuf_add(out, path, pathlen);
		strbuf_add(out, state->mapped_oid.hash, to->rawsz);
		state->mapped_oid.algo = 0;
		p = path + pathlen + from->rawsz;
		state->buf_pos = p - buf;
	}
	return 0;
}

static int convert_commit_object_step(struct object_file_convert_state *state)
{
	const struct git_hash_algo *from = state->from;
	struct strbuf *out = state->outbuf;
	const char *buf = state->buf;
	const char *tail = buf + state->buf_len;
	const char *bufptr = buf + state->buf_pos;
	const int tree_entry_len = from->hexsz + 5;
	const int parent_entry_len = from->hexsz + 7;
	struct object_id oid;
	const char *p;

	if (state->buf_pos == 0) {
		if (tail <= bufptr + tree_entry_len + 1 || memcmp(bufptr, "tree ", 5) ||
		    bufptr[tree_entry_len] != '\n')
			return error("bogus commit object");

		if (parse_oid_hex_algop(bufptr + 5, &oid, &p, from) < 0)
			return error("bad tree pointer");

		if (!state->mapped_oid.algo) {
			oidcpy(&state->oid, &oid);
			return 1;
		}
		else if (!oideq(&oid, &state->oid))
			return error(_("bad object_file_convert_state oid"));

		strbuf_addf(out, "tree %s\n", oid_to_hex(&state->mapped_oid));
		state->mapped_oid.algo = 0;
		bufptr = p + 1;
		state->buf_pos = bufptr - buf;
	}

	while (bufptr + parent_entry_len < tail && !memcmp(bufptr, "parent ", 7)) {
		if (tail <= bufptr + parent_entry_len + 1 ||
		    parse_oid_hex_algop(bufptr + 7, &oid, &p, from) ||
		    *p != '\n')
			return error("bad parents in commit");

		if (!state->mapped_oid.algo) {
			oidcpy(&state->oid, &oid);
			return 1;
		}
		else if (!oideq(&oid, &state->oid))
			return error(_("bad object_file_convert_state oid"));

		strbuf_addf(out, "parent %s\n", oid_to_hex(&state->mapped_oid));
		state->mapped_oid.algo = 0;
		bufptr = p + 1;
		state->buf_pos = bufptr - buf;
	}
	strbuf_add(out, bufptr, tail - bufptr);
	return 0;
}

static int convert_tag_object_step(struct object_file_convert_state *state)
{
	struct strbuf payload = STRBUF_INIT, temp = STRBUF_INIT, oursig = STRBUF_INIT, othersig = STRBUF_INIT;
	const struct git_hash_algo *from = state->from;
	const struct git_hash_algo *to = state->to;
	struct strbuf *out = state->outbuf;
	const char *buffer = state->buf;
	size_t payload_size, size = state->buf_len;;
	struct object_id oid;
	const char *p;
	int ret = 0;

	if (!state->mapped_oid.algo) {
		if (strncmp(buffer, "object ", 7) ||
		    buffer[from->hexsz + 7] != '\n')
			return error("bogus tag object");
		if (parse_oid_hex_algop(buffer + 7, &oid, &p, from) < 0)
			return error("bad tag object ID");

		oidcpy(&state->oid, &oid);
		return 1;
	}

	/* Add some slop for longer signature header in the new algorithm. */
	strbuf_grow(out, size + 7);

	/* Is there a signature for our algorithm? */
	payload_size = parse_signed_buffer(buffer, size);
	strbuf_add(&payload, buffer, payload_size);
	if (payload_size != size) {
		/* Yes, there is. */
		strbuf_add(&oursig, buffer + payload_size, size - payload_size);
	}
	/* Now, is there a signature for the other algorithm? */
	if (parse_buffer_signed_by_header(payload.buf, payload.len, &temp, &othersig, to)) {
		/* Yes, there is. */
		strbuf_swap(&payload, &temp);
		strbuf_release(&temp);
	}

	/*
	 * Our payload is now in payload and we may have up to two signatrures
	 * in oursig and othersig.
	 */
	if (strncmp(payload.buf, "object ", 7) || payload.buf[from->hexsz + 7] != '\n') {
		ret = error("bogus tag object");
		goto out;
	}
	if (parse_oid_hex_algop(payload.buf + 7, &oid, &p, from) < 0) {
		ret = error("bad tag object ID");
		goto out;
	}
	if (!oideq(&oid, &state->oid)) {
		ret = error(_("bad object_file_convert_state oid"));
		goto out;
	}

	strbuf_addf(out, "object %s\n", oid_to_hex(&state->mapped_oid));
	strbuf_add(out, p, payload.len - (p - payload.buf));
	strbuf_addbuf(out, &othersig);
	if (oursig.len)
		add_header_signature(out, &oursig, from);
out:
	strbuf_release(&oursig);
	strbuf_release(&othersig);
	strbuf_release(&payload);
	return ret;
}

void convert_object_file_begin(struct object_file_convert_state *state,
			      struct strbuf *outbuf,
			      const struct git_hash_algo *from,
			      const struct git_hash_algo *to,
			      const void *buf, size_t len,
			      enum object_type type)
{
	memset(state, 0, sizeof(*state));
	state->outbuf = outbuf;
	state->from = from;
	state->to = to;
	state->buf = buf;
	state->buf_len = len;
	state->buf_pos = 0;
	state->type = type;


	/* Don't call this function when no conversion is necessary */
	if ((from == to) || (type == OBJ_BLOB))
		BUG("Attempting noop object file conversion");

	switch (type) {
	case OBJ_TREE:
	case OBJ_COMMIT:
	case OBJ_TAG:
		break;
	default:
		/* Not implemented yet, so fail. */
		BUG("Unknown object file type found in conversion");
	}
}

int convert_object_file_step(struct object_file_convert_state *state)
{
	int ret;

	switch(state->type) {
	case OBJ_TREE:
		ret = convert_tree_object_step(state);
		break;
	case OBJ_COMMIT:
		ret = convert_commit_object_step(state);
		break;
	case OBJ_TAG:
		ret = convert_tag_object_step(state);
		break;
	default:
		ret = -1;
		break;
	}
	return ret;
}

void convert_object_file_end(struct object_file_convert_state *state, int ret)
{
	if (ret != 0) {
		strbuf_release(state->outbuf);
	}
	memset(state, 0, sizeof(*state));
}

int convert_object_file(struct strbuf *outbuf,
			const struct git_hash_algo *from,
			const struct git_hash_algo *to,
			const void *buf, size_t len,
			enum object_type type,
			int gentle)
{
	struct object_file_convert_state state;
	int ret;

	convert_object_file_begin(&state, outbuf, from, to, buf, len, type);

	for (;;) {
		ret = convert_object_file_step(&state);
		if (ret != 1)
			break;
		ret = repo_oid_to_algop(the_repository, &state.oid, state.to,
					&state.mapped_oid);
		if (ret)
			ret = repo_submodule_oid_to_algop(the_repository,
							  &state.oid,
							  state.to,
							  &state.mapped_oid);
		if (ret) {
			error(_("failed to map %s entry for %s"),
			      type_name(type), oid_to_hex(&state.oid));
			break;
		}
	}

	convert_object_file_end(&state, ret);
	if (!ret || gentle)
		return ret;
	die(_("Failed to convert object from %s to %s"),
		from->name, to->name);
}
