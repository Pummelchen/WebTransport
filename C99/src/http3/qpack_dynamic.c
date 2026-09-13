/* QPACK's dynamic table (RFC 9204 section 3.2). */

#include "webtransport/http3/qpack.h"

#include <string.h>

void wt_qpack_dynamic_init(wt_qpack_dynamic_table_t *table, size_t capacity) {
  if (table == NULL) return;
  memset(table, 0, sizeof(*table));
  table->capacity = capacity;
}

/* Evict the oldest entry, which is what "evicted from the beginning" means
 * (section 3.2.4): its bytes go with it. */
static void drop_oldest(wt_qpack_dynamic_table_t *table) {
  size_t entry_size;
  size_t gone;
  size_t i;

  if (table->count == 0U) return;
  entry_size = (size_t)table->entries[0].name_length + (size_t)table->entries[0].value_length +
               (size_t)WT_QPACK_DYNAMIC_ENTRY_OVERHEAD;
  table->size -= entry_size;
  gone = (size_t)table->entries[0].name_length + (size_t)table->entries[0].value_length;
  memmove(table->bytes, table->bytes + gone, table->used - gone);
  table->used -= gone;
  memmove(&table->entries[0], &table->entries[1],
          (table->count - 1U) * sizeof(table->entries[0]));
  table->count--;
  table->dropped++;
  /* The bytes of every surviving entry just moved down by `gone`, so their offsets
   * have to move with them: an entry whose offset still pointed into the old arena
   * would read another entry's name, which is the quietest way for a dynamic table
   * to produce a different header section. */
  for (i = 0U; i < table->count; i++) {
    table->entries[i].offset -= (uint32_t)gone;
  }
}

void wt_qpack_dynamic_set_capacity(wt_qpack_dynamic_table_t *table, size_t capacity) {
  if (table == NULL) return;
  table->capacity = capacity;
  while (table->count != 0U && table->size > table->capacity) {
    drop_oldest(table);
  }
}

wt_status_t wt_qpack_dynamic_insert(wt_qpack_dynamic_table_t *table, const uint8_t *name,
                                    size_t name_length, const uint8_t *value, size_t value_length,
                                    uint64_t *out_absolute_index) {
  size_t entry_size;
  size_t needed;

  if (table == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (name == NULL && name_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (value == NULL && value_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (name_length > 0xffffU || value_length > 0xffffU) return WT_ERR_LIMIT;
  if (name_length > SIZE_MAX - value_length - WT_QPACK_DYNAMIC_ENTRY_OVERHEAD) return WT_ERR_OVERFLOW;

  entry_size = name_length + value_length + (size_t)WT_QPACK_DYNAMIC_ENTRY_OVERHEAD;
  /* Section 3.2.1: an entry larger than the whole capacity can never be stored,
   * and inserting it is the encoder's error rather than something to truncate. */
  if (entry_size > table->capacity) return WT_ERR_LIMIT;
  if (table->count >= (size_t)WT_QPACK_DYNAMIC_MAX_ENTRIES) return WT_ERR_LIMIT;
  /* The arena holds the live bytes; an entry that would not fit even after every
   * eviction is one this build's bound refuses. */
  if (name_length + value_length > sizeof(table->bytes)) return WT_ERR_LIMIT;

  /* Make room, oldest first, then by compacting what is left to the front: the
   * bytes of evicted entries would otherwise be holes, and a table that only ever
   * appended would run out of arena after capacity's worth of traffic. */
  while (table->count != 0U && table->size + entry_size > table->capacity) {
    drop_oldest(table);
  }
  if (table->used + name_length + value_length > sizeof(table->bytes)) {
    /* Every live entry is contiguous at the front already -- `drop_oldest` moves
     * the rest down -- so this can only happen if the live bytes are larger than
     * the arena, which the entry-size check above rules out for a single entry. */
    return WT_ERR_LIMIT;
  }

  needed = name_length + value_length;
  /* An empty name or value is legal and has no bytes to copy; the guards keep a
   * NULL with a zero length away from `memcpy`'s nonnull parameters. */
  if (name_length != 0U) memcpy(table->bytes + table->used, name, name_length);
  if (value_length != 0U) memcpy(table->bytes + table->used + name_length, value, value_length);
  table->entries[table->count].absolute_index = table->insert_count;
  table->entries[table->count].offset = (uint32_t)table->used;
  table->entries[table->count].name_length = (uint16_t)name_length;
  table->entries[table->count].value_length = (uint16_t)value_length;
  table->count++;
  table->used += needed;
  table->size += entry_size;
  if (out_absolute_index != NULL) *out_absolute_index = table->insert_count;
  table->insert_count++;
  return WT_OK;
}

wt_status_t wt_qpack_dynamic_entry(const wt_qpack_dynamic_table_t *table, uint64_t absolute_index,
                                   const uint8_t **out_name, size_t *out_name_length,
                                   const uint8_t **out_value, size_t *out_value_length) {
  const wt_qpack_dynamic_entry_meta_t *meta;

  if (table == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (out_name == NULL || out_name_length == NULL || out_value == NULL ||
      out_value_length == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* Evicted entries are gone, and their indices are not reused, so a reference to
   * one is a decompression failure at the caller rather than something to guess
   * at (section 3.2.4). */
  if (absolute_index < table->dropped || absolute_index >= table->insert_count) {
    return WT_ERR_CLOSED;
  }
  meta = &table->entries[(size_t)(absolute_index - table->dropped)];
  *out_name = table->bytes + meta->offset;
  *out_name_length = (size_t)meta->name_length;
  *out_value = table->bytes + meta->offset + meta->name_length;
  *out_value_length = (size_t)meta->value_length;
  return WT_OK;
}
