#ifndef _AFL_CMPLOG_H
#define _AFL_CMPLOG_H

#include "types.h"
#include "afl-fuzz.h"

#define MAX_PATH_LENGTH (16 * 1024)
#define MAX_LINE_LENGTH (16 * 1024)

#define UNREACHABLE_DIST 0x7FFFFFFF

/* Some time limitation for inter/intra-explore/exploit */
#define MINIMAL_UPDATE_EXEC   (50 * 1000U)
#define BEGIN_EXPLORE_TLIMIT  (30 * 60 * 1000U)
#define INTER_EXPLORE_TLIMIT  (30 * 60 * 1000U)
#define INTRA_EXPLORE_TLIMIT  (15 * 60 * 1000U)
#define TARGET_EXPLOIT_TLIMIT (30 * 60 * 1000U)
#define LOG_FREQUENCY_TLIMIT  (30 * 60 * 1000U)



/* for fishfuzz's seed selection */
enum {
  /* 00 */ INTRA_FUNC_EXPLORE,
  /* 01 */ INTER_FUNC_EXPLORE,
  /* 02 */ TARGET_EXPLOIT
};


struct func_shortest {

  u32 src;
  u32 shortest;
  struct func_shortest *next;

};

struct func_dist_map {

  u64 start_bb, end_bb; 
  struct func_shortest *shortest_list,
                       *shortest_tail;
};


struct fishfuzz_profile {

  u8  *fish_debug_log,                  
      *exploit_debug_log,
      *cull_debug_log,
      *function_debug_log,
      *seed_selec_log,
      *exploit_log,
      *dev_log;
  
  FILE *fish_debug_fd,
      *exploit_debug_fd,
      *cull_debug_fd,
      *function_debug_fd,
      *seed_selec_fd,
      *exploit_fd,
      *dev_fd;
  
  u64 last_log_time,
      log_cull_origin_time,
      log_cull_explore_time,
      log_cull_exploit_time,
      log_cull_other_time,
      log_total_fuzz_time,
      log_total_iteration_time,
      log_update_explore_time,
      log_update_exploit_time;

};

struct fishfuzz_info {

  u32 *reach_bits_count,
      *trigger_bits_count;
  
  u32 current_func_covered,
      current_targets_reached,
      current_targets_triggered;
  
  u32 queued_retryed,
      queued_fuzzed_favored,
      queued_fuzzed_non_favored,
      queued_fuzzed_retryed;
  
  u64 last_reach_time,
      last_trigger_time,
      last_func_time,
      start_func_time,
      start_intra_time,
      last_update_exec;

  u8  function_changed,
      target_changed,
      skip_inter_func,
      fish_seed_selection,
      no_exploitation;
  
  u32 exploit_threshould; 

  u64 func_map_size;

  u32 *shortest_dist;

  u8 *unvisited_func_map, 
     *iterated_func_map;

  struct func_dist_map *global_dist_map;

  struct fishfuzz_profile *prof;

};


/* FishFuzz APIs */
void initialize_fishfuzz(afl_state_t *);
void target_ranking(afl_state_t *, struct fishfuzz_info *);
void update_bitmap_score_explore(afl_state_t *, struct fishfuzz_info *, struct queue_entry *);

#endif