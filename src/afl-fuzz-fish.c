
#include "afl-fuzz.h"
#include "fishfuzz.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

/* update function distance */
void add_func_shortest(struct func_dist_map *dst, u32 src, u32 shortest) {

  struct func_shortest *new_shortest = (struct func_shortest *)ck_alloc(sizeof(struct func_shortest));

  if (!new_shortest) FATAL("Failed allocate memory!");

  new_shortest->src = src;
  new_shortest->shortest = shortest;
  new_shortest->next = NULL;

  if (!dst->shortest_list) {

    dst->shortest_tail = new_shortest;
    dst->shortest_list = new_shortest;

  } else {

    dst->shortest_tail->next = new_shortest;
    dst->shortest_tail = new_shortest;

  }

}


void initialized_dist_map(afl_state_t *afl) {

  cJSON *shortest_dist_map = NULL;
  cJSON *func_shortest_value = NULL;
  cJSON *src_s = NULL;

  struct fishfuzz_info *ff_info = afl->ff_info;
  struct func_dist_map *global_dist_map = ff_info->global_dist_map;
    
  char temporary_calldst_dir[MAX_PATH_LENGTH];    
  char *tmp_dir_env = getenv("AFL_FISHFUZZ_DIR");

  if (tmp_dir_env == NULL) FATAL("AFL_FISHFUZZ_DIR not available!");

  sprintf(temporary_calldst_dir, "%s/calldst.json", tmp_dir_env);
    
  // Read JSON file
  FILE *dist_map = fopen(temporary_calldst_dir, "rb");
  if (!dist_map) FATAL("Failed reading dist file!");

  fseek(dist_map, 0, SEEK_END);
  u64 file_size = ftell(dist_map);
  fseek(dist_map, 0, SEEK_SET);
    
  char *file_contents = (char *)ck_alloc(file_size + 1);
  if (!file_contents) FATAL("Failed allocating memory for file!");
    
  fread(file_contents, 1, file_size, dist_map);
  fclose(dist_map);
  file_contents[file_size] = '\0';
    
  // Parse JSON
  shortest_dist_map = cJSON_Parse(file_contents);

  if (!shortest_dist_map) FATAL("Failed parse json distance!");

  // Iterate over JSON objects
  cJSON_ArrayForEach(func_shortest_value, shortest_dist_map) {
    const char *dst_s = func_shortest_value->string;

    // DEBUG
    printf("trying to visit %d th item of global_dist_map, which is %p\n", atoi(dst_s), &(global_dist_map[atoi(dst_s)]));
    struct func_dist_map *new_dst = &(global_dist_map[atoi(dst_s)]);
    new_dst->shortest_list = NULL;
    new_dst->shortest_tail = NULL;
    
    cJSON_ArrayForEach(src_s, func_shortest_value) {
      u32 src = (u32)atoi(src_s->string);
      u32 shortest = (u32)cJSON_GetNumberValue(src_s);
      add_func_shortest(new_dst, src, shortest);
    }
  }
    
  cJSON_Delete(shortest_dist_map);
  ck_free(file_contents);

}

/* function id start from 1, so would not conflict with error code 0 */
u32 parse_func_info(char* line, struct func_dist_map * global_dist_map) {

  char *token = strtok(line, ",");
  if (token == NULL) return 0; 

  // ignore filename
  // Get fid
  token = strtok(NULL, ",");
  if (token == NULL) return 0; 
  u32 fid = atoi(token);
  struct func_dist_map * current_dist_map = &global_dist_map[fid];

  // Get start_bb
  token = strtok(NULL, ",");
  if (token == NULL) return 0; 
  current_dist_map->start_bb = atoi(token);

  // Get end_bb
  token = strtok(NULL, ",");
  if (token == NULL) return 0; 
  current_dist_map->end_bb = atoi(token);

  return fid; 
  
}

/* interface to initialize all the ff related structure, 
   need more tuning on ff_info initialization 
*/
void initialize_fishfuzz(afl_state_t *afl) {

  char temporary_fid_dir[MAX_PATH_LENGTH];    
  char *tmp_dir_env = getenv("AFL_FISHFUZZ_DIR");

  if (tmp_dir_env == NULL) FATAL("AFL_FISHFUZZ_DIR not available!");

  sprintf(temporary_fid_dir, "%s/fid", tmp_dir_env);

  // TODO: fix initialization
  if (!afl->ff_info) afl->ff_info = (struct fishfuzz_info *) ck_alloc(sizeof(struct fishfuzz_info));

  FILE* file = fopen(temporary_fid_dir, "r"); 
  char line[MAX_LINE_LENGTH];
  u64 nfunc = 0;

  if (file == NULL) FATAL("Failed open fid!");

  while (fgets(line, sizeof(line), file) != NULL) nfunc += 1;

  fseek(file, 0, SEEK_SET);

  // take care of off-by-one, the func id start from 1
  afl->ff_info->global_dist_map = (struct func_dist_map *)ck_alloc(
                      sizeof(struct func_dist_map) * (nfunc + 1));
  afl->ff_info->func_map_size = nfunc;

  // we initialize the distance map with start_bb/end_bb here
  struct func_dist_map *global_dist_map = afl->ff_info->global_dist_map;

  while (fgets(line, sizeof(line), file) != NULL) {

    u32 fid = parse_func_info(line, global_dist_map);
    if (!fid) FATAL("Error Parsing the line!");

    // DEBUG 
    // printf("Now walking to function %d, start from %lld to %lld\n",
    //       fid, global_dist_map[fid].start_bb, global_dist_map[fid].end_bb);

  }

  fclose(file);

  afl->ff_info->unvisited_func_map = (u8*)ck_alloc(sizeof(u8) * (afl->ff_info->func_map_size + 1));
  afl->ff_info->iterated_func_map = (u8*)ck_alloc(sizeof(u8) * (afl->ff_info->func_map_size + 1));

  for (u64 i = 1; i <= afl->ff_info->func_map_size; i ++) afl->ff_info->unvisited_func_map[i] = 1;

  initialized_dist_map(afl);

}


/* Now we don't need a trace_func, given that we can map the bitmap (afl->fsrv.trace_bits[i]) 
   to the func_map
*/
void update_bitmap_score_explore(afl_state_t *afl, struct fishfuzz_info *ff_info, struct queue_entry *q) {

  if (!ff_info->virgin_funcs) return ;

  if (!ff_info->shortest_dist) {
    
    ff_info->shortest_dist = (u32 *)ck_alloc(sizeof(u32) * (ff_info->func_map_size + 1));

    for (u32 i = 1; i <= ff_info->func_map_size; i ++) ff_info->shortest_dist[i] = UNREACHABLE_DIST;
  
  }

  if (!afl->top_rated_explore) {

    afl->top_rated_explore = ck_alloc(sizeof(void *) * (ff_info->func_map_size + 1));

  }

  // quickly generate a trace_func from trace_bits
  u8 *trace_func = ck_alloc(sizeof(u8) * (ff_info->func_map_size + 1));
  struct func_dist_map *global_dist_map = ff_info->global_dist_map;

  for (u32 bb = 0, fid = 1; bb < afl->fsrv.map_size; fid += 1) {

    if (fid > ff_info->func_map_size) break;

    bb = global_dist_map[fid].start_bb;
    
    while (bb++ <= global_dist_map[fid].end_bb) {

      if (unlikely(afl->fsrv.trace_bits[bb])) {

        trace_func[fid] = 1;
        break;

      }

    }

  }

  u8 has_new_func = 0;
  for (u32 i = 1; i <= ff_info->func_map_size; i ++) {

    if (unlikely(trace_func[i]) && unlikely(!ff_info->iterated_func_map[i])) { has_new_func = 1; break; }
        
  }

  if (!has_new_func) return ;

  u64 fav_factor = q->len * q->exec_us;

  for (u32 dst_func = 1; dst_func <= ff_info->func_map_size; dst_func ++) {

    if (!ff_info->unvisited_func_map[dst_func] || ff_info->virgin_funcs[dst_func]) continue;

      // now we don't remove explored functions 
      // if (afl->top_rated_explore[dst_func]) {

      //   if (afl->top_rated_explore[dst_func]->fuzz_level) afl->top_rated_explore[dst_func] = NULL;
      
      // }
    u32 fexp_score = 0, shortest_dist = UNREACHABLE_DIST; //, src_func = 0;

    // for (auto iter = func_dist_map[dst_func].begin(); iter != func_dist_map[dst_func].end(); iter ++) {
      
    //   if (trace_func[iter->first]) {

    //     if (iter->second < shortest_dist) { src_func = iter->first; shortest_dist = iter->second; }
        
    //   }
      
    // }
    for (struct func_shortest * iter = global_dist_map[dst_func].shortest_list; 
        iter != NULL; iter = iter->next) {
      
      if (trace_func[iter->src]) {

        if (iter->shortest < shortest_dist) shortest_dist = iter->shortest;  // src_func = iter->src; 

      }

    }

    if (shortest_dist != UNREACHABLE_DIST) fexp_score = shortest_dist * 100;

    if (!fexp_score) continue;

    if (!afl->top_rated_explore[dst_func] || fexp_score < ff_info->shortest_dist[dst_func]) {
        
      afl->top_rated_explore[dst_func] = q; ff_info->shortest_dist[dst_func] = fexp_score;
      ff_info->last_func_time = get_cur_time(); ff_info->skip_inter_func = 0;
        
    } else if (fexp_score == ff_info->shortest_dist[dst_func] && !afl->top_rated_explore[dst_func]->fuzz_level) {

      u64 old_factor = afl->top_rated_explore[dst_func]->exec_us * afl->top_rated_explore[dst_func]->len;

      if (fav_factor < old_factor) {
              
        afl->top_rated_explore[dst_func] = q; ff_info->shortest_dist[dst_func] = fexp_score;
        ff_info->last_func_time = get_cur_time(); ff_info->skip_inter_func = 0;

      }
          
    }
    
  }

  for (u32 i = 1; i <= ff_info->func_map_size; i ++) {

    if (unlikely(trace_func[i])) ff_info->iterated_func_map[i] = 1;
      
  } 

  ck_free(trace_func);


}


int compare_u32(const void* a, const void* b) {
  uint32_t arg1 = *(const uint32_t*)a;
  uint32_t arg2 = *(const uint32_t*)b;

  if (arg1 < arg2) return -1;
  if (arg1 > arg2) return 1;
  return 0;
}


void target_ranking(afl_state_t *afl, struct fishfuzz_info *ff_info) {

  u32* reached_bugs = NULL;
  u32 max_value = 1;

  if (!ff_info->reach_bits_count || !ff_info->trigger_bits_count) return;

  reached_bugs = (u32*)ck_alloc(afl->fsrv.map_size * sizeof(u32));

  u64 reached_bugs_count = 0;

  for (u32 i = 0; i < afl->fsrv.map_size; i++) {
    if (ff_info->reach_bits_count[i] && !ff_info->trigger_bits_count[i]) {
        
      reached_bugs[reached_bugs_count++] = ff_info->reach_bits_count[i];

      if (max_value < ff_info->reach_bits_count[i]) max_value = ff_info->reach_bits_count[i];
    
    }
  }

  qsort(reached_bugs, reached_bugs_count, sizeof(u32), compare_u32);

  if (max_value != 1) {

    float rate = (float)afl->pending_not_fuzzed / afl->queued_items;
    
    if (rate < 0.2) rate = 0.1;
    else if (rate < 0.5) rate = 0.075;
    else rate = 0.05;
    
    ff_info->exploit_threshould = reached_bugs[(u32)(reached_bugs_count * rate)];

  }

  ck_free(reached_bugs);

}


void update_fishfuzz_states(afl_state_t *afl, struct fishfuzz_info *ff_info) {

  if (unlikely(!ff_info->trigger_bits_count)) {
  
    ff_info->trigger_bits_count = ck_alloc(sizeof(u32) * afl->fsrv.map_size);
  
  }
  if (unlikely(!ff_info->reach_bits_count)) {
  
    ff_info->reach_bits_count = ck_alloc(sizeof(u32) * afl->fsrv.map_size);
  
  }

  /* TOFIX: handle if we target ASan labels */
  u8 *targets_map = afl->fsrv.trace_bits;
  for (u32 i = 0; i < afl->fsrv.map_size; i ++) {

    if (unlikely(targets_map[i])) {

      if (!ff_info->reach_bits_count[i]) {

        ff_info->last_reach_time = get_cur_time();
        ff_info->current_targets_reached ++;

      }

      ff_info->reach_bits_count[i] ++;
      
    }
  }

}


void cull_queue_explore(afl_state_t *afl, struct fishfuzz_info *ff_info) {
  
  if (likely(!ff_info->function_changed || afl->non_instrumented_mode)) { return; }

  u32 i;

  ff_info->function_changed = 0;

  afl->queued_favored = 0;
  afl->pending_favored = 0;
  ff_info->queued_retryed = 0;

  for (i = 0; i < afl->queued_items; i++) {

    afl->queue_buf[i]->favored = 0;
    afl->queue_buf[i]->retry = 0;

  }

  for (i = 1; i <= ff_info->func_map_size; i++) {
    if (afl->top_rated_explore[i] && !ff_info->virgin_funcs[i]) {
      
      if (afl->top_rated_explore[i]->favored) continue;

      afl->top_rated_explore[i]->favored = 1;
      afl->queued_favored++;

      if (!afl->top_rated_explore[i]->was_fuzzed) afl->pending_favored++;

    }
  }

  if (!afl->pending_favored) ff_info->skip_inter_func = 1;

  for (i = 0; i < afl->queued_items; i++) {

    mark_as_redundant(afl, afl->queue_buf[i], !afl->queue_buf[i]->favored);

  }

}


void cull_queue_exploit(afl_state_t *afl, struct fishfuzz_info *ff_info) {
  #define TRACE_MINI_VISITED(trace_mini, idx) (trace_mini[idx >> 3] & (1 << (idx & 7)))
  
  // struct queue_entry* q;
  u8 *temp_v = afl->map_tmp_buf;
  u32 len = (afl->fsrv.map_size >> 3), i;

  /* if score not changed and we've already have favored seeds */
  u8 should_skip = (afl->pending_favored + ff_info->queued_retryed == 0);
  if (afl->non_instrumented_mode || (!ff_info->target_changed && !should_skip)) return;

  /* for first cull_queue, ignore */
  if (!ff_info->exploit_threshould) return ;

  ff_info->target_changed = 0;
  memset(temp_v, 255, len);

  afl->queued_favored = 0;
  afl->pending_favored = 0;
  ff_info->queued_retryed = 0;

  for (i = 0; i < afl->queued_items; i++) {

    afl->queue_buf[i]->favored = 0;
    afl->queue_buf[i]->retry = 0;

  }

  // u32 total_visit_cnt = 0, total_n_bugs = 0;
  for (i = 0; i < afl->fsrv.map_size; i++) {
    if ((temp_v[i >> 3] & (1 << (i & 7))) && ff_info->reach_bits_count[i]) {

      if (ff_info->reach_bits_count[i] > ff_info->exploit_threshould) continue;
      if (ff_info->trigger_bits_count[i]) continue;
      
      // we target all bbs now, so just reuse the top_rated
      struct queue_entry *selected = afl->top_rated[i];

      if (!selected) continue; 
      if (selected->favored || !selected->trace_mini) continue;
              
      u32 k = len;

      while (k--) 
        if (selected->trace_mini[k]) 
          temp_v[k] &= ~selected->trace_mini[k];
        
      selected->favored = 1;
      afl->queued_favored++;

      if (!selected->was_fuzzed) afl->pending_favored++;

    }
  }

  /* maybe retry some seeds */
  if (afl->queued_favored && afl->pending_favored * 100 / afl->queued_favored < 10) {

    u64 total_visit_cnt = 0, total_trigger_cnt = 0, avg_violation_visit = 0; // avg_violation_trigger = 0
    for (u32 i = 0; i < afl->fsrv.map_size; i ++) {

      if (ff_info->trigger_bits_count[i]) total_trigger_cnt += ff_info->trigger_bits_count[i];
      if (ff_info->reach_bits_count[i]) total_visit_cnt += ff_info->reach_bits_count[i];
    
    }

    // if (ff_info->current_targets_triggered) avg_violation_trigger = total_trigger_cnt / ff_info->current_targets_triggered;
    if (ff_info->current_targets_reached) avg_violation_visit = total_visit_cnt / ff_info->current_targets_reached;
    /* pick up favored seeds that is not well explored */
    if (avg_violation_visit) {
      for (i = 0; i < afl->fsrv.map_size; i++) {
        if (ff_info->reach_bits_count[i] && !ff_info->trigger_bits_count[i] && 
            ff_info->reach_bits_count[i] <= ff_info->exploit_threshould / 10) {
          struct queue_entry *selected = afl->top_rated[i];

          if (!selected) continue;
          /* only select already fuzzed favored seed and not marked as retry */
          if (!selected->favored || !selected->was_fuzzed || selected->retry) continue;

          if (avg_violation_visit > ff_info->reach_bits_count[i]) {
            
            ff_info->queued_retryed ++;
            selected->retry = 1;
            
          }
        
        }
      }
    }

  }

  for (i = 0; i < afl->queued_items; i++) {

    mark_as_redundant(afl, afl->queue_buf[i], !afl->queue_buf[i]->favored);

  }

}

void update_function_cov(afl_state_t *afl, struct fishfuzz_info *ff_info) {

  if (!afl->fsrv.trace_bits) return ;
  
  if (unlikely(!ff_info->virgin_funcs)) {

    ff_info->virgin_funcs = ck_alloc(sizeof(u8) * (ff_info->func_map_size + 1));
  
  }
  
  for (u32 i = 1; i <= ff_info->func_map_size; i ++) {
  
    if (!ff_info->virgin_funcs[i]) {

      u32 bb = ff_info->global_dist_map[i].start_bb;
      u8 visited = 0;

      while (bb++ <= ff_info->global_dist_map[i].end_bb) {

        if (afl->fsrv.trace_bits[bb]) {visited = 1; break;}

      }
      
      if (visited) {

        ff_info->virgin_funcs[i] = 1;
        ff_info->function_changed = 1;
        ff_info->current_func_covered += 1;
      
      }
  
    }
  
  }

}