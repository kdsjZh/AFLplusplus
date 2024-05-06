
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
    // printf("trying to visit %d th item of global_dist_map, which is %p\n", atoi(dst_s), &(global_dist_map[atoi(dst_s)]));
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

void initialize_fishfuzz(afl_state_t *afl) {

  char temporary_fid_dir[MAX_PATH_LENGTH];    
  char *tmp_dir_env = getenv("AFL_FISHFUZZ_DIR");

  if (tmp_dir_env == NULL) FATAL("AFL_FISHFUZZ_DIR not available!");

  sprintf(temporary_fid_dir, "%s/fid", tmp_dir_env);

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

  // we initialize the distance map with start_bb/end_bb here
  struct func_dist_map *global_dist_map = afl->ff_info->global_dist_map;

  if (!global_dist_map) FATAL("Failed allocating memory for dist map!");

  while (fgets(line, sizeof(line), file) != NULL) {

    u32 fid = parse_func_info(line, global_dist_map);
    if (!fid) FATAL("Error Parsing the line!");

    // DEBUG 
    // printf("Now walking to function %d, start from %lld to %lld\n",
    //       fid, global_dist_map[fid].start_bb, global_dist_map[fid].end_bb);

  }

  fclose(file);

  initialized_dist_map(afl);

}
