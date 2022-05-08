#include "../../inc/cache.h"
#include "bo.h"
#include <unordered_map>
#include <set>

#define DEGREE 2

void CACHE::prefetcher_initialize() 
{
  bo_prefetcher_initialize(this);
}

// uint32_t CACHE::llc_prefetcher_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type, uint32_t metadata_in, uint64_t instr_id, uint64_t curr_cycle)
uint32_t CACHE::prefetcher_cache_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type, uint32_t metadata_in)
{
  vector<uint64_t> bo_candidates;
  bo_prefetcher_operate(this, addr, ip, cache_hit, type, get_set(addr), get_way(addr, get_set(addr)), DEGREE, bo_candidates);
  for(uint32_t i=0; i<bo_candidates.size(); i++)
    prefetch_line(bo_candidates[i], true, 0);
  return metadata_in;
}

void CACHE::prefetcher_cycle_operate() {}

uint32_t CACHE::prefetcher_cache_fill(uint64_t addr, uint32_t set, uint32_t match, uint8_t prefetch, uint64_t evicted_addr, uint32_t metadata_in)
{
  bo_prefetcher_cache_fill(addr, set, match, prefetch, evicted_addr);
  return 0;
}

void CACHE::prefetcher_final_stats()
{
  bo_prefetcher_final_stats();
}
