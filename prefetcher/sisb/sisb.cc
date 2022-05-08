#include "../../inc/cache.h"
#include "sisb.h"
#include <unordered_map>
#include <set>

#define DEGREE 2

void CACHE::prefetcher_initialize() 
{
  sisb_prefetcher_initialize();
}

// uint32_t CACHE::llc_prefetcher_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type, uint32_t metadata_in, uint64_t instr_id, uint64_t curr_cycle)
uint32_t CACHE::prefetcher_cache_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type, uint32_t metadata_in)
{
  vector<uint64_t> sisb_candidates;
  sisb_prefetcher_operate(addr, ip, cache_hit, type, DEGREE, sisb_candidates);
  for(uint32_t i=0; i<sisb_candidates.size(); i++)
    prefetch_line(sisb_candidates[i], true, 0);
  return metadata_in;
}

void CACHE::prefetcher_cycle_operate() {}

uint32_t CACHE::prefetcher_cache_fill(uint64_t addr, uint32_t set, uint32_t match, uint8_t prefetch, uint64_t evicted_addr, uint32_t metadata_in)
{
  sisb_prefetcher_cache_fill(addr, set, match, prefetch, evicted_addr);
  return 0;
}

void CACHE::prefetcher_final_stats()
{
  sisb_prefetcher_final_stats();
}
