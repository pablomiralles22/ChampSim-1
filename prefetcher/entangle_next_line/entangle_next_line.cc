#include "../../inc/cache.h"
#include "../../inc/ooo_cpu.h"
#include <unordered_map>
using namespace std;

#define LLC_MISS_LATENCY 171

#define DEGREE 2

unordered_map<uint64_t, uint64_t> bere_cache;
unordered_map<uint64_t, uint64_t> last_cache;

uint64_t llc_last_block = 0;

extern uint8_t warmup_complete[NUM_CPUS];
extern std::array<O3_CPU*, NUM_CPUS> ooo_cpu;

// HISTORY BUFFER

#define LLC_HIST_BUFFER_ENTRIES (2048 * 16)
#define LLC_HIST_BUFFER_MASK (LLC_HIST_BUFFER_ENTRIES - 1)

typedef struct __llc_hist_entry {
  uint64_t tag;
  uint64_t ip;
  uint64_t time; 
} llc_hist_entry;

llc_hist_entry llc_hist_buffer[LLC_HIST_BUFFER_ENTRIES];
uint64_t llc_hist_buffer_head; // log_2 (LLC_HIST_BUFFER_ENTRIES)

void llc_hist_buffer_init() {
  llc_hist_buffer_head = 0;
  for (uint32_t i = 0; i < LLC_HIST_BUFFER_ENTRIES; i++) {
    llc_hist_buffer[i].tag = 0;
    llc_hist_buffer[i].ip = 0;
    llc_hist_buffer[i].time = 0;
  }
}

uint64_t llc_hist_buffer_find_entry(uint64_t line_addr, uint64_t ip) {
  for (uint32_t count = 0, i = (llc_hist_buffer_head + LLC_HIST_BUFFER_MASK) % LLC_HIST_BUFFER_ENTRIES; count < LLC_HIST_BUFFER_ENTRIES; count++, i = (i + LLC_HIST_BUFFER_MASK) % LLC_HIST_BUFFER_ENTRIES) {
    if (llc_hist_buffer[i].tag == line_addr && llc_hist_buffer[i].ip == ip) return i;
  }
  return LLC_HIST_BUFFER_ENTRIES;
}

// It can have duplicated entries if the line was evicted in between
void llc_hist_buffer_add_entry(uint64_t line_addr, uint64_t ip, uint64_t cycle) {
  // Allocate a new entry (evict old one if necessary)
  llc_hist_buffer[llc_hist_buffer_head].tag = line_addr;
  llc_hist_buffer[llc_hist_buffer_head].ip = ip;
  llc_hist_buffer[llc_hist_buffer_head].time = cycle;
  llc_hist_buffer_head = (llc_hist_buffer_head + 1) % LLC_HIST_BUFFER_ENTRIES;
}

// return bere (best request -- entangled address)
uint64_t llc_hist_buffer_get_bere(uint64_t ip, uint64_t cycle, uint32_t skip = 0) {
  uint32_t num_skipped = 0;
  for (uint32_t count = 0, i = (llc_hist_buffer_head + LLC_HIST_BUFFER_MASK) % LLC_HIST_BUFFER_ENTRIES; count < LLC_HIST_BUFFER_ENTRIES; count++, i = (i + LLC_HIST_BUFFER_MASK) % LLC_HIST_BUFFER_ENTRIES) {
    if (llc_hist_buffer[i].tag && llc_hist_buffer[i].ip == ip && cycle - llc_hist_buffer[i].time >= LLC_MISS_LATENCY) {
      if (skip == num_skipped) {
        return llc_hist_buffer[i].tag;
      } else {
        num_skipped++;
      }
    }
  }
  return 0;
}

// return bere (best request -- entangled address)
uint64_t llc_hist_buffer_get_last(uint64_t ip, uint64_t cycle, uint32_t skip = 0) {
  uint32_t num_skipped = 0;
  for (uint32_t count = 0, i = (llc_hist_buffer_head + LLC_HIST_BUFFER_MASK) % LLC_HIST_BUFFER_ENTRIES; count < LLC_HIST_BUFFER_ENTRIES; count++, i = (i + LLC_HIST_BUFFER_MASK) % LLC_HIST_BUFFER_ENTRIES) {
    if (llc_hist_buffer[i].tag && llc_hist_buffer[i].ip == ip) {
      if (skip == num_skipped) {
        return llc_hist_buffer[i].tag;
      } else {
        num_skipped++;
      }
    }
  }
  return 0;
}

/////////////////

#define LLC_PAGE_BLOCKS_BITS (LOG2_PAGE_SIZE - LOG2_BLOCK_SIZE)
#define LLC_PAGE_BLOCKS (1 << LLC_PAGE_BLOCKS_BITS)
#define LLC_PAGE_OFFSET_MASK (LLC_PAGE_BLOCKS - 1)

#define LLC_BERTI_THROTTLING 1
#define LLC_BURST_THROTTLING 2

//#define CONTINUE_BURST

//#define BERTI_LATENCIES
//#define JUST_BERTI // No compensation for holes
#define LINNEA
#define WARMUP_NEW_PAGES

// TIME AND OVERFLOWS

#define LLC_TIME_BITS 32
#define LLC_TIME_OVERFLOW ((uint64_t)1 << LLC_TIME_BITS)
#define LLC_TIME_MASK (LLC_TIME_OVERFLOW - 1)


// INTERFACE

void CACHE::prefetcher_initialize() 
{
  // cout << "CPU " << cpu << " LLC Berti prefetcher" << endl;
}

uint32_t CACHE::prefetcher_cache_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type, uint32_t metadata_in)
{

  uint8_t count = 0;


  uint64_t line_addr = addr >> LOG2_BLOCK_SIZE;
  uint64_t page_addr = line_addr >> LLC_PAGE_BLOCKS_BITS;
  uint64_t offset = line_addr & LLC_PAGE_OFFSET_MASK;

  // ENTANGLED

  /* training */
  uint64_t bere = llc_hist_buffer_get_bere(ip, ooo_cpu[cpu]->current_cycle, 0);
  uint64_t last = llc_hist_buffer_get_last(ip, ooo_cpu[cpu]->current_cycle, 0);
  if (bere && line_addr != bere) {
    bere_cache[bere] = line_addr;
  }
  if (bere && line_addr != bere) {
    last_cache[last] = line_addr;
  }

  // Add the request in the history buffer
  //if ((llc_hist_buffer_find_entry(line_addr, ip) == LLC_HIST_BUFFER_ENTRIES)) {
  llc_hist_buffer_add_entry(line_addr, ip, ooo_cpu[cpu]->current_cycle);
  //}

  /* prediction */
  if (warmup_complete[cpu]) {
    if (bere_cache.find(line_addr) != bere_cache.end()) {
      // issue prefetch
      bool prefetched = prefetch_line(bere_cache[line_addr] << LOG2_BLOCK_SIZE, true, 1);
      //if (prefetched) llc_add_latencies_table(index, pf_offset, current_core_cycle[cpu]);
      count++;
      line_addr = bere_cache[line_addr];
    }
    while (count < DEGREE && last_cache.find(line_addr) != last_cache.end()) {
      // issue prefetch
      bool prefetched = prefetch_line(last_cache[line_addr] << LOG2_BLOCK_SIZE, true, 1);
      //if (prefetched) llc_add_latencies_table(index, pf_offset, current_core_cycle[cpu]);
      count++;
      line_addr = last_cache[line_addr];
    }
  }

  // Next line
  if (count < DEGREE) {
    bool prefetched = prefetch_line(addr + (1 << LOG2_BLOCK_SIZE), true, 0);
    count++;
  }
  if (count < DEGREE) {
    bool prefetched = prefetch_line(addr + (2 << LOG2_BLOCK_SIZE), true, 0);
  }

  return metadata_in;
}


uint32_t CACHE::prefetcher_cache_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr, uint32_t metadata_in)
{
  return metadata_in;
}

void CACHE::prefetcher_cycle_operate() {}
void CACHE::prefetcher_final_stats() { }

