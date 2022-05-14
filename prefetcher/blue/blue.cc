#include "../../inc/cache.h"
#include "../../inc/ooo_cpu.h"
#include <unordered_map>
using namespace std;

#define LLC_MISS_LATENCY 171

#define DEGREE 2

extern uint8_t warmup_complete[NUM_CPUS];
extern std::array<O3_CPU*, NUM_CPUS> ooo_cpu;

namespace blue {
  unordered_map<uint64_t, uint64_t> bere_cache;
  unordered_map<uint64_t, uint64_t> last_cache;

  uint64_t llc_last_block = 0;

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

  uint64_t llc_get_latency(uint64_t cycle, uint64_t cycle_prev) {
    uint64_t cycle_masked = cycle & LLC_TIME_MASK;
    uint64_t cycle_prev_masked = cycle_prev & LLC_TIME_MASK;
    if (cycle_prev_masked > cycle_masked) {
      return (cycle_masked + LLC_TIME_OVERFLOW) - cycle_prev_masked;
    }
    return cycle_masked - cycle_prev_masked;
  }

  // STRIDE

  int llc_calculate_stride(uint64_t prev_offset, uint64_t current_offset) {
    assert(prev_offset < LLC_PAGE_BLOCKS);
    assert(current_offset < LLC_PAGE_BLOCKS);
    int stride;
    if (current_offset > prev_offset) {
      stride = current_offset - prev_offset;
    } else {
      stride = prev_offset - current_offset;
      stride *= -1;
    }
    assert(stride > (0 - LLC_PAGE_BLOCKS) && stride < LLC_PAGE_BLOCKS);
    return stride;
  }

  // BIT VECTOR

  uint64_t llc_count_bit_vector(uint64_t vector) {
    uint64_t count = 0;
    for (int i = 0; i < LLC_PAGE_BLOCKS; i++) {
      if (vector & ((uint64_t)1 << i)) {
        count++;
      }
    }
    return count;
  }

  uint64_t llc_count_wrong_berti_bit_vector(uint64_t vector, int berti) {
    uint64_t wrong = 0;
    for (int i = 0; i < LLC_PAGE_BLOCKS; i++) {
      if (vector & ((uint64_t)1 << i)) {
        if (i + berti >= 0 && i + berti < LLC_PAGE_BLOCKS && !(vector & ((uint64_t)1 << (i + berti)))) { 
          wrong++;
        }
      }
    }
    return wrong;
  }

  uint64_t llc_count_lost_berti_bit_vector(uint64_t vector, int berti) {
    uint64_t lost = 0;
    if (berti > 0) {
      for (int i = 0; i < berti; i++) {
        if (vector & ((uint64_t)1 << i)) {
          lost++;
        }
      }
    } else if (berti < 0) {
      for (int i = LLC_PAGE_OFFSET_MASK; i > LLC_PAGE_OFFSET_MASK + berti; i--) {
        if (vector & ((uint64_t)1 << i)) {
          lost++;
        }
      }
    }
    return lost;
  }

  // Check if all last blocks within berti where accessed
  bool llc_all_last_berti_accessed_bit_vector(uint64_t vector, int berti) {
    if (berti < 0) {
      for (int i = 0; i < berti; i++) {
        if (!(vector & ((uint64_t)1 << i))) {
          return false;
        }
      }
    } else if (berti > 0) {
      for (int i = LLC_PAGE_OFFSET_MASK; i > LLC_PAGE_OFFSET_MASK + berti; i--) {
        if (!(vector & ((uint64_t)1 << i))) {
          return false;
        }
      }
    }
    return true;
  }

  // CURRENT PAGES TABLE

#define LLC_CURRENT_PAGES_TABLE_INDEX_BITS 9
#define LLC_CURRENT_PAGES_TABLE_ENTRIES ((1 << LLC_CURRENT_PAGES_TABLE_INDEX_BITS) - 1) // Null pointer for prev_request
#define LLC_CURRENT_PAGES_TABLE_NUM_BERTI 6
#define LLC_CURRENT_PAGES_TABLE_NUM_BERTI_PER_ACCESS 6 // Better if not more than throttling

  typedef struct __llc_current_page_entry {
    uint64_t page_addr; // 52 bits
    uint64_t u_vector; // 64 bits
    int berti[LLC_CURRENT_PAGES_TABLE_NUM_BERTI]; // 70 bits
    unsigned berti_score[LLC_CURRENT_PAGES_TABLE_NUM_BERTI]; // XXX bits
    int current_berti; // 7 bits
    int stride; // Divide tables. Long reuse do not need to calculate berties
    bool short_reuse; // 1 bit
    bool continue_burst; // 1 bit
    uint64_t lru; // 6 bits
  } llc_current_page_entry;

  llc_current_page_entry llc_current_pages_table[LLC_CURRENT_PAGES_TABLE_ENTRIES];

  void llc_init_current_pages_table() {
    for (int i = 0; i < LLC_CURRENT_PAGES_TABLE_ENTRIES; i++) {
      llc_current_pages_table[i].page_addr = 0;
      llc_current_pages_table[i].u_vector = 0; // not valid
      for (int j = 0; j < LLC_CURRENT_PAGES_TABLE_NUM_BERTI; j++) {
        llc_current_pages_table[i].berti[j] = 0;
      }
      llc_current_pages_table[i].current_berti = 0;
      llc_current_pages_table[i].stride = 0;
      llc_current_pages_table[i].short_reuse = true;
      llc_current_pages_table[i].continue_burst = false;
      llc_current_pages_table[i].lru = i;
    }
  }

  uint64_t llc_get_current_pages_entry(uint64_t page_addr) {
    for (int i = 0; i < LLC_CURRENT_PAGES_TABLE_ENTRIES; i++) {
      if (llc_current_pages_table[i].page_addr == page_addr) return i;
    }
    return LLC_CURRENT_PAGES_TABLE_ENTRIES;
  }

  void llc_update_lru_current_pages_table(uint64_t index) {
    assert(index < LLC_CURRENT_PAGES_TABLE_ENTRIES);
    for (int i = 0; i < LLC_CURRENT_PAGES_TABLE_ENTRIES; i++) {
      if (llc_current_pages_table[i].lru < llc_current_pages_table[index].lru) { // Found
        llc_current_pages_table[i].lru++;
      }
    }
    llc_current_pages_table[index].lru = 0;
  }

  uint64_t llc_get_lru_current_pages_entry() {
    uint64_t lru = LLC_CURRENT_PAGES_TABLE_ENTRIES;
    for (int i = 0; i < LLC_CURRENT_PAGES_TABLE_ENTRIES; i++) {
      llc_current_pages_table[i].lru++;
      if (llc_current_pages_table[i].lru == LLC_CURRENT_PAGES_TABLE_ENTRIES) {
        llc_current_pages_table[i].lru = 0;
        lru = i;
      } 
    }
    assert(lru != LLC_CURRENT_PAGES_TABLE_ENTRIES);
    return lru;
  }

  void llc_add_current_pages_table(uint64_t index, uint64_t page_addr) {
    assert(index < LLC_CURRENT_PAGES_TABLE_ENTRIES);
    llc_current_pages_table[index].page_addr = page_addr;
    llc_current_pages_table[index].u_vector = 0;
    for (int i = 0; i < LLC_CURRENT_PAGES_TABLE_NUM_BERTI; i++) {
      llc_current_pages_table[index].berti[i] = 0;
    }
    llc_current_pages_table[index].continue_burst = false;
  }

  void llc_update_current_pages_table(uint64_t index, uint64_t offset) {
    assert(index < LLC_CURRENT_PAGES_TABLE_ENTRIES);
    llc_current_pages_table[index].u_vector |= (uint64_t)1 << offset;
    llc_update_lru_current_pages_table(index);
  }

  void llc_remove_offset_current_pages_table(uint64_t index, uint64_t offset) {
    assert(index < LLC_CURRENT_PAGES_TABLE_ENTRIES);
    llc_current_pages_table[index].u_vector &= !((uint64_t)1 << offset);
  }

  void llc_add_berti_current_pages_table(uint64_t index, int *berti, unsigned *saved_cycles) {
    assert(index < LLC_CURRENT_PAGES_TABLE_ENTRIES);

    // for each berti collected
    for (int i = 0; i < LLC_CURRENT_PAGES_TABLE_NUM_BERTI_PER_ACCESS; i++) {
      if (berti[i] == 0) break;
      //assert(abs(berti[i]) < LLC_PAGE_BLOCKS);

      for (int j = 0; j < LLC_CURRENT_PAGES_TABLE_NUM_BERTI; j++) {
        if (llc_current_pages_table[index].berti[j] == 0) {
          llc_current_pages_table[index].berti[j] = berti[i];
#ifdef BERTI_LATENCIES
          llc_current_pages_table[index].berti_score[j] = saved_cycles[i];
#else
          llc_current_pages_table[index].berti_score[j] = 1;
#endif
          break;
        } else if (llc_current_pages_table[index].berti[j] == berti[i]) {
#ifdef BERTI_LATENCIES
          llc_current_pages_table[index].berti_score[j] += saved_cycles[i];
#else
          llc_current_pages_table[index].berti_score[j]++;
          //assert(llc_current_pages_table[index].berti_score[j] < LLC_PAGE_BLOCKS);
#endif
#ifdef WARMUP_NEW_PAGES
          // For first time accessed pages. No wait until it is evicted to predict
          if (llc_current_pages_table[index].current_berti == 0
              && llc_current_pages_table[index].berti_score[j] > 2) {
            llc_current_pages_table[index].current_berti = berti[i];
          }
#endif
          break;
        }
      }
    }
    llc_update_lru_current_pages_table(index);
  }

  int llc_get_berti_current_pages_table(uint64_t index) {
    assert(index < LLC_CURRENT_PAGES_TABLE_ENTRIES);
    uint64_t vector = llc_current_pages_table[index].u_vector;
    int max_score = 0;
    uint64_t berti = 0;
    for (int i = 0; i < LLC_CURRENT_PAGES_TABLE_NUM_BERTI; i++) {
      int curr_berti = llc_current_pages_table[index].berti[i];
      if (curr_berti != 0) { 
        // For every miss reduce next level access latency
        int score = llc_current_pages_table[index].berti_score[i];
#if defined(BERTI_LATENCIES) || defined(JUST_BERTI)
        int neg_score = 0; //llc_count_wrong_berti_bit_vector(vector, curr_berti) * LLC_MISS_LATENCY;
#else 
        int neg_score = 0 - abs(curr_berti);
        // ((abs(curr_berti) >> 1) + (abs(curr_berti) >> 2));
        //llc_count_wrong_berti_bit_vector(vector, curr_berti) - llc_count_lost_berti_bit_vector(vector, curr_berti);
#endif
        // Modify score based on bad prefetches
        if (score < neg_score) {
          score = 0;
        } else { 
          score -= neg_score;
        }
        if (score >= max_score) { // In case of a draw we choose the larger, since we have bursts 
          berti = curr_berti;
          max_score = score;
        }
      }
    }
    return berti;
  }

  bool llc_offset_requested_current_pages_table(uint64_t index, uint64_t offset) {
    assert(index < LLC_CURRENT_PAGES_TABLE_ENTRIES);
    assert(offset < LLC_PAGE_BLOCKS);
    return llc_current_pages_table[index].u_vector & ((uint64_t)1 << offset);
  }

  // PREVIOUS REQUESTS TABLE

#define LLC_PREV_REQUESTS_TABLE_INDEX_BITS 13
#define LLC_PREV_REQUESTS_TABLE_ENTRIES (1 << LLC_PREV_REQUESTS_TABLE_INDEX_BITS)
#define LLC_PREV_REQUESTS_TABLE_MASK (LLC_PREV_REQUESTS_TABLE_ENTRIES - 1)
#define LLC_PREV_REQUESTS_TABLE_NULL_POINTER LLC_CURRENT_PAGES_TABLE_ENTRIES

  typedef struct __llc_prev_request_entry {
    uint64_t page_addr_pointer; // 6 bits
    uint64_t offset; // 6 bits
    uint64_t time; // 16 bits
  } llc_prev_request_entry;

  llc_prev_request_entry llc_prev_requests_table[LLC_PREV_REQUESTS_TABLE_ENTRIES];
  uint64_t llc_prev_requests_table_head;

  void llc_init_prev_requests_table() {
    llc_prev_requests_table_head = 0;
    for (int i = 0; i < LLC_PREV_REQUESTS_TABLE_ENTRIES; i++) {
      llc_prev_requests_table[i].page_addr_pointer = LLC_PREV_REQUESTS_TABLE_NULL_POINTER;
    }
  }

  uint64_t llc_find_prev_request_entry(uint64_t pointer, uint64_t offset) {
    for (int i = 0; i < LLC_PREV_REQUESTS_TABLE_ENTRIES; i++) {
      if (llc_prev_requests_table[i].page_addr_pointer == pointer
          && llc_prev_requests_table[i].offset == offset) return i;
    }
    return LLC_PREV_REQUESTS_TABLE_ENTRIES;
  }

  void llc_add_prev_requests_table(uint64_t pointer, uint64_t offset, uint64_t cycle) {
    // First find for coalescing
    if (llc_find_prev_request_entry(pointer, offset) != LLC_PREV_REQUESTS_TABLE_ENTRIES) return;

    // Allocate a new entry (evict old one if necessary)
    llc_prev_requests_table[llc_prev_requests_table_head].page_addr_pointer = pointer;
    llc_prev_requests_table[llc_prev_requests_table_head].offset = offset;
    llc_prev_requests_table[llc_prev_requests_table_head].time = cycle & LLC_TIME_MASK;
    llc_prev_requests_table_head = (llc_prev_requests_table_head + 1) & LLC_PREV_REQUESTS_TABLE_MASK;
  }

  void llc_reset_pointer_prev_requests(uint64_t pointer) {
    for (int i = 0; i < LLC_PREV_REQUESTS_TABLE_ENTRIES; i++) {
      if (llc_prev_requests_table[i].page_addr_pointer == pointer) {
        llc_prev_requests_table[i].page_addr_pointer = LLC_PREV_REQUESTS_TABLE_NULL_POINTER;
      }
    }
  }

  // req_time is 0 if already requested (fill) or current time if (hit)
  void llc_get_berti_prev_requests_table(uint64_t pointer, uint64_t offset, uint64_t latency, int *berti, unsigned *saved_cycles, uint64_t req_time) {
    int my_pos = 0;
    uint64_t extra_time = 0;
    uint64_t last_time = llc_prev_requests_table[(llc_prev_requests_table_head + LLC_PREV_REQUESTS_TABLE_MASK) & LLC_PREV_REQUESTS_TABLE_MASK].time;
    for (uint64_t i = (llc_prev_requests_table_head + LLC_PREV_REQUESTS_TABLE_MASK) & LLC_PREV_REQUESTS_TABLE_MASK; i != llc_prev_requests_table_head; i = (i + LLC_PREV_REQUESTS_TABLE_MASK) & LLC_PREV_REQUESTS_TABLE_MASK) {
      // Against the time overflow
      if (last_time < llc_prev_requests_table[i].time) {
        extra_time = LLC_TIME_OVERFLOW;
      }
      last_time = llc_prev_requests_table[i].time;  
      if (llc_prev_requests_table[i].page_addr_pointer == pointer) { // Same page
        if (llc_prev_requests_table[i].offset == offset) { // Its me
          req_time = llc_prev_requests_table[i].time;
        } else if (req_time) { // Not me (check only older than me)
          if (llc_prev_requests_table[i].time <= req_time + extra_time - latency) {
            berti[my_pos] = llc_calculate_stride(llc_prev_requests_table[i].offset, offset);
            saved_cycles[my_pos] = latency;
            my_pos++;
          } else if (req_time + extra_time - llc_prev_requests_table[i].time > 0) { // Only if some savings
#ifdef BERTI_LATENCIES
            berti[my_pos] = llc_calculate_stride(llc_prev_requests_table[i].offset, offset);
            saved_cycles[my_pos] = req_time + extra_time - llc_prev_requests_table[i].time;
            my_pos++;
#endif
          }
          if (my_pos == LLC_CURRENT_PAGES_TABLE_NUM_BERTI_PER_ACCESS) {
            berti[my_pos] = 0;
            return;
          }
        }
      }
    }
    berti[my_pos] = 0;
  }

  // RECORD PAGES TABLE

  typedef struct __llc_record_page_entry {
    uint64_t linnea; // 8 bytes
    uint64_t last_offset; // 6 bits
    bool short_reuse; // 1 bit
  } llc_record_page_entry;

  unordered_map<uint64_t, llc_record_page_entry> llc_record_pages_table;

  void llc_add_record_pages_table(uint64_t page_addr, uint64_t new_page_addr, uint64_t last_offset = 0, bool short_reuse = true) {
    llc_record_pages_table[page_addr].linnea = new_page_addr;
    llc_record_pages_table[page_addr].last_offset = last_offset;
    llc_record_pages_table[page_addr].short_reuse = short_reuse;
  }


  // IP TABLE

#define LLC_IP_TABLE_INDEX_BITS 16
#define LLC_IP_TABLE_ENTRIES (1 << LLC_IP_TABLE_INDEX_BITS)
#define LLC_IP_TABLE_INDEX_MASK (LLC_IP_TABLE_ENTRIES - 1)

  typedef struct __llc_ip_entry {
    bool current; // 1 bit
    int berti_or_pointer; // 7 bits // Berti if current == 0
    bool consecutive; // 1 bit
    bool short_reuse; // 1 bit
  } llc_ip_entry;

  llc_ip_entry llc_ip_table[LLC_IP_TABLE_ENTRIES];

  //Stats
  uint64_t llc_ip_misses[LLC_IP_TABLE_ENTRIES];
  uint64_t llc_ip_hits[LLC_IP_TABLE_ENTRIES];
  uint64_t llc_ip_late[LLC_IP_TABLE_ENTRIES];
  uint64_t llc_ip_early[LLC_IP_TABLE_ENTRIES];
  uint64_t llc_stats_pref_addr;
  uint64_t llc_stats_pref_ip;
  uint64_t llc_stats_pref_current;
  uint64_t cache_accesses;
  uint64_t cache_misses;

  void llc_init_ip_table() {
    for (int i = 0; i < LLC_IP_TABLE_ENTRIES; i++) {
      llc_ip_table[i].current = false;
      llc_ip_table[i].berti_or_pointer = 0;
      llc_ip_table[i].consecutive = false;
      llc_ip_table[i].short_reuse = true;

      llc_ip_misses[i] = 0;
      llc_ip_hits[i] = 0;
      llc_ip_late[i] = 0;
      llc_ip_early[i] = 0;
    }
    llc_stats_pref_addr = 0;
    llc_stats_pref_ip = 0;
    llc_stats_pref_current = 0;
    cache_accesses = 0;
    cache_misses = 0;
  }

  void llc_update_ip_table(int pointer, int berti, int stride, bool short_reuse) {
    for (int i = 0; i < LLC_IP_TABLE_ENTRIES; i++) {
      if (llc_ip_table[i].current
          && llc_ip_table[i].berti_or_pointer == pointer) {
        llc_ip_table[i].current = false;
        if (short_reuse) {
          llc_ip_table[i].berti_or_pointer = berti;
        } else {
          llc_ip_table[i].berti_or_pointer = stride;
        }
        llc_ip_table[i].short_reuse = short_reuse;
      }
    }
  }

  // INTERTABLES

  uint64_t llc_evict_lru_current_page_entry() {
    // Find victim and clear pointers to it
    uint64_t victim_index = llc_get_lru_current_pages_entry(); // already updates lru
    assert(victim_index < LLC_CURRENT_PAGES_TABLE_ENTRIES);

    // From all timely delta found, we record the best 
    if (llc_current_pages_table[victim_index].u_vector) { // Accessed entry

      // Update any IP pointing to it
      llc_update_ip_table(victim_index,
          llc_get_berti_current_pages_table(victim_index),
          llc_current_pages_table[victim_index].stride,
          llc_current_pages_table[victim_index].short_reuse);
    }

    llc_reset_pointer_prev_requests(victim_index); // Not valid anymore

    return victim_index;
  }

  void llc_evict_current_page_entry(uint64_t index) {
    assert(index < LLC_CURRENT_PAGES_TABLE_ENTRIES);

    // From all timely delta found, we record the best 
    if (llc_current_pages_table[index].u_vector) { // Accessed entry

      // Update any IP pointing to it
      llc_update_ip_table(index,
          llc_get_berti_current_pages_table(index),
          llc_current_pages_table[index].stride,
          llc_current_pages_table[index].short_reuse);
    }

    llc_reset_pointer_prev_requests(index); // Not valid anymore
  }

  void llc_remove_current_table_entry(uint64_t index) {
    llc_current_pages_table[index].page_addr = 0;
    llc_current_pages_table[index].u_vector = 0;
    for (int i = 0; i < LLC_CURRENT_PAGES_TABLE_NUM_BERTI; i++) {
      llc_current_pages_table[index].berti[i] = 0;
    }
  }
}

// INTERFACE

void CACHE::prefetcher_initialize() 
{
  // cout << "CPU " << cpu << " LLC Berti prefetcher" << endl;

  blue::llc_init_current_pages_table();
  blue::llc_init_prev_requests_table();
  blue::llc_init_ip_table();

}

uint32_t CACHE::prefetcher_cache_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type, uint32_t metadata_in)
{

  uint8_t count = 0;

  blue::cache_accesses++;
  if (!cache_hit) blue::cache_misses++;

  uint64_t line_addr = addr >> LOG2_BLOCK_SIZE;
  uint64_t page_addr = line_addr >> LLC_PAGE_BLOCKS_BITS;
  uint64_t offset = line_addr & LLC_PAGE_OFFSET_MASK;
  uint64_t ip_index = ip & LLC_IP_TABLE_INDEX_MASK;

  // ENTANGLED

  /* training */
  uint64_t bere = blue::llc_hist_buffer_get_bere(ip, ooo_cpu[cpu]->current_cycle, 0);
  uint64_t last = blue::llc_hist_buffer_get_last(ip, ooo_cpu[cpu]->current_cycle, 0);
  if (bere && line_addr != bere) {
    blue::bere_cache[bere] = line_addr;
  }
  if (bere && line_addr != bere) {
    blue::last_cache[last] = line_addr;
  }

  // Add the request in the history buffer
  //if ((llc_hist_buffer_find_entry(line_addr, ip) == LLC_HIST_BUFFER_ENTRIES)) {
  blue::llc_hist_buffer_add_entry(line_addr, ip, ooo_cpu[cpu]->current_cycle);
  //}

  /* prediction */
  if (warmup_complete[cpu]) {
    if (blue::bere_cache.find(line_addr) != blue::bere_cache.end()) {
      // issue prefetch
      bool prefetched = prefetch_line(blue::bere_cache[line_addr] << LOG2_BLOCK_SIZE, true, 1);
      //if (prefetched) llc_add_latencies_table(index, pf_offset, current_core_cycle[cpu]);
      count++;
      line_addr = blue::bere_cache[line_addr];
    }
    while (count < DEGREE && blue::last_cache.find(line_addr) != blue::last_cache.end()) {
      // issue prefetch
      bool prefetched = prefetch_line(blue::last_cache[line_addr] << LOG2_BLOCK_SIZE, true, 1);
      //if (prefetched) llc_add_latencies_table(index, pf_offset, current_core_cycle[cpu]);
      count++;
      line_addr = blue::last_cache[line_addr];
    }
  }




  int last_berti = 0;
  int berti = 0;
  bool linnea_hits = false;
  bool first_access = false;
  bool full_access = false;
  int stride = 0;
  bool short_reuse = true;

  // Find the entry in the current page table
  uint64_t index = blue::llc_get_current_pages_entry(page_addr);

  bool recently_accessed = false;
  if (index < LLC_CURRENT_PAGES_TABLE_ENTRIES) { // Hit in current page table
    recently_accessed = blue::llc_offset_requested_current_pages_table(index, offset);
  }

  if (index < LLC_CURRENT_PAGES_TABLE_ENTRIES  // Hit in current page table
      && blue::llc_current_pages_table[index].u_vector != 0) { // Used before

    // Within the same page we always predict the same
    last_berti = blue::llc_current_pages_table[index].current_berti;
    berti = last_berti;

    // Update accessed block vector
    blue::llc_update_current_pages_table(index, offset);

  } else { // First access to a new page

    first_access = true;

    // Find Berti and Linnea

    // Check IP table
    if (blue::llc_ip_table[ip_index].current) { // Here we check for Berti and Linnea

      int ip_pointer = blue::llc_ip_table[ip_index].berti_or_pointer;
      assert(ip_pointer < LLC_CURRENT_PAGES_TABLE_ENTRIES);
      // It will be a change of page for the IP

      // Get the last berti the IP is using and new berti to use
      last_berti = blue::llc_current_pages_table[ip_pointer].current_berti;
      berti = blue::llc_get_berti_current_pages_table(ip_pointer);

      // Get if all blocks for a potential burst were accessed
      full_access = blue::llc_all_last_berti_accessed_bit_vector(blue::llc_current_pages_table[ip_pointer].u_vector, berti);

      // Make the link (linnea)
      uint64_t last_page_addr = blue::llc_current_pages_table[ip_pointer].page_addr;

      short_reuse = (blue::llc_count_bit_vector(blue::llc_current_pages_table[ip_pointer].u_vector) > 2);
      if (short_reuse) {
        if (berti > 0 && last_page_addr + 1 == page_addr) {
          blue::llc_ip_table[ip_index].consecutive = true;
        } else if (berti < 0 && last_page_addr == page_addr + 1) {
          blue::llc_ip_table[ip_index].consecutive = true;
        } else { // Only add to record if not consecutive
          blue::llc_ip_table[ip_index].consecutive = false;
          blue::llc_add_record_pages_table(last_page_addr, page_addr);
        }
      } else {
        if (blue::llc_current_pages_table[ip_pointer].short_reuse) {
          blue::llc_current_pages_table[ip_pointer].short_reuse = false;
        }
        if (blue::llc_record_pages_table.find(last_page_addr) != blue::llc_record_pages_table.end()) {
          if (!blue::llc_record_pages_table[last_page_addr].short_reuse
              && blue::llc_record_pages_table[last_page_addr].linnea == page_addr) {
            stride = blue::llc_calculate_stride(blue::llc_record_pages_table[last_page_addr].last_offset, offset);
          }
        }

        if (!recently_accessed) { // If not accessed recently
          blue::llc_add_record_pages_table(last_page_addr, page_addr, offset, short_reuse);
        }
      }

    } else {
      berti = blue::llc_ip_table[ip_index].berti_or_pointer;
    }

    if (index == LLC_CURRENT_PAGES_TABLE_ENTRIES) { // Miss in current page table

      // Not found (linnea did not work or was not used -- berti == 0)

      // Add new page entry evicting a previous one.
      index = blue::llc_evict_lru_current_page_entry();
      blue::llc_add_current_pages_table(index, page_addr);

    } else { // First access, but linnea worked and blocks of the page have been prefetched
      linnea_hits = true;
    }

    // Update accessed block vector
    blue::llc_update_current_pages_table(index, offset);

  }

  // Update berti
  // Find berti distance from pref_latency cycles before
  int berties[LLC_CURRENT_PAGES_TABLE_NUM_BERTI_PER_ACCESS]; 
  unsigned saved_cycles[LLC_CURRENT_PAGES_TABLE_NUM_BERTI_PER_ACCESS]; 
  blue::llc_get_berti_prev_requests_table(index, offset, LLC_MISS_LATENCY, berties, saved_cycles, ooo_cpu[cpu]->current_cycle);
  if (!recently_accessed) { // If not accessed recently
    blue::llc_add_berti_current_pages_table(index, berties, saved_cycles);
  }	

  // Set the new berti
  if (!recently_accessed) { // If not accessed recently
    if (short_reuse) {
      blue::llc_current_pages_table[index].current_berti = berti;
    } else {
      blue::llc_current_pages_table[index].stride = stride;
    }
    blue::llc_current_pages_table[index].short_reuse = short_reuse;

    blue::llc_add_prev_requests_table(index, offset, ooo_cpu[cpu]->current_cycle);

    blue::llc_ip_table[ip_index].current = true;
    blue::llc_ip_table[ip_index].berti_or_pointer = index;
  }

  if (berti != 0) {

    // Burst mode
    if ((first_access && full_access) || blue::llc_current_pages_table[index].continue_burst) {
      int burst_init = 0;
      int burst_end = 0;
      int burst_it = 0;
      if (!linnea_hits || blue::llc_current_pages_table[index].continue_burst) { // Linnea missed: full burst
        blue::llc_current_pages_table[index].continue_burst = false;
        if (berti > 0) {
          burst_init = offset + 1;
          burst_end = offset + berti;
          burst_it = 1;
        } else {
          burst_init = offset - 1;
          burst_end = offset + berti;
          burst_it = -1;
        }
      } else if (last_berti > 0 && berti > 0 && berti > last_berti) { // larger abs berti: semi burst
        burst_init = last_berti;
        burst_end = berti;
        burst_it = 1;
      } else if (last_berti < 0 && berti < 0 && berti < last_berti) { // larger abs berti: semi burst
        burst_init = LLC_PAGE_OFFSET_MASK + last_berti;
        burst_end = LLC_PAGE_OFFSET_MASK + berti;
        burst_it = -1;
      }
      int bursts = 0;
      for (int i = burst_init; i != burst_end; i += burst_it) {
        if (i >= 0 && i < LLC_PAGE_BLOCKS) { // Burst are for the current page
          uint64_t pf_line_addr = (page_addr << LLC_PAGE_BLOCKS_BITS) | i;
          uint64_t pf_addr = pf_line_addr << LOG2_BLOCK_SIZE;
          uint64_t pf_offset = pf_line_addr & LLC_PAGE_OFFSET_MASK;
          // We are doing the berti here. Do not leave space for it
          if (warmup_complete[cpu] && count < 2 && bursts < LLC_BURST_THROTTLING) { 
            //if (ip_index == 0x10f) cout << "BURST PREFETCH " << hex << page_addr << dec << " <" << pf_offset << ">" << endl;
            bool prefetched = prefetch_line(pf_addr, true, 1);
            //assert(prefetched);
            //llc_add_latencies_table(index, pf_offset, current_core_cycle[cpu]);
            bursts++;
            count++;
          } else { // record last burst
#ifdef CONTINUE_BURST
            if (!recently_accessed) { // If not accessed recently
              llc_current_pages_table[index].continue_burst = true;
            }
#endif
            break;
          }
        }
      }
    }

    // Berti mode
    for (int i = 1; i <= LLC_BERTI_THROTTLING; i++) {

      uint64_t pf_line_addr = line_addr + (berti * i);
      uint64_t pf_addr = pf_line_addr << LOG2_BLOCK_SIZE;
      uint64_t pf_page_addr = pf_line_addr >> LLC_PAGE_BLOCKS_BITS;
      uint64_t pf_offset = pf_line_addr & LLC_PAGE_OFFSET_MASK;

      // If the prefetcher will be done
      if (warmup_complete[cpu] && count < 2) {

        // Same page, prefetch standard
        if (pf_page_addr == page_addr) { 
          //if (ip_index == 0x10f) cout << "BERTI PREFETCH " << hex << page_addr << dec << " <" << pf_offset << ">" << endl;
          bool prefetched = prefetch_line(pf_addr, true, 1);
          //assert(prefetched);
          //llc_add_latencies_table(index, pf_offset, current_core_cycle[cpu]);
          count++;

          // Out of page, try consecutive first
        } else if (blue::llc_ip_table[ip_index].consecutive && berti != 0) { 
          uint64_t new_page;
          if (berti < 0) {
            new_page = page_addr - 1;
          } else {
            new_page = page_addr + 1;
          }

          // Need to add the linnea page to current pages
          uint64_t new_index = blue::llc_get_current_pages_entry(new_page);

          if (new_index == LLC_CURRENT_PAGES_TABLE_ENTRIES) {

            // Add new page entry evicting a previous one.
            new_index = blue::llc_evict_lru_current_page_entry();
            blue::llc_add_current_pages_table(new_index, new_page);

          }

          uint64_t pf_offset = (offset + berti + LLC_PAGE_BLOCKS) & LLC_PAGE_OFFSET_MASK;
          uint64_t new_line = new_page << LLC_PAGE_BLOCKS_BITS;
          uint64_t new_pf_line = new_line | pf_offset;
          uint64_t new_addr = new_line << LOG2_BLOCK_SIZE;
          uint64_t new_pf_addr = new_pf_line << LOG2_BLOCK_SIZE;

          //cout << "CONSECUTIVE " << hex << new_page << " " << dec << pf_offset << hex << " " << " " << new_line << " " << new_pf_line << " " << new_addr << " " << new_pf_addr << dec << endl;

          //if (ip_index == 0x10f) cout << "CONSECUTIVE PREFETCH " << hex << new_page << dec << " <" << pf_offset << ">" << endl;
          bool prefetched = prefetch_line(new_pf_addr, true, 1);
          //assert(prefetched);
          //llc_add_latencies_table(new_index, pf_offset, current_core_cycle[cpu]);
          count++;
        } else { // Out of page, try Linnea
#ifdef LINNEA
          if (blue::llc_record_pages_table.find(page_addr) != blue::llc_record_pages_table.end()) { // Linnea found

            uint64_t new_page = blue::llc_record_pages_table[page_addr].linnea;

            // Need to add the linnea page to current pages
            uint64_t new_index = blue::llc_get_current_pages_entry(new_page);

            if (new_index == LLC_CURRENT_PAGES_TABLE_ENTRIES) {

              // Add new page entry evicting a previous one.
              new_index = blue::llc_evict_lru_current_page_entry();
              blue::llc_add_current_pages_table(new_index, new_page);

            }

            uint64_t pf_offset = (offset + berti + LLC_PAGE_BLOCKS) & LLC_PAGE_OFFSET_MASK;
            uint64_t new_line = new_page << LLC_PAGE_BLOCKS_BITS;
            uint64_t new_pf_line = new_line | pf_offset;
            uint64_t new_addr = new_line << LOG2_BLOCK_SIZE;
            uint64_t new_pf_addr = new_pf_line << LOG2_BLOCK_SIZE;

            //cout << "LINNEA " << hex << new_page << " " << dec << pf_offset << hex << " " << " " << new_line << " " << new_pf_line << " " << new_addr << " " << new_pf_addr << dec << endl;

            //if (ip_index == 0x10f) cout << "LINNEA PREFETCH " << hex << new_page << dec << " <" << pf_offset << ">" << endl;
            bool prefetched = prefetch_line(new_pf_addr, true, 1);
            //assert(prefetched);
            //llc_add_latencies_table(new_index, pf_offset, current_core_cycle[cpu]);
            count++;
          }
#endif
        }
      }
    }
  }

  if (!short_reuse) { // Use stride as it is a long reuse ip

    assert(!blue::llc_ip_table[ip_index].short_reuse || !blue::llc_current_pages_table[index].short_reuse);

    // If the prefetcher will be done
    if (warmup_complete[cpu] && count < 2) {
      if (blue::llc_record_pages_table.find(page_addr) != blue::llc_record_pages_table.end()) { // Linnea found

        uint64_t new_page = blue::llc_record_pages_table[page_addr].linnea;
        uint64_t new_offset = blue::llc_record_pages_table[page_addr].last_offset;
        int new_stride;
        int where;
        if (!blue::llc_current_pages_table[index].short_reuse) {
          new_stride = blue::llc_current_pages_table[index].stride;
          where = 1;
        } else {
          assert(!blue::llc_ip_table[ip_index].short_reuse);
          where = 2;
          new_stride = blue::llc_ip_table[ip_index].berti_or_pointer;
        }
        //if (ip_index == 0x10f) cout << "LONG REUSE PREFETCH " << hex << page_addr << "->" << new_page << " " << ip_index << dec << " " << new_offset << " " << new_stride << " " << where << endl;

        // Need to add the linnea page to current pages
        uint64_t new_index = blue::llc_get_current_pages_entry(new_page);

        if (new_index == LLC_CURRENT_PAGES_TABLE_ENTRIES) {

          // Add new page entry evicting a previous one.
          new_index = blue::llc_evict_lru_current_page_entry();
          blue::llc_add_current_pages_table(new_index, new_page);

        }

        uint64_t pf_offset = new_offset + new_stride;
        if (pf_offset >= 0 && pf_offset < LLC_PAGE_BLOCKS) {
          uint64_t new_line = new_page << LLC_PAGE_BLOCKS_BITS;
          uint64_t new_pf_line = new_line | pf_offset;
          uint64_t new_addr = new_line << LOG2_BLOCK_SIZE;
          uint64_t new_pf_addr = new_pf_line << LOG2_BLOCK_SIZE;

          //cout << "LINNEA " << hex << new_page << " " << dec << pf_offset << hex << " " << " " << new_line << " " << new_pf_line << " " << new_addr << " " << new_pf_addr << dec << endl;

          //if (ip_index == 0x10f) cout << "STRIDE PREFETCH " << hex << new_page << dec << " <" << pf_offset << ">" << endl;
          bool prefetched = prefetch_line(new_pf_addr, true, 0);
          //assert(prefetched);
          //llc_add_latencies_table(new_index, pf_offset, current_core_cycle[cpu]);
          count++;
        }
      }
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

