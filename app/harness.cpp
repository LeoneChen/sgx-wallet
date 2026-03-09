/*
 * EnclaveFuzz - SGX Enclave Fuzzing Test Harness (Auto-Generated)
 *
 * Generated from EDL: enclave.edl
 *
 * ============================================================================
 * Fuzzing Framework Architecture
 * ============================================================================
 *
 * Initialization (once):
 *     LibFuzzer → LLVMFuzzerInitialize()
 *                  ↓
 *                 customized_init()  ← Register harnesses, calculate weights
 *
 * Fuzzing loop (per input):
 *     LibFuzzer → LLVMFuzzerTestOneInput(data, size)
 *                  ↓ Reinitialize g_fdp with new input
 *                  ↓ Recreate enclave (__g_harness_eid)
 *                  ↓
 *                 customized_harness()  ← Weighted selection
 *                  ↓
 *                 _harness_xxx()   ← Auto-generated test functions
 *                  ↓
 *                 ECall → Enclave Code
 *
 * ============================================================================
 * EDL Attribute Reference
 * ============================================================================
 *
 * | Attribute    | Meaning             | Fuzzing Strategy (ECall)         |
 * |--------------|---------------------|----------------------------------|
 * | [in]         | Input to callee     | Generate fuzzy data (Host→Encl)  |
 * | [out]        | Output from callee  | Allocate buffer (Encl→Host)      |
 * | [in,out]     | Bidirectional       | Generate input + allocate        |
 * | [size=N]     | Buffer size (bytes) | Use N for allocation             |
 * | [count=N]    | Array element count | Use N * sizeof(element)          |
 * | [string]     | Null-terminated str | Ensure null terminator           |
 * | [user_check] | No auto checking    | High fuzz value                  |
 *
 * CRITICAL: Direction Semantics ([in]/[out] relative to callee)
 * - For ECalls (Enclave is callee):
 *   [in] = Host→Enclave → FUZZ THIS in harness
 *   [out] = Enclave→Host → Allocate buffer only
 * - For OCalls (Host is callee):
 *   [in] = Enclave→Host → No fuzzing needed
 *   [out] = Host→Enclave → FUZZ THIS in OCall wrapper
 *
 * ============================================================================
 * Memory Management (Two Approaches)
 * ============================================================================
 * Approach 1 (Auto-Managed by g_alloc_mgr) - CURRENT DEFAULT:
 * - Use calloc() + g_alloc_mgr.push_back() to track allocations
 * - Framework in LLVMFuzzerTestOneInput (at test.cpp) automatically frees all
 * tracked memory after each iteration
 * - No explicit free() needed in harness functions
 * - Pros: Simple, no memory leaks, centralized cleanup
 * - Cons: Memory accumulates until end of iteration
 *
 * Approach 2 (Explicit free()):
 * - Use calloc() without g_alloc_mgr tracking
 * - Manually write free() calls at appropriate locations in harness code
 * - Pros: Immediate memory release, lower memory footprint
 * - Cons: Must ensure all allocations are freed, risk of memory leaks
 *
 * Usage: Choose approach based on your needs:
 * - Default: g_alloc_mgr for safety and simplicity
 * - Manual: Direct free() for memory-sensitive scenarios
 *
 * ============================================================================
 * Weighted Selection System
 * ============================================================================
 * Each harness has a weight (default: 10). Adjust weights in customized_init():
 * - High weight (e.g., 50-100) for critical/bottleneck paths
 * - Low weight (e.g., 1-5) for well-covered paths
 * - Modify test_harness_registry[i].weight before calculating total_weight
 *
 * ============================================================================
 */

#include "FuzzedDataProvider.h"
#include "enclave_u.h"
#include <errno.h>
#include <sgx_urts.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

template <typename T> constexpr size_t safe_sizeof() {
  return sizeof(
      typename std::conditional<std::is_void<T>::value, char, T>::type);
}

// ============================================================================
// Global Variables
// ============================================================================

extern FuzzedDataProvider *g_fdp;
extern std::vector<uint8_t *> g_alloc_mgr;
extern sgx_enclave_id_t __g_harness_eid;

// Fuzzing configuration parameters
static size_t g_max_strlen = 128; // Max string length for [string] attributes
static size_t g_max_cnt = 32;     // Max count for unbounded arrays
static size_t g_max_size = 512;   // Max size for unbounded buffers

// ============================================================================
// Test Harness Registration System
// ============================================================================

typedef void (*TestHarness)(void);

struct TestHarnessEntry {
  TestHarness function;
  int weight; // Selection weight (default: 10)
};

static TestHarnessEntry test_harness_registry[10240];
static unsigned int test_harness_count = 0;
static int total_weight = 0;

// ============================================================================
// OCall Wrappers
// ============================================================================
// These wrappers intercept OCalls and fuzz [out] parameters
// to test Enclave's resilience to untrusted data
// ============================================================================

extern "C" void _harness_ocall_debug_print(const char *str) {
  ocall_debug_print(str);
}

extern "C" int _harness_ocall_save_wallet(const uint8_t *sealed_data,
                                          size_t sealed_size) {
  int _fuzz_ret = ocall_save_wallet(sealed_data, sealed_size);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int _harness_ocall_load_wallet(uint8_t *sealed_data,
                                          size_t sealed_size) {
  int _fuzz_ret = ocall_load_wallet(sealed_data, sealed_size);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_sealed_data = ((1) * (sealed_size)) / sizeof(uint8_t);
    g_fdp->ConsumeData((void *)sealed_data,
                       count_0_sealed_data * sizeof(uint8_t));
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int _harness_ocall_is_wallet(void) {
  int _fuzz_ret = ocall_is_wallet();
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" void _harness_sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf) {
  sgx_oc_cpuidex(cpuinfo, leaf, subleaf);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
      g_fdp->ConsumeData(&cpuinfo[i_0_0], sizeof(int));
    }
  }
}

extern "C" int
_harness_sgx_thread_wait_untrusted_event_ocall(const void *self) {
  int _fuzz_ret = sgx_thread_wait_untrusted_event_ocall(self);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_self =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)self, count_0_self * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_set_untrusted_event_ocall(const void *waiter) {
  int _fuzz_ret = sgx_thread_set_untrusted_event_ocall(waiter);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_waiter =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)waiter, count_0_waiter * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_setwait_untrusted_events_ocall(const void *waiter,
                                                   const void *self) {
  int _fuzz_ret = sgx_thread_setwait_untrusted_events_ocall(waiter, self);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_waiter =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)waiter, count_0_waiter * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_self =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)self, count_0_self * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_set_multiple_untrusted_events_ocall(const void **waiters,
                                                        size_t total) {
  int _fuzz_ret =
      sgx_thread_set_multiple_untrusted_events_ocall(waiters, total);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

// ============================================================================
// ECall Test Harnesses
// ============================================================================
// Auto-generated harness functions for each ECall
// Each function prepares fuzz inputs and invokes the corresponding ECall
// ============================================================================

static void _harness_ecall_create_wallet(void) {
  int _fuzz_ret;
  char *master_password = NULL;
  size_t master_password_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  master_password = (char *)calloc(master_password_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)master_password);
  g_fdp->ConsumeData(master_password, master_password_strlen * sizeof(char));
  ecall_create_wallet(__g_harness_eid, &_fuzz_ret, master_password);
}
static void _harness_ecall_show_wallet(void) {
  int _fuzz_ret;
  char *master_password = NULL;
  size_t master_password_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  master_password = (char *)calloc(master_password_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)master_password);
  g_fdp->ConsumeData(master_password, master_password_strlen * sizeof(char));
  wallet_t *wallet = NULL;
  size_t wallet_size;
  wallet_size = g_fdp->ConsumeIntegralInRange<size_t>(1, g_max_size);
  wallet = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_wallet = ((1) * (wallet_size) + 1 - 1) / 1;
    wallet = (wallet_t *)calloc(count_0_wallet, 1);
    g_alloc_mgr.push_back((uint8_t *)wallet);
  }
  ecall_show_wallet(__g_harness_eid, &_fuzz_ret, master_password, wallet,
                    wallet_size);
}
static void _harness_ecall_change_master_password(void) {
  int _fuzz_ret;
  char *old_password = NULL;
  size_t old_password_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  old_password = (char *)calloc(old_password_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)old_password);
  g_fdp->ConsumeData(old_password, old_password_strlen * sizeof(char));
  char *new_password = NULL;
  size_t new_password_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  new_password = (char *)calloc(new_password_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)new_password);
  g_fdp->ConsumeData(new_password, new_password_strlen * sizeof(char));
  ecall_change_master_password(__g_harness_eid, &_fuzz_ret, old_password,
                               new_password);
}
static void _harness_ecall_add_item(void) {
  int _fuzz_ret;
  char *master_password = NULL;
  size_t master_password_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  master_password = (char *)calloc(master_password_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)master_password);
  g_fdp->ConsumeData(master_password, master_password_strlen * sizeof(char));
  item_t *item = NULL;
  size_t item_size;
  item_size = g_fdp->ConsumeIntegralInRange<size_t>(1, g_max_size);
  item = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_item = ((1) * (item_size) + 1 - 1) / 1;
    item = (item_t *)calloc(count_0_item, 1);
    g_alloc_mgr.push_back((uint8_t *)item);
    g_fdp->ConsumeData((void *)item, count_0_item * 1);
  }
  ecall_add_item(__g_harness_eid, &_fuzz_ret, master_password, item, item_size);
}
static void _harness_ecall_remove_item(void) {
  int _fuzz_ret;
  char *master_password = NULL;
  size_t master_password_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  master_password = (char *)calloc(master_password_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)master_password);
  g_fdp->ConsumeData(master_password, master_password_strlen * sizeof(char));
  int index;
  g_fdp->ConsumeData(&index, sizeof(int));
  ecall_remove_item(__g_harness_eid, &_fuzz_ret, master_password, index);
}

// ============================================================================
// Customized Initialization
// ============================================================================
// This function is called once during fuzzer initialization
// (LLVMFuzzerInitialize).
//
// REQUIRED: Register all test harnesses by filling test_harness_registry[]
//
// Usage:
//   test_harness_registry[test_harness_count++] = {harness_function, weight};
//
// IMPORTANT:
// - This function is called BEFORE any fuzzing iterations start
// - DO NOT create or initialize the enclave here (__g_harness_eid will be 0)
// - DO NOT access g_fdp here (it's not initialized yet)
// - Keep initialization lightweight and fast
// - Weight MUST be > 0 for all harnesses
//
// Optional: Add custom initialization such as:
// - Environment variable configuration (setenv, putenv)
// - Global state initialization
// - Logging/debugging setup
// - Resource pre-allocation
// - Configuration file loading
// ============================================================================

extern "C" void customized_init() {
  // ========================================================================
  // Step 1: Register all test harnesses
  // ========================================================================
  test_harness_registry[test_harness_count++] = {
      _harness_ecall_create_wallet, 10}; // Test ecall_create_wallet
  test_harness_registry[test_harness_count++] = {_harness_ecall_show_wallet,
                                                 10}; // Test ecall_show_wallet
  test_harness_registry[test_harness_count++] = {
      _harness_ecall_change_master_password,
      10}; // Test ecall_change_master_password
  test_harness_registry[test_harness_count++] = {_harness_ecall_add_item,
                                                 10}; // Test ecall_add_item
  test_harness_registry[test_harness_count++] = {_harness_ecall_remove_item,
                                                 10}; // Test ecall_remove_item

  // ========================================================================
  // Step 2: Calculate total weight for weighted random selection
  // ========================================================================

  // Sanity check: ensure at least one harness is registered
  if (test_harness_count == 0) {
    fprintf(stderr, "[!] Error: No test harnesses registered\n");
    abort();
  }

  total_weight = 0;
  for (unsigned int i = 0; i < test_harness_count; i++) {
    total_weight += test_harness_registry[i].weight;
  }

  // Sanity check: ensure total weight > 0
  if (total_weight == 0) {
    fprintf(stderr, "[!] Error: All harness weights are 0\n");
    abort();
  }

  // ========================================================================
  // Step 3: Custom initialization (optional)
  // ========================================================================
  // Examples:
  // - setenv("SGX_AESM_ADDR", "1", 1);
  // - freopen("/tmp/fuzzer.log", "w", stderr);
  // - Initialize global variables
  // - Pre-load configuration files
}

// ============================================================================
// Main Test Entry Point
// ============================================================================
// Called by LLVMFuzzerTestOneInput for each fuzzing iteration
// Performs weighted random selection of test harnesses
// ============================================================================

extern "C" void customized_harness(void) {
  // Weighted random selection
  do {
    int rand_val = g_fdp->ConsumeIntegralInRange<int>(0, total_weight - 1);
    int cumulative = 0;
    for (unsigned int i = 0; i < test_harness_count; i++) {
      cumulative += test_harness_registry[i].weight;
      if (rand_val < cumulative) {
        test_harness_registry[i].function();
        break;
      }
    }
  } while (g_fdp->remaining_bytes() > 0);
}
