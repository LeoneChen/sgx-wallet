#include "app.h"
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

extern "C" void sgxfuzz_log(int ll, bool with_prefix, const char *fmt, ...);
extern "C" int SGXFuzzerEnvClearBeforeTest() {
  // rm wallet.seal
  std::error_code ec;
  fs::remove(fs::path(WALLET_FILE), ec);
  if (ec) {
    sgxfuzz_log(1, true, "rm wallet.seal: %s\n", ec.message().c_str());
  }
  return 0;
}
