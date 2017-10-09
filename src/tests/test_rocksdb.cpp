// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include <rocksdb/db.h>

namespace {

    TEST(RocksDB, CreateTest) {
        rocksdb::DB* db;
        rocksdb::Options options;
        options.create_if_missing = true;
        rocksdb::Status status =
                rocksdb::DB::Open(options, "/tmp/testdb", &db);
        assert(status.ok());
    }
}