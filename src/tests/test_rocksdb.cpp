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

        EXPECT_TRUE(status.ok());

        delete db;
    }

    TEST(RocksDB, ReadWriteStrings) {
        rocksdb::DB* db;
        rocksdb::Options options;
        options.create_if_missing = true;

        rocksdb::Status status =
                rocksdb::DB::Open(options, "/tmp/testdb", &db);

        std::string key = "test";
        std::string value = "test_value";
        std::string value_back;

        auto s = db->Put(rocksdb::WriteOptions(), key, value);
        EXPECT_TRUE(status.ok());

        s = db->Get(rocksdb::ReadOptions(), key, &value_back);
        EXPECT_TRUE(status.ok());
        EXPECT_EQ(value, value_back);

        delete db;
    }

//    TEST(RocksDB, ReadWriteVectors) {
//        rocksdb::DB* db;
//        rocksdb::Options options;
//        options.create_if_missing = true;
//
//        rocksdb::Status status =
//                rocksdb::DB::Open(options, "/tmp/testdb", &db);
//
//        std::vector<unsigned char> key {1, 2, 3, 4};
//        std::vector<unsigned char> value {1, 2, 3, 4};
//        std::string value_back;
//
//        auto s = db->Put(rocksdb::WriteOptions(), key, value);
//        EXPECT_TRUE(status.ok());
//
//        s = db->Get(rocksdb::ReadOptions(), key, &value_back);
//        EXPECT_TRUE(status.ok());
//        EXPECT_EQ(value, value_back);
//
//        s = db->Delete(rocksdb::WriteOptions(), key);
//        EXPECT_EQ(value, value_back);
//
//        s = db->Get(rocksdb::ReadOptions(), key, &value_back);
//        EXPECT_FALSE(status.ok());
//
//        delete db;
//    }

}