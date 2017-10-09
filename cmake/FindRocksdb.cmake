#  ROCKSDB_FOUND
#  ROCKSDB_LIBRARIES         Rocksdb libs
#  ROCKSDB_INCLUDE_DIR       Rocksdb headers

include(FindPackageHandleStandardArgs)

find_path(ROCKSDB_ROOT_DIR
        NAMES include/rocksdb/db.h
        )

find_library(ROCKSDB_LIBRARIES
        NAMES rocksdb
        HINTS ${ROCKSDB_ROOT_DIR}
        )

find_path(ROCKSDB_INCLUDE_DIR
        NAMES rocksdb/db.h
        HINTS ${ROCKSDB_ROOT_DIR}/include
        )

find_package_handle_standard_args(Rocksdb DEFAULT_MSG
        ROCKSDB_LIBRARIES
        ROCKSDB_INCLUDE_DIR
        )

mark_as_advanced(
        ROCKSDB_ROOT_DIR
        ROCKSDB_LIBRARIES
        ROCKSDB_INCLUDE_DIR
)