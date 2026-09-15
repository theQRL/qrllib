// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <sys/types.h>
#include <vector>

namespace {

enum class EntropyResult {
    bytes,
    interrupted,
    unavailable,
    permanent_error,
    zero
};

struct EntropyStep {
    EntropyResult result;
    size_t length;
};

std::deque<EntropyStep> getrandom_steps;
std::deque<EntropyStep> read_steps;
std::deque<int> open_errors;
std::vector<size_t> getrandom_requests;
std::vector<size_t> read_requests;
unsigned char next_byte;
unsigned int open_calls;
unsigned int close_calls;

ssize_t return_entropy_step(std::deque<EntropyStep> &steps,
                            unsigned char *buffer,
                            size_t request)
{
    if (steps.empty()) {
        errno = EIO;
        return -1;
    }

    const EntropyStep step = steps.front();
    steps.pop_front();
    switch (step.result) {
        case EntropyResult::bytes:
            for (size_t i = 0; i < std::min(step.length, request); ++i) {
                buffer[i] = next_byte++;
            }
            return static_cast<ssize_t>(step.length);
        case EntropyResult::interrupted:
            errno = EINTR;
            return -1;
        case EntropyResult::unavailable:
            errno = ENOSYS;
            return -1;
        case EntropyResult::permanent_error:
            errno = EIO;
            return -1;
        case EntropyResult::zero:
            return 0;
    }

    errno = EIO;
    return -1;
}

ssize_t fake_getrandom(unsigned char *buffer, size_t request, unsigned int)
{
    getrandom_requests.push_back(request);
    return return_entropy_step(getrandom_steps, buffer, request);
}

int fake_open(const char *, int)
{
    ++open_calls;
    if (!open_errors.empty()) {
        errno = open_errors.front();
        open_errors.pop_front();
        return -1;
    }
    return 7;
}

ssize_t fake_read(int, void *buffer, size_t request)
{
    read_requests.push_back(request);
    return return_entropy_step(read_steps,
                               static_cast<unsigned char *>(buffer),
                               request);
}

int fake_close(int)
{
    ++close_calls;
    return 0;
}

}  // namespace

#define QRLLIB_SYSTEM_RANDOM_MAX_EINTR_RETRIES 2U
#define QRLLIB_SYSTEM_RANDOM_GETRANDOM(buffer, length, flags) \
    fake_getrandom((buffer), (length), (flags))
#define QRLLIB_SYSTEM_RANDOM_OPEN(path, flags) fake_open((path), (flags))
#define QRLLIB_SYSTEM_RANDOM_READ(fd, buffer, length) \
    fake_read((fd), (buffer), (length))
#define QRLLIB_SYSTEM_RANDOM_CLOSE(fd) fake_close((fd))

#include "../../../src/crypto/system_random.cpp"

namespace {

class RandombytesTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        getrandom_steps.clear();
        read_steps.clear();
        open_errors.clear();
        getrandom_requests.clear();
        read_requests.clear();
        next_byte = 1;
        open_calls = 0;
        close_calls = 0;
        entropy_operation_depth = 0;
        entropy_operation_failed = false;
    }
};

TEST_F(RandombytesTest, RequestsOnlyTheRemainingBytes)
{
    std::array<unsigned char, 8> guarded;
    guarded.fill(0xa5);
    getrandom_steps = {
        {EntropyResult::bytes, 3},
        {EntropyResult::bytes, 1}
    };

    EXPECT_EQ(0, qrllib_system_random(guarded.data(), 4));
    EXPECT_EQ((std::vector<size_t>{4, 1}), getrandom_requests);
    EXPECT_EQ((std::array<unsigned char, 4>{1, 2, 3, 4}),
              (std::array<unsigned char, 4>{guarded[0], guarded[1],
                                             guarded[2], guarded[3]}));
    EXPECT_TRUE(std::all_of(guarded.begin() + 4,
                            guarded.end(),
                            [](unsigned char value) { return value == 0xa5; }));
}

TEST_F(RandombytesTest, ResetsInterruptBudgetAfterProgress)
{
    std::array<unsigned char, 4> output{};
    getrandom_steps = {
        {EntropyResult::interrupted, 0},
        {EntropyResult::interrupted, 0},
        {EntropyResult::bytes, 1},
        {EntropyResult::interrupted, 0},
        {EntropyResult::interrupted, 0},
        {EntropyResult::bytes, 3}
    };

    EXPECT_EQ(0, qrllib_system_random(output.data(), output.size()));
    EXPECT_EQ((std::array<unsigned char, 4>{1, 2, 3, 4}), output);
}

TEST_F(RandombytesTest, ExhaustedInterruptBudgetWipesTheWholeOutput)
{
    std::array<unsigned char, 4> output;
    output.fill(0xa5);
    getrandom_steps = {
        {EntropyResult::bytes, 2},
        {EntropyResult::interrupted, 0},
        {EntropyResult::interrupted, 0},
        {EntropyResult::interrupted, 0}
    };

    EXPECT_EQ(-1, qrllib_system_random(output.data(), output.size()));
    EXPECT_TRUE(std::all_of(output.begin(), output.end(),
                            [](unsigned char value) { return value == 0; }));
}

TEST_F(RandombytesTest, ZeroProgressWipesTheWholeOutput)
{
    std::array<unsigned char, 4> output;
    output.fill(0xa5);
    getrandom_steps = {
        {EntropyResult::bytes, 2},
        {EntropyResult::zero, 0}
    };

    EXPECT_EQ(-1, qrllib_system_random(output.data(), output.size()));
    EXPECT_TRUE(std::all_of(output.begin(), output.end(),
                            [](unsigned char value) { return value == 0; }));
}

TEST_F(RandombytesTest, PermanentErrorWipesTheWholeOutput)
{
    std::array<unsigned char, 4> output;
    output.fill(0xa5);
    getrandom_steps = {
        {EntropyResult::bytes, 2},
        {EntropyResult::permanent_error, 0}
    };

    EXPECT_EQ(-1, qrllib_system_random(output.data(), output.size()));
    EXPECT_TRUE(std::all_of(output.begin(), output.end(),
                            [](unsigned char value) { return value == 0; }));
    EXPECT_EQ(0U, open_calls);
}

TEST_F(RandombytesTest, FallbackUsesRemainingBytesAndResetsInterruptBudget)
{
    std::array<unsigned char, 8> guarded;
    guarded.fill(0xa5);
    getrandom_steps = {
        {EntropyResult::bytes, 2},
        {EntropyResult::unavailable, 0}
    };
    open_errors = {EINTR, EINTR};
    read_steps = {
        {EntropyResult::interrupted, 0},
        {EntropyResult::interrupted, 0},
        {EntropyResult::bytes, 1},
        {EntropyResult::interrupted, 0},
        {EntropyResult::interrupted, 0},
        {EntropyResult::bytes, 1}
    };

    EXPECT_EQ(0, qrllib_system_random(guarded.data(), 4));
    EXPECT_EQ((std::vector<size_t>{4, 2}), getrandom_requests);
    EXPECT_EQ((std::vector<size_t>{2, 2, 2, 1, 1, 1}), read_requests);
    EXPECT_EQ(3U, open_calls);
    EXPECT_EQ(1U, close_calls);
    EXPECT_EQ((std::array<unsigned char, 4>{1, 2, 3, 4}),
              (std::array<unsigned char, 4>{guarded[0], guarded[1],
                                             guarded[2], guarded[3]}));
    EXPECT_TRUE(std::all_of(guarded.begin() + 4,
                            guarded.end(),
                            [](unsigned char value) { return value == 0xa5; }));
}

TEST_F(RandombytesTest, FallbackFailureWipesAllPrimaryAndFallbackProgress)
{
    std::array<unsigned char, 4> output;
    output.fill(0xa5);
    getrandom_steps = {
        {EntropyResult::bytes, 1},
        {EntropyResult::unavailable, 0}
    };
    read_steps = {
        {EntropyResult::bytes, 1},
        {EntropyResult::zero, 0}
    };

    EXPECT_EQ(-1, qrllib_system_random(output.data(), output.size()));
    EXPECT_TRUE(std::all_of(output.begin(), output.end(),
                            [](unsigned char value) { return value == 0; }));
    EXPECT_EQ(1U, close_calls);
}

TEST_F(RandombytesTest, HandlesEmptyAndInvalidBuffers)
{
    EXPECT_EQ(0, qrllib_system_random(nullptr, 0));
    EXPECT_EQ(-1, qrllib_system_random(nullptr, 1));
    EXPECT_TRUE(getrandom_requests.empty());
}

TEST_F(RandombytesTest, LegacyCallbackRecordsFailureForItsOperation)
{
    std::array<unsigned char, 4> output;
    output.fill(0xa5);
    getrandom_steps = {{EntropyResult::permanent_error, 0}};

    qrllib_entropy_operation_begin();
    randombytes(output.data(), output.size());

    EXPECT_EQ(-1, qrllib_entropy_operation_end());
    EXPECT_TRUE(std::all_of(output.begin(), output.end(),
                            [](unsigned char value) { return value == 0; }));
}

}  // namespace
