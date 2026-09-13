// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <array>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <xmssBasic.h>
#include <xmssFast.h>
#include "gtest/gtest.h"

namespace {
thread_local int allocationsBeforeFailure = -1;
thread_local bool failAfterTreeAllocation = false;
thread_local bool failTreeAllocation = false;
thread_local size_t treeAllocations = 0;
thread_local size_t liveTrees = 0;
thread_local void* treePointer = nullptr;

struct FailureScope {
    ~FailureScope()
    {
        allocationsBeforeFailure = -1;
        failAfterTreeAllocation = false;
        failTreeAllocation = false;
    }
};

void* trackedMalloc(size_t size)
{
    if (failTreeAllocation) return nullptr;
    void* pointer = std::malloc(size);
    if (pointer) {
        ++treeAllocations;
        ++liveTrees;
        treePointer = pointer;
    }
    return pointer;
}

void trackedFree(void* pointer)
{
    if (pointer) {
        --liveTrees;
        treePointer = nullptr;
    }
    std::free(pointer);
}
}

// Keep allocation overrides in this executable, away from the normal tests.
void* operator new(size_t size)
{
    if ((failAfterTreeAllocation && liveTrees) || allocationsBeforeFailure == 0) {
        allocationsBeforeFailure = -1;
        failAfterTreeAllocation = false;
        throw std::bad_alloc();
    }
    if (allocationsBeforeFailure > 0) --allocationsBeforeFailure;
    if (void* pointer = std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}

void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, size_t) noexcept { std::free(pointer); }

// Instrument the real tree code without adding production test hooks. Standard
// headers are included above so these macros only intercept its malloc/free.
// These definitions satisfy the archive's symbols instead of algsxmss.c.o.
#define malloc trackedMalloc
#define free trackedFree
#include "xmss-alt/algsxmss.c"
#undef malloc
#undef free

namespace {
// All copied signers use this same message to avoid demonstrating OTS reuse
// across different messages.
const TMESSAGE message(32, 0x5a);

class XmssAllocation : public ::testing::Test {
protected:
    void SetUp() override { treeAllocations = 0; }
    void TearDown() override
    {
        FailureScope reset;
        EXPECT_EQ(0u, liveTrees);
        // Clean up a leaked allocation if the regression is reintroduced.
        if (treePointer) trackedFree(treePointer);
    }
};

TEST_F(XmssAllocation, Sha2ExceptionReleasesAllocatedTree)
{
    XmssBasic signer(TSEED(48, 1), 4, eHashFunction::SHA2_256,
                     eAddrFormatType::SHA256_2X);
    bool threw = false;
    {
        FailureScope reset;
        failAfterTreeAllocation = true;
        try { signer.sign(message); }
        catch (const std::bad_alloc&) { threw = true; }
    }
    ASSERT_TRUE(threw);
    EXPECT_EQ(1u, treeAllocations);
    ASSERT_EQ(0u, liveTrees);
    EXPECT_EQ(1u, signer.getIndex());
    EXPECT_TRUE(XmssBase::verify(message, signer.sign(message), signer.getPK()));
    EXPECT_EQ(2u, signer.getIndex());
}

TEST_F(XmssAllocation, NullTreeAllocationConsumesIndexAndAllowsRetry)
{
    XmssBasic signer(TSEED(48, 2), 4, eHashFunction::SHAKE_128,
                     eAddrFormatType::SHA256_2X);
    bool threw = false;
    {
        FailureScope reset;
        failTreeAllocation = true;
        try { signer.sign(message); }
        catch (const std::runtime_error&) { threw = true; }
    }
    ASSERT_TRUE(threw);
    EXPECT_EQ(0u, treeAllocations);
    EXPECT_EQ(1u, signer.getIndex());
    const auto signature = signer.sign(message);
    ASSERT_GE(signature.size(), 4u);
    EXPECT_EQ(1u, signature[3]);
    EXPECT_TRUE(XmssBase::verify(message, signature, signer.getPK()));
    EXPECT_EQ(2u, signer.getIndex());
    EXPECT_EQ(1u, treeAllocations);
}

TEST_F(XmssAllocation, SuccessfulSigningReleasesTreeForEveryHashFunction)
{
    for (auto hash : {eHashFunction::SHA2_256, eHashFunction::SHAKE_128,
                      eHashFunction::SHAKE_256}) {
        XmssBasic signer(TSEED(48, 3), 4, hash, eAddrFormatType::SHA256_2X);
        EXPECT_TRUE(XmssBase::verify(message, signer.sign(message), signer.getPK()));
        EXPECT_EQ(0u, liveTrees);
    }
    EXPECT_EQ(3u, treeAllocations);
}

class SignerProbe : public XmssFast {
public:
    using XmssFast::XmssFast;

    std::array<uint32_t, 13> parameters() const
    {
        const auto& w = params.wots_par;
        return {{_height, static_cast<uint32_t>(_hashFunction),
                 static_cast<uint32_t>(_addrFormatType), params.n, params.h, params.k,
                 w.len_1, w.len_2, w.len, w.n, w.w, w.log_w, w.keysize}};
    }

    std::array<const void*, 9> buffers() const
    {
        return {{_sk.data(), _seed.data(), _stack.data(), _stacklevels.data(),
                 _auth.data(), _keep.data(), _treehash.data(), _th_nodes.data(),
                 _retain.data()}};
    }

    bool ownsState() const
    {
        if (_state.stack != _stack.data() || _state.stacklevels != _stacklevels.data()
            || _state.auth != _auth.data() || _state.keep != _keep.data()
            || _state.treehash != _treehash.data() || _state.retain != _retain.data()) {
            return false;
        }
        for (size_t i = 0; i < _treehash.size(); ++i) {
            if (_treehash[i].node != _th_nodes.data() + params.n * i) return false;
        }
        return true;
    }
};

void expectSameSigner(SignerProbe& actual, SignerProbe& expected)
{
    EXPECT_EQ(expected.parameters(), actual.parameters());
    EXPECT_EQ(expected.getSK(), actual.getSK());
    EXPECT_EQ(expected.getPK(), actual.getPK());
    EXPECT_EQ(expected.getSeed(), actual.getSeed());
    EXPECT_EQ(expected.getIndex(), actual.getIndex());
    EXPECT_TRUE(actual.ownsState());
}

TEST_F(XmssAllocation, EveryCopyAssignmentFailurePreservesBothSigners)
{
    SignerProbe originalDestination(TSEED(48, 4), 4, eHashFunction::SHAKE_128);
    SignerProbe originalSource(TSEED(48, 5), 6, eHashFunction::SHA2_256);
    originalDestination.setIndex(3);
    originalSource.setIndex(7);

    // Fail allocation 0, 1, ... until assignment completes. The bound guards
    // against an accidental unbounded test if assignment's allocation changes.
    for (int failure = 0; failure < 64; ++failure) {
        SCOPED_TRACE(failure);
        SignerProbe destination(originalDestination);
        const auto destinationBuffers = destination.buffers();
        bool threw = false;
        {
            SignerProbe source(originalSource);
            const auto sourceBuffers = source.buffers();
            {
                FailureScope reset;
                allocationsBeforeFailure = failure;
                try { destination = source; }
                catch (const std::bad_alloc&) { threw = true; }
            }
            expectSameSigner(source, originalSource);
            EXPECT_EQ(sourceBuffers, source.buffers());
            expectSameSigner(destination, threw ? originalDestination : originalSource);
            if (threw) EXPECT_EQ(destinationBuffers, destination.buffers());
        }
        // The attempted assignment's source has been destroyed. This also
        // exercises traversal pointers and buffer sizes after every failure.
        ASSERT_TRUE(destination.ownsState());
        const auto publicKey = destination.getPK();
        EXPECT_TRUE(XmssBase::verify(message, destination.sign(message), publicKey));
        if (!threw) {
            EXPECT_GT(failure, 0);
            return;
        }
    }
    FAIL() << "Copy assignment did not succeed within the allocation failure sweep";
}

TEST_F(XmssAllocation, SelfCopyAssignmentDoesNotAllocate)
{
    SignerProbe signer(TSEED(48, 6), 4, eHashFunction::SHAKE_128);
    signer.setIndex(3);
    SignerProbe before(signer);
    const auto buffers = signer.buffers();
    bool threw = false;
    {
        FailureScope reset;
        allocationsBeforeFailure = 0;
        try { signer = signer; }
        catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_FALSE(threw);
    expectSameSigner(signer, before);
    EXPECT_EQ(buffers, signer.buffers());
    EXPECT_TRUE(XmssBase::verify(message, signer.sign(message), signer.getPK()));
}
}
