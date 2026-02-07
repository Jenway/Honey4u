#pragma once

#include "components/merkle_mixin.hpp"
#include "components/tbls_mixin.hpp"
#include "components/tpke_mixin.hpp"
#include <exec/static_thread_pool.hpp>

namespace Honey::BFT::Crypto {

using TblsParams = Honey::Crypto::Tbls::TblsVerificationParameters;
using TblsShare = Honey::Crypto::Tbls::TblsPrivateKeyShare;

struct SchedulerOwner {
    using Scheduler = exec::static_thread_pool::scheduler;

    explicit SchedulerOwner(size_t num_threads)
        : thread_pool_(num_threads)
        , scheduler_(thread_pool_.get_scheduler())
    {
    }

protected:
    Scheduler scheduler() const { return scheduler_; }

    exec::static_thread_pool thread_pool_;
    Scheduler scheduler_;
};

class UnifiedCryptoService
    : private SchedulerOwner,
      public Components::MerkleMixin<SchedulerOwner::Scheduler>,
      public Components::TblsMixin<SchedulerOwner::Scheduler>,
      public Components::TpkeMixin<SchedulerOwner::Scheduler> {
    using Scheduler = SchedulerOwner::Scheduler;

public:
    using MerkleBuildResult = Components::MerkleBuildResult;

    UnifiedCryptoService(
        size_t num_threads,
        const TblsParams& tbls_params,
        const TblsShare& tbls_share,
        const TpkeParams& tpke_params,
        const TpkeShare& tpke_share)
        : SchedulerOwner(num_threads)
        , MerkleMixin(scheduler())
        , TblsMixin(scheduler())
        , TpkeMixin(scheduler(), tpke_params, tpke_share)
    {
        set_verification_params(tbls_params);
        set_private_key_share(tbls_share);
    }

    ~UnifiedCryptoService()
    {
        thread_pool_.request_stop();
    }
};

}
