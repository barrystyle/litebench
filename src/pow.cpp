// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"
#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

bool haveAnnounced = false;

///////////////////////////////////////////////////////////////////////////////////////////
// #1 standard bitcoin/litecoin retarget
///////////////////////////////////////////////////////////////////////////////////////////

unsigned int testcase1(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DifficultyAdjustmentInterval()-1;
    if ((pindexLast->nHeight+1) != params.DifficultyAdjustmentInterval())
        blockstogoback = params.DifficultyAdjustmentInterval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);

    return testcase1_ext(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int testcase1_ext(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Litecoin: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

///////////////////////////////////////////////////////////////////////////////////////////
// #2 darkgravity wave v3 retarget
///////////////////////////////////////////////////////////////////////////////////////////

unsigned int static testcase2(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    /* current difficulty formula, dash - DarkGravity v3, written by Evan Duffield - evan@dash.org */
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    int64_t nPastBlocks = 24;

    // make sure we have at least (nPastBlocks + 1) blocks, otherwise just return powLimit
    if (!pindexLast || pindexLast->nHeight < nPastBlocks) {
        return bnPowLimit.GetCompact();
    }

    if (params.fPowAllowMinDifficultyBlocks) {
        // recent block is more than 2 hours old
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + 2 * 60 * 60) {
            return bnPowLimit.GetCompact();
        }
        // recent block is more than 10 minutes old
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 4) {
            arith_uint256 bnNew = arith_uint256().SetCompact(pindexLast->nBits) * 10;
            if (bnNew > bnPowLimit) {
                bnNew = bnPowLimit;
            }
            return bnNew.GetCompact();
        }
    }

    const CBlockIndex *pindex = pindexLast;
    arith_uint256 bnPastTargetAvg;

    for (unsigned int nCountBlocks = 1; nCountBlocks <= nPastBlocks; nCountBlocks++) {
        arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
        if (nCountBlocks == 1) {
            bnPastTargetAvg = bnTarget;
        } else {
            // NOTE: that's not an average really...
            bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);
        }

        if(nCountBlocks != nPastBlocks) {
            assert(pindex->pprev); // should never fail
            pindex = pindex->pprev;
        }
    }

    arith_uint256 bnNew(bnPastTargetAvg);

    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindex->GetBlockTime();
    // NOTE: is this accurate? nActualTimespan counts it for (nPastBlocks - 1) blocks only...
    int64_t nTargetTimespan = nPastBlocks * params.nPowTargetSpacing;

    if (nActualTimespan < nTargetTimespan/3)
        nActualTimespan = nTargetTimespan/3;
    if (nActualTimespan > nTargetTimespan*3)
        nActualTimespan = nTargetTimespan*3;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    return bnNew.GetCompact();
}

///////////////////////////////////////////////////////////////////////////////////////////
// #3 kimotogravitywell retarget
///////////////////////////////////////////////////////////////////////////////////////////

unsigned int static testcase3(const CBlockIndex* pindexLast, const Consensus::Params& params) {
    const CBlockIndex *BlockLastSolved = pindexLast;
    const CBlockIndex *BlockReading = pindexLast;
    uint64_t PastBlocksMass = 0;
    int64_t PastRateActualSeconds = 0;
    int64_t PastRateTargetSeconds = 0;
    double PastRateAdjustmentRatio = double(1);
    arith_uint256 PastDifficultyAverage;
    arith_uint256 PastDifficultyAveragePrev;
    double EventHorizonDeviation;
    double EventHorizonDeviationFast;
    double EventHorizonDeviationSlow;

    uint64_t pastSecondsMin = params.nPowTargetTimespan * 0.025;
    uint64_t pastSecondsMax = params.nPowTargetTimespan * 7;
    uint64_t PastBlocksMin = pastSecondsMin / params.nPowTargetSpacing;
    uint64_t PastBlocksMax = pastSecondsMax / params.nPowTargetSpacing;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64_t)BlockLastSolved->nHeight < PastBlocksMin) { return UintToArith256(params.powLimit).GetCompact(); }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
        PastBlocksMass++;

        PastDifficultyAverage.SetCompact(BlockReading->nBits);
        if (i > 1) {
            // handle negative arith_uint256
            if(PastDifficultyAverage >= PastDifficultyAveragePrev)
                PastDifficultyAverage = ((PastDifficultyAverage - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
            else
                PastDifficultyAverage = PastDifficultyAveragePrev - ((PastDifficultyAveragePrev - PastDifficultyAverage) / i);
        }
        PastDifficultyAveragePrev = PastDifficultyAverage;

        PastRateActualSeconds = BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
        PastRateTargetSeconds = params.nPowTargetSpacing * PastBlocksMass;
        PastRateAdjustmentRatio = double(1);
        if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
            PastRateAdjustmentRatio = double(PastRateTargetSeconds) / double(PastRateActualSeconds);
        }
        EventHorizonDeviation = 1 + (0.7084 * pow((double(PastBlocksMass)/double(28.2)), -1.228));
        EventHorizonDeviationFast = EventHorizonDeviation;
        EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

        if (PastBlocksMass >= PastBlocksMin) {
                if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast))
                { assert(BlockReading); break; }
        }
        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    arith_uint256 bnNew(PastDifficultyAverage);
    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
        bnNew *= PastRateActualSeconds;
        bnNew /= PastRateTargetSeconds;
    }

    if (bnNew > UintToArith256(params.powLimit)) {
        bnNew = UintToArith256(params.powLimit);
    }

    return bnNew.GetCompact();
}

///////////////////////////////////////////////////////////////////////////////////////////
// #4 digishield retarget
///////////////////////////////////////////////////////////////////////////////////////////

unsigned int static testcase4(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int bnProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    bool fTestNet = false;
    int blockstogoback = 0;
    int64_t retargetTimespan = params.nPowTargetTimespan;
    int64_t retargetSpacing = params.nPowTargetSpacing;
    int64_t retargetInterval = retargetTimespan / retargetSpacing;
	
    // Genesis block
    if (pindexLast == NULL) return bnProofOfWorkLimit;

    // Only change once per interval
    if ((pindexLast->nHeight+1) % retargetInterval != 0){
      // Special difficulty rule for testnet:
        if (fTestNet){
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->nTime > pindexLast->nTime + retargetSpacing*2)
                return bnProofOfWorkLimit;
        else {
            // Return the last non-special-min-difficulty-rules-block
            const CBlockIndex* pindex = pindexLast;
            while (pindex->pprev && pindex->nHeight % retargetInterval != 0 && pindex->nBits == bnProofOfWorkLimit)
            pindex = pindex->pprev;
        return pindex->nBits;
        }
      }
      return pindexLast->nBits;
    }

    // DigiByte: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    blockstogoback = retargetInterval-1;
    if ((pindexLast->nHeight+1) != retargetInterval) blockstogoback = retargetInterval;

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    LogPrintf("  nActualTimespan = %g before bounds\n", nActualTimespan);

    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    if (nActualTimespan < (retargetTimespan - (retargetTimespan/4)) ) nActualTimespan = (retargetTimespan - (retargetTimespan/4));
    if (nActualTimespan > (retargetTimespan + (retargetTimespan/2)) ) nActualTimespan = (retargetTimespan + (retargetTimespan/2));

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= retargetTimespan;

    /// debug print
    LogPrintf("DigiShield RETARGET \n");
    LogPrintf("RetargetTimespan = %g    nActualTimespan = %g \n", retargetTimespan, nActualTimespan);

    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    return bnNew.GetCompact();
}

///////////////////////////////////////////////////////////////////////////////////////////
// #5 dualkgw3 retarget
///////////////////////////////////////////////////////////////////////////////////////////

unsigned int static testcase5(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    // current difficulty formula, ERC3 - DUAL_KGW3, written by Bitcoin Talk Limx Dev
    const CBlockIndex *BlockLastSolved = pindexLast;
    const CBlockIndex *BlockReading = pindexLast;
    bool kgwdebug=false;
    uint64_t PastBlocksMass = 0;
    int64_t PastRateActualSeconds = 0;
    int64_t PastRateTargetSeconds = 0;
    double PastRateAdjustmentRatio = double(1);
    arith_uint256 PastDifficultyAverage;
    arith_uint256 PastDifficultyAveragePrev;
    double EventHorizonDeviation;
    double EventHorizonDeviationFast;
    double EventHorizonDeviationSlow;
    //DUAL_KGW3 SETUP
    static const uint64_t Blocktime = params.nPowTargetSpacing;
    static const unsigned int timeDaySeconds = 60 * 60 * 24;
    uint64_t pastSecondsMin = timeDaySeconds * 0.025;
    uint64_t pastSecondsMax = timeDaySeconds * 7;
    uint64_t PastBlocksMin = pastSecondsMin / Blocktime;
    uint64_t PastBlocksMax = pastSecondsMax / Blocktime;

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64_t)BlockLastSolved->nHeight < PastBlocksMin) {  return bnPowLimit.GetCompact(); }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
        PastBlocksMass++;
        PastDifficultyAverage.SetCompact(BlockReading->nBits);
        if (i > 1) {
            if(PastDifficultyAverage >= PastDifficultyAveragePrev)
                PastDifficultyAverage = ((PastDifficultyAverage - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
            else
                PastDifficultyAverage = PastDifficultyAveragePrev - ((PastDifficultyAveragePrev - PastDifficultyAverage) / i);
        }
        PastDifficultyAveragePrev = PastDifficultyAverage;
        PastRateActualSeconds = BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
        PastRateTargetSeconds = Blocktime * PastBlocksMass;
        PastRateAdjustmentRatio = double(1);
        if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
            PastRateAdjustmentRatio = double(PastRateTargetSeconds) / double(PastRateActualSeconds);
        }
        EventHorizonDeviation = 1 + (0.7084 * pow((double(PastBlocksMass)/double(72)), -1.228));  //28.2 and 144 possible
        EventHorizonDeviationFast = EventHorizonDeviation;
        EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

        if (PastBlocksMass >= PastBlocksMin) {
                if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast))
                { assert(BlockReading); break; }
        }
        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    //KGW Original
    arith_uint256 kgw_dual1(PastDifficultyAverage);
    arith_uint256 kgw_dual2;
    kgw_dual2.SetCompact(pindexLast->nBits);
    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
         kgw_dual1 *= PastRateActualSeconds;
         kgw_dual1 /= PastRateTargetSeconds;
    }

    int64_t nActualTime1 = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();
    int64_t nActualTimespanshort = nActualTime1;

    // Retarget BTC Original ...not exactly
    // Small Fix

    if(nActualTime1 < 0) nActualTime1 = Blocktime;

    if (nActualTime1 < Blocktime / 3)
        nActualTime1 = Blocktime / 3;
    if (nActualTime1 > Blocktime * 3)
        nActualTime1 = Blocktime * 3;

    kgw_dual2 *= nActualTime1;
    kgw_dual2 /= Blocktime;

    //Fusion from Retarget and Classic KGW3 (BitSend=)

    arith_uint256 bnNew;
    bnNew = ((kgw_dual2 + kgw_dual1)/2);
    // DUAL KGW3 increased rapidly the Diff if Blocktime to last block under Blocktime/6 sec.

    if(kgwdebug)LogPrintf("nActualTimespanshort = %d \n", nActualTimespanshort );
    if( nActualTimespanshort < Blocktime/6 )
        {
        if(kgwdebug)LogPrintf("Vordiff:%08x %s bnNew first  \n", bnNew.GetCompact(), bnNew.ToString().c_str());
        const int nLongShortNew1   = 85; const int nLongShortNew2   = 100;
        bnNew = bnNew * nLongShortNew1;    bnNew = bnNew / nLongShortNew2;
        if(kgwdebug)LogPrintf("Erhöhte Diff:\n %08x %s bnNew second \n", bnNew.GetCompact(), bnNew.ToString().c_str() );
        }


    //BitBreak BitSend
    // Reduce difficulty if current block generation time has already exceeded maximum time limit.
    // Diffbreak 12 Hours
    const int nLongTimeLimit   = 12 * 60 * 60;
    if(kgwdebug)
    {
    LogPrintf("Prediff %08x %s\n", bnNew.GetCompact(), bnNew.ToString().c_str());
    LogPrintf("Vordiff %d \n", nLongTimeLimit);
    LogPrintf(" %d Block", BlockReading->nHeight );
    }

    if ((pblock-> nTime - pindexLast->GetBlockTime()) > nLongTimeLimit)  //block.nTime
    {
        bnNew = bnPowLimit;
           if(kgwdebug)LogPrintf("<BSD> Maximum block time hit - cute diff %08x %s\n", bnNew.GetCompact(), bnNew.ToString().c_str());
    }

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }
    return bnNew.GetCompact();
}

///////////////////////////////////////////////////////////////////////////////////////////
// #6 orbitcoin super shield retarget
///////////////////////////////////////////////////////////////////////////////////////////

unsigned int static testcase6(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    /* Orbitcoin Super Shield (OSS);
     * retargets every block using two averaging windows of 5 and 20 blocks,
     * 0.25 damping and further oscillation limiting */

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    int64_t nIntervalShort = 5, nIntervalLong = 20, nTargetSpacing, nTargetTimespan,
              nActualTimespan, nActualTimespanShort, nActualTimespanLong, nActualTimespanAvg,
              nActualTimespanMax, nActualTimespanMin;

    nTargetSpacing = params.nPowTargetSpacing;
    nTargetTimespan = nTargetSpacing * nIntervalLong;

    /* The short averaging window */
    const CBlockIndex* pindexShort = pindexLast;
    for(int i = 0; pindexShort && (i < nIntervalShort); i++) {
      pindexShort = pindexLast->pprev;
    }
    nActualTimespanShort = (int64_t)pindexLast->pprev->nTime - (int64_t)pindexShort->nTime;

    /* The long averaging window */
    const CBlockIndex* pindexLong = pindexShort;
    for(int i = 0; pindexLong && (i < (nIntervalLong - nIntervalShort)); i++)
      pindexLong = pindexLong->pprev;
    nActualTimespanLong = (int64_t)pindexLast->nTime - (int64_t)pindexLong->nTime;

    /* Time warp protection */
    {
            nActualTimespanShort = std::max(nActualTimespanShort, (nTargetSpacing * nIntervalShort / 2));
            nActualTimespanShort = std::min(nActualTimespanShort, (nTargetSpacing * nIntervalShort * 2));
            nActualTimespanLong  = std::max(nActualTimespanLong,  (nTargetSpacing * nIntervalLong  / 2));
            nActualTimespanLong  = std::min(nActualTimespanLong,  (nTargetSpacing * nIntervalLong  * 2));
    }

    /* The average of both windows */
    nActualTimespanAvg = (nActualTimespanShort * (nIntervalLong / nIntervalShort) + nActualTimespanLong) / 2;

    /* 0.25 damping */
    nActualTimespan = nActualTimespanAvg + 3 * nTargetTimespan;
    nActualTimespan /= 4;

    /* Oscillation limiters */
    {
            /* +5% to -10% */
            nActualTimespanMin = nTargetTimespan * 100 / 105;
            nActualTimespanMax = nTargetTimespan * 110 / 100;
    }
    if(nActualTimespan < nActualTimespanMin) nActualTimespan = nActualTimespanMin;
    if(nActualTimespan > nActualTimespanMax) nActualTimespan = nActualTimespanMax;

    /* Retarget */
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if(bnNew > bnPowLimit) bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

///////////////////////////////////////////////////////////////////////////////////////////

double GetDifficulty(unsigned int nBits)
{
    int nShift = (nBits >> 24) & 0xff;
    double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);
    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }
    return dDiff;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    int nHeight = pindexLast->nHeight+1;
    int retargetRoutine = GetArg("-retarget", 1);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    if (nHeight < 100)
       return nProofOfWorkLimit;

    switch (retargetRoutine) {

       case 1 :  if(!haveAnnounced) LogPrintf("* Using standard bitcoin/litecoin retarget algorithm..\n"); haveAnnounced = true;
                 nProofOfWorkLimit = testcase1(pindexLast, pblock, params);
                 LogPrintf("* next block difficulty is %0.4f (%08x)\n", GetDifficulty(nProofOfWorkLimit), nProofOfWorkLimit);
                 return nProofOfWorkLimit;

       case 2 :  if(!haveAnnounced) LogPrintf("* Using darkgravitywave v3 retarget algorithm..\n"); haveAnnounced = true;
                 nProofOfWorkLimit = testcase2(pindexLast, pblock, params);
                 LogPrintf("* next block difficulty is %0.4f (%08x)\n", GetDifficulty(nProofOfWorkLimit), nProofOfWorkLimit);
                 return nProofOfWorkLimit;

       case 3 :  if(!haveAnnounced) LogPrintf("* Using kimotogravitywell retarget algorithm..\n"); haveAnnounced = true;
                 nProofOfWorkLimit = testcase3(pindexLast, params);
                 LogPrintf("* next block difficulty is %0.4f (%08x)\n", GetDifficulty(nProofOfWorkLimit), nProofOfWorkLimit);
                 return nProofOfWorkLimit;

       case 4 :  if(!haveAnnounced) LogPrintf("* Using digishield retarget algorithm..\n"); haveAnnounced = true;
                 nProofOfWorkLimit = testcase4(pindexLast, pblock, params);
                 LogPrintf("* next block difficulty is %0.4f (%08x)\n", GetDifficulty(nProofOfWorkLimit), nProofOfWorkLimit);
                 return nProofOfWorkLimit;

       case 5 :  if(!haveAnnounced) LogPrintf("* Using dualkgw3 retarget algorithm..\n"); haveAnnounced = true;
                 nProofOfWorkLimit = testcase5(pindexLast, pblock, params);
                 LogPrintf("* next block difficulty is %0.4f (%08x)\n", GetDifficulty(nProofOfWorkLimit), nProofOfWorkLimit);
                 return nProofOfWorkLimit;

       case 6 :  if(!haveAnnounced) LogPrintf("* Using orbitcoin retarget algorithm..\n"); haveAnnounced = true;
                 nProofOfWorkLimit = testcase6(pindexLast, params);
                 LogPrintf("* next block difficulty is %0.4f (%08x)\n", GetDifficulty(nProofOfWorkLimit), nProofOfWorkLimit);
                 return nProofOfWorkLimit;
    }
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

