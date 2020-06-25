package rpcserver

import (
	"encoding/hex"
	"fmt"

	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/rpcserver/jsonresult"
	"github.com/incognitochain/incognito-chain/rpcserver/rpcservice"
	"github.com/pkg/errors"
)

type finalityProof struct {
	proposeTime uint64

	blkMerkleRoot string
	instRoot      string
	blkData       string
	signerSigs    []string
	sigIdxs       []int
}

func (httpServer *HttpServer) handleGetFinalityProof(params interface{}, closeChan <-chan struct{}) (interface{}, *rpcservice.RPCError) {
	listParams, ok := params.([]interface{})
	if !ok || len(listParams) < 2 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array at least 1 element"))
	}

	heightParam, ok := listParams[0].(float64)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("height param is invalid"))
	}
	height := uint64(heightParam)

	shardParam, ok := listParams[1].(float64)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("shard param is invalid"))
	}
	shardID := byte(shardParam)

	// Get the 2 blocks
	bc := httpServer.GetBlockchain()
	block1, err := getSingleShardBlockByHeight(bc, height, shardID)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}
	block2, err := getSingleShardBlockByHeight(bc, height+1, shardID)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}

	// Check if the block is finalled
	round1 := common.CalculateTimeSlot(block1.Header.ProposeTime)
	round2 := common.CalculateTimeSlot(block2.Header.ProposeTime)
	if round1+1 != round2 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, fmt.Errorf("block is not finalized, time slot = %v and %v", round1, round2))
	}

	// Build proof
	blk1 := &shardBlock{block1}
	proof1, err := buildFinalityProofForBlock(blk1, httpServer.config.ConsensusEngine)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}

	blk2 := &shardBlock{block2}
	proof2, err := buildFinalityProofForBlock(blk2, httpServer.config.ConsensusEngine)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}
	return buildFinalityProofResult(proof1, proof2), nil
}

func getSingleShardBlockByHeight(bc *blockchain.BlockChain, height uint64, shardID byte) (*blockchain.ShardBlock, error) {
	blocks, err := bc.GetShardBlockByHeight(height, shardID)
	if err != nil {
		return nil, err
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no block found for shardID = %v, height = %v", shardID, height)
	}
	var block *blockchain.ShardBlock
	for _, b := range blocks {
		block = b
		break
	}
	return block, nil
}

func buildFinalityProofForBlock(blk block, ce ConsensusEngine) (*finalityProof, error) {
	// Get sig data
	bSigs, sigIdxs, err := blk.Sig(ce)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sigs := []string{}
	for _, s := range bSigs {
		sigs = append(sigs, hex.EncodeToString(s))
	}
	proof := &finalityProof{
		proposeTime:   uint64(blk.ProposeTime()),
		blkMerkleRoot: hex.EncodeToString(blk.BlockMerkleRoot()),
		instRoot:      hex.EncodeToString(blk.InstructionMerkleRoot()),
		blkData:       hex.EncodeToString(blk.MetaHash()),
		signerSigs:    sigs,
		sigIdxs:       sigIdxs,
	}
	return proof, nil
}

func buildFinalityProofResult(proof1, proof2 *finalityProof) jsonresult.GetFinalityProof {
	return jsonresult.GetFinalityProof{
		BlkData:       [2]string{proof1.blkData, proof2.blkData},
		InstRoot:      [2]string{proof1.instRoot, proof2.instRoot},
		BlkMerkleRoot: proof2.blkMerkleRoot,
		ProposeTime:   [2]uint64{proof1.proposeTime, proof2.proposeTime},
		Sigs:          [2][]string{proof1.signerSigs, proof2.signerSigs},
		SigIdxs:       [2][]int{proof1.sigIdxs, proof2.sigIdxs},
	}
}
