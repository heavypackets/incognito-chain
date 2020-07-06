package rpcserver

import (
	"encoding/hex"
	"fmt"

	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/rawdbv2"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/rpcserver/jsonresult"
	"github.com/incognitochain/incognito-chain/rpcserver/rpcservice"
	"github.com/pkg/errors"
)

type finalityProof struct {
	inst           string
	instPath       []string
	instPathIsLeft []bool

	instRoot   string
	blkData    string
	signerSigs []string
	sigIdxs    []int
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

	insts, err := extractInstsFromShardBlock(block, bc)
	if err != nil {
		return nil, err
	}
	block.Body.Instructions = insts
	return block, nil
}

func buildFinalityProofForBlock(blk block, ce ConsensusEngine) (*finalityProof, error) {
	// Build merkle proof for instruction
	insts := blk.Instructions()
	instID, err := findBlockMerkleRootInst(insts)
	if err != nil {
		return nil, err
	}
	instProof := buildInstProof(insts, instID)
	decodedInst, err := blockchain.DecodeInstruction(insts[instID])
	if err != nil {
		return nil, err
	}
	inst := hex.EncodeToString(decodedInst)

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
		inst:           inst,
		instPath:       instProof.getPath(),
		instPathIsLeft: instProof.left,

		instRoot:   hex.EncodeToString(blk.InstructionMerkleRoot()),
		blkData:    hex.EncodeToString(blk.MetaHash()),
		signerSigs: sigs,
		sigIdxs:    sigIdxs,
	}
	return proof, nil
}

func findBlockMerkleRootInst(insts [][]string) (int, error) {
	_, id := findCommSwapInst(insts, metadata.BlockMerkleRootMeta)
	if id < 0 {
		return -1, fmt.Errorf("BlockMerkleRootMeta not found")
	}
	return id, nil
}

func buildFinalityProofResult(proof1, proof2 *finalityProof) jsonresult.GetFinalityProof {
	return jsonresult.GetFinalityProof{
		Instructions:    [2]string{proof1.inst, proof2.inst},
		InstPaths:       [2][]string{proof1.instPath, proof2.instPath},
		InstPathIsLefts: [2][]bool{proof1.instPathIsLeft, proof2.instPathIsLeft},

		BlkData:  [2]string{proof1.blkData, proof2.blkData},
		InstRoot: [2]string{proof1.instRoot, proof2.instRoot},
		Sigs:     [2][]string{proof1.signerSigs, proof2.signerSigs},
		SigIdxs:  [2][]int{proof1.sigIdxs, proof2.sigIdxs},
	}
}

func (httpServer *HttpServer) handleGetAncestorProof(params interface{}, closeChan <-chan struct{}) (interface{}, *rpcservice.RPCError) {
	listParams, ok := params.([]interface{})
	if !ok || len(listParams) < 2 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array at least 1 element"))
	}

	shardParam, ok := listParams[0].(float64)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("shard param is invalid"))
	}
	shardID := byte(shardParam)

	ancestorHeightParam, ok := listParams[1].(float64)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("ancestor height is invalid"))
	}
	ancestorHeight := uint64(ancestorHeightParam)

	ancestorHashParam, ok := listParams[2].(string)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("Tx id invalid"))
	}
	ancestorHash, err := common.Hash{}.NewHashFromStr(ancestorHashParam)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}
	_ = ancestorHash

	anchorBlockHeightParam, ok := listParams[3].(float64)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("root height is invalid"))
	}
	anchorBlockHeight := uint64(anchorBlockHeightParam)

	anchorBlockHashParam, ok := listParams[4].(string)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("Tx id invalid"))
	}
	anchorBlockHash, err := common.Hash{}.NewHashFromStr(anchorBlockHashParam)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}
	_ = anchorBlockHash

	bc := httpServer.GetBlockchain()
	db := bc.GetShardChainDatabase(shardID)
	merkleBlockRootHash, err := rawdbv2.GetShardBlockRootHash(db, shardID, anchorBlockHeight)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}

	dbAccessWarper := statedb.NewDatabaseAccessWarper(db)
	stateDB, err := statedb.NewWithPrefixTrie(merkleBlockRootHash, dbAccessWarper)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}
	path, left, err := blockchain.GetMerkleProofWithRoot(
		stateDB,
		shardID,
		ancestorHeight,
		anchorBlockHeight,
	)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}

	return buildAncestorProof(path, left), nil
}

func buildAncestorProof(path [][]byte, left []bool) jsonresult.GetAncestorProof {
	proof := jsonresult.GetAncestorProof{}
	for i, h := range path {
		proof.Path = append(proof.Path, hex.EncodeToString(h))
		proof.IsLeft = append(proof.IsLeft, left[i])
	}
	return proof
}
