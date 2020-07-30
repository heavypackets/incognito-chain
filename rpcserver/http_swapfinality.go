package rpcserver

import (
	"encoding/hex"
	"fmt"

	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
	"github.com/incognitochain/incognito-chain/incdb"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/rpcserver/jsonresult"
	"github.com/incognitochain/incognito-chain/rpcserver/rpcservice"
	"github.com/pkg/errors"
)

type finalityProof struct {
	swapID uint64

	inst     string
	instPath []string
	id       int64

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
	block1, err := getSingleBlockByHeight(bc, height, shardID)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}
	block2, err := getSingleBlockByHeight(bc, height+1, shardID)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}

	// Check if the block is finalled
	round1 := common.CalculateTimeSlot(block1.ProposeTime())
	round2 := common.CalculateTimeSlot(block2.ProposeTime())
	if round1+1 != round2 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, fmt.Errorf("block is not finalized, time slot = %v and %v", round1, round2))
	}

	// Build proof
	stateDB, err := getBlockStateDBFromBeststate(bc, shardID, httpServer.blockService)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}

	proof1, err := buildFinalityProofForBlock(block1, shardID, stateDB, httpServer.config.ConsensusEngine)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}

	proof2, err := buildFinalityProofForBlock(block2, shardID, stateDB, httpServer.config.ConsensusEngine)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}
	return buildFinalityProofResult(proof1, proof2), nil
}

func getSingleBlockByHeight(bc *blockchain.BlockChain, height uint64, shardID byte) (block, error) {
	if shardID != byte(255) {
		block, err := getSingleShardBlockByHeight(bc, height, shardID)
		if err != nil {
			return nil, err
		}
		return &shardBlock{block}, nil
	}

	block, err := getSingleBeaconBlockByHeight(bc, height)
	if err != nil {
		return nil, err
	}
	return &beaconBlock{block}, nil
}

func getSingleBeaconBlockByHeight(bc *blockchain.BlockChain, height uint64) (*blockchain.BeaconBlock, error) {
	beaconBlock, err := bc.GetBeaconBlockByView(bc.BeaconChain.GetFinalView(), height)
	if err != nil {
		return nil, fmt.Errorf("cannot find beacon block with height %d %w", height, err)
	}
	return beaconBlock, nil
}

func getSingleShardBlockByHeight(bc *blockchain.BlockChain, height uint64, shardID byte) (*blockchain.ShardBlock, error) {
	block, err := bc.GetShardBlockByView(bc.ShardChain[shardID].GetFinalView(), height, shardID)
	if err != nil {
		return nil, err
	}

	insts, err := extractInstsFromShardBlock(block, bc)
	if err != nil {
		return nil, err
	}
	block.Body.Instructions = insts
	return block, nil
}

func buildFinalityProofForBlock(
	blk block,
	shardID byte,
	stateDB *statedb.StateDB,
	ce ConsensusEngine,
) (*finalityProof, error) {
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

	// Get swapID of the committee signed this block
	swapID, err := statedb.GetSwapIDForBlock(stateDB, shardID, blk.GetHeight())
	if err != nil {
		return nil, err
	}

	proof := &finalityProof{
		swapID: swapID,

		inst:     inst,
		instPath: instProof.getPath(),
		id:       int64(instID),

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
		SwapID:       proof1.swapID,
		Instructions: [2]string{proof1.inst, proof2.inst},
		IDs:          [2]int64{proof1.id, proof2.id},
		InstPaths:    [2][]string{proof1.instPath, proof2.instPath},

		BlkData: [2]string{proof1.blkData, proof2.blkData},
		Sigs:    [2][]string{proof1.signerSigs, proof2.signerSigs},
		SigIdxs: [2][]int{proof1.sigIdxs, proof2.sigIdxs},
	}
}

func (httpServer *HttpServer) handleGetAncestorProof(params interface{}, closeChan <-chan struct{}) (interface{}, *rpcservice.RPCError) {
	listParams, ok := params.([]interface{})
	if !ok || len(listParams) < 2 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array at least 1 element"))
	}

	shardIDParam, ok := listParams[0].(float64)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("shard param is invalid"))
	}
	shardID := byte(shardIDParam)

	ancestorHeightParam, ok := listParams[1].(float64)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("ancestor height is invalid"))
	}
	ancestorHeight := uint64(ancestorHeightParam)

	anchorBlockHeightParam, ok := listParams[2].(float64)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("root height is invalid"))
	}
	anchorBlockHeight := uint64(anchorBlockHeightParam)

	stateDB, err := getBlockStateDBWithHeight(httpServer.GetBlockchain(), shardID, anchorBlockHeight)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}
	path, _, err := blockchain.GetMerkleProofWithRoot(
		stateDB,
		shardID,
		ancestorHeight,
		anchorBlockHeight,
	)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}

	return buildAncestorProof(path, ancestorHeight), nil
}

func buildAncestorProof(path [][]byte, id uint64) jsonresult.GetAncestorProof {
	proof := jsonresult.GetAncestorProof{}
	proof.ID = int64(id)
	for _, h := range path {
		proof.Path = append(proof.Path, hex.EncodeToString(h))
	}
	return proof
}

func getBlockStateDB(bc *blockchain.BlockChain, shardID byte, rootHash common.Hash) (*statedb.StateDB, error) {
	var db incdb.Database
	if shardID == byte(255) {
		db = bc.GetBeaconChainDatabase()
	} else {
		db = bc.GetShardChainDatabase(shardID)
	}

	dbAccessWarper := statedb.NewDatabaseAccessWarper(db)
	stateDB, err := statedb.NewWithPrefixTrie(rootHash, dbAccessWarper)
	if err != nil {
		return nil, fmt.Errorf("error initiating trie with rootHash = %s: %w", rootHash.String(), err)
	}
	return stateDB, nil
}

func getBlockStateDBWithHeight(bc *blockchain.BlockChain, shardID byte, blockHeight uint64) (*statedb.StateDB, error) {
	var merkleBlockRootHash common.Hash
	var err error
	if shardID == byte(255) {
		merkleBlockRootHash, err = bc.GetFinalizedBeaconBlockRootHash(blockHeight)
	} else {
		merkleBlockRootHash, err = bc.GetFinalizedShardBlockRootHash(blockHeight, shardID)
	}
	if err != nil {
		return nil, fmt.Errorf("error getting block root hash for shardID = %v, height = %v: %w", shardID, blockHeight, err)
	}

	return getBlockStateDB(bc, shardID, merkleBlockRootHash)
}

func getBlockStateDBFromBeststate(bc *blockchain.BlockChain, shardID byte, blockService *rpcservice.BlockService) (*statedb.StateDB, error) {
	var blockMerkleRoot common.Hash
	if shardID != byte(255) {
		bestState, err := blockService.GetShardBestStateByShardID(shardID)
		if err != nil {
			return nil, fmt.Errorf("error getting shard best state for shardID = %d: %w", shardID, err)
		}
		blockMerkleRoot = bestState.BlockStateDBRootHash
	} else {
		bestState, err := blockService.GetBeaconBestState()
		if err != nil {
			return nil, fmt.Errorf("error getting beacon best state: %w", err)
		}
		blockMerkleRoot = bestState.BlockStateDBRootHash
	}
	return getBlockStateDB(bc, shardID, blockMerkleRoot)
}
