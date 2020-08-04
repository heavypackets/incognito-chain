package rpcserver

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/rpcserver/rpcservice"
	"github.com/pkg/errors"
)

// handleGetBurnProof returns a proof of a tx burning pETH
func (httpServer *HttpServer) handleGetBurnProof(
	params interface{},
	closeChan <-chan struct{},
) (interface{}, *rpcservice.RPCError) {
	return retrieveBurnProof(params, closeChan, metadata.BurningConfirmMeta, httpServer)
}

// handleGetBurnProof returns a proof of a tx burning pETH
func (httpServer *HttpServer) handleGetBurnProofForDepositToSC(
	params interface{},
	closeChan <-chan struct{},
) (interface{}, *rpcservice.RPCError) {
	return retrieveBurnProof(params, closeChan, metadata.BurningConfirmForDepositToSCMeta, httpServer)
}

func retrieveBurnProof(
	params interface{},
	closeChan <-chan struct{},
	burningMetaType int,
	httpServer *HttpServer,
) (interface{}, *rpcservice.RPCError) {
	listParams, ok := params.([]interface{})
	if !ok || len(listParams) < 1 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array at least 1 element"))
	}

	txIDParam, ok := listParams[0].(string)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("Tx id invalid"))
	}

	txID, err := common.Hash{}.NewHashFromStr(txIDParam)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, err)
	}
	// Get block height from txID
	height, err := httpServer.blockService.GetBurningConfirm(*txID)
	if err != nil {
		return nil, rpcservice.NewRPCError(rpcservice.UnexpectedError, fmt.Errorf("proof of tx not found"))
	}
	return getBurnProofByHeight(burningMetaType, httpServer, height, txID)
}

func getBurnProofByHeight(
	burningMetaType int,
	httpServer *HttpServer,
	height uint64,
	txID *common.Hash,
) (interface{}, *rpcservice.RPCError) {
	// TODO(@0xbunyip): get beacon block from txid
	// Get bridge block and corresponding beacon blocks
	// bridgeBlock, beaconBlocks, err := getShardAndBeaconBlocks(height, httpServer.GetBlockchain())
	// if err != nil {
	// 	return nil, rpcservice.NewRPCError(rpcservice.UnexpectedError, err)
	// }
	// // Get proof of instruction on beacon
	// beaconInstProof, err := getBurnProofOnBeacon(bridgeInstProof.inst, beaconBlocks, httpServer.config.ConsensusEngine)
	// if err != nil {
	// 	return nil, rpcservice.NewRPCError(rpcservice.UnexpectedError, err)
	// }
	beaconInstProof := &swapProof{}
	fmt.Println("beaconInstProof", beaconInstProof)
	// Decode instruction to send to Ethereum without having to decode on client
	decodedInst, beaconHeight := splitAndDecodeInst(beaconInstProof.inst)
	fmt.Println("decodedInst", decodedInst)
	fmt.Println("beaconHeight", beaconHeight)
	//decodedInst := hex.EncodeToString(blockchain.DecodeInstruction(bridgeInstProof.inst))

	return buildProofResult(decodedInst, beaconInstProof), nil
}

// getBurnProofOnBeacon finds in given beacon blocks a BurningConfirm instruction and returns its proof
func getBurnProofOnBeacon(
	inst []string,
	beaconBlocks []*blockchain.BeaconBlock,
	ce ConsensusEngine,
) (*swapProof, error) {
	// Get beacon block and check if it contains beacon swap instruction
	b, instID := findBeaconBlockWithBurnInst(beaconBlocks, inst)
	if b == nil {
		return nil, fmt.Errorf("cannot find corresponding beacon block that includes burn instruction")
	}

	insts := b.Body.Instructions
	block := &beaconBlock{BeaconBlock: b}
	return buildProofForBlock(block, insts, instID, ce)
}

// findBeaconBlockWithBurnInst finds a beacon block with a specific burning instruction and the instruction's index; nil if not found
func findBeaconBlockWithBurnInst(beaconBlocks []*blockchain.BeaconBlock, inst []string) (*blockchain.BeaconBlock, int) {
	for _, b := range beaconBlocks {
		for k, blkInst := range b.Body.Instructions {
			diff := false
			// Ignore block height (last element)
			for i, part := range inst[:len(inst)-1] {
				if i >= len(blkInst) || part != blkInst[i] {
					diff = true
					break
				}
			}
			if !diff {
				return b, k
			}
		}
	}
	return nil, -1
}

// findBurnConfirmInst finds a BurningConfirm instruction in a list, returns it along with its index
func findBurnConfirmInst(
	burningMetaType int,
	insts [][]string,
	txID *common.Hash,
) ([]string, int) {
	instType := strconv.Itoa(burningMetaType)
	for i, inst := range insts {
		if inst[0] != instType || len(inst) < 5 {
			continue
		}

		h, err := common.Hash{}.NewHashFromStr(inst[5])
		if err != nil {
			continue
		}

		if h.IsEqual(txID) {
			return inst, i
		}
	}
	return nil, -1
}

// splitAndDecodeInst splits BurningConfirm insts (on beacon) into 2 parts: the inst itselfand the beaconHeight that contains the inst
func splitAndDecodeInst(beaconInst []string) (string, string) {
	// Decode instructions
	beaconInstFlat, _ := blockchain.DecodeInstruction(beaconInst)

	// Split of last 32 bytes (block height)
	beaconHeight := hex.EncodeToString(beaconInstFlat[len(beaconInstFlat)-32:])

	decodedInst := hex.EncodeToString(beaconInstFlat[:len(beaconInstFlat)-32])
	return decodedInst, beaconHeight
}

// handleGetBurnProof returns a proof of a tx burning pETH
func (httpServer *HttpServer) handleGetBurningAddress(params interface{}, closeChan <-chan struct{}) (interface{}, *rpcservice.RPCError) {
	listParams, ok := params.([]interface{})
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array"))
	}

	beaconHeightParam := float64(0)
	if len(listParams) >= 1 {
		beaconHeightParam, ok = listParams[0].(float64)
		if !ok {
			return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("beacon height is invalid"))
		}
	}

	burningAddress := httpServer.blockService.GetBurningAddress(uint64(beaconHeightParam))

	return burningAddress, nil
}
