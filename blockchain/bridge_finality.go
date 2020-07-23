package blockchain

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
	"github.com/incognitochain/incognito-chain/metadata"
)

func buildBlockMerkleRootInstruction(
	stateDB *statedb.StateDB,
	shardID byte,
	blkHeight uint64,
	newBlkHash common.Hash,
	proposeTime int64,
) ([]string, error) {
	tree, err := loadIncrementalMerkle(
		stateDB,
		shardID,
		blkHeight,
	)
	if err != nil {
		return nil, err
	}
	tree.Add([][]byte{newBlkHash[:]})
	root := tree.GetRoot()
	t := big.NewInt(proposeTime)
	return []string{
		strconv.Itoa(metadata.BlockMerkleRootMeta),
		base58.EncodeCheck(root[:]),
		base58.EncodeCheck(t.Bytes()),
	}, nil
}

func updateSwapID(
	stateDB *statedb.StateDB,
	shardID byte,
	newHeight uint64,
	insts [][]string,
	meta int,
) error {
	// Get swapID of the current block height
	swapID, err := statedb.GetSwapIDForBlock(stateDB, shardID, newHeight)
	if err != nil {
		return fmt.Errorf("error getting swapID for shardID = %v, newHeight = %v: %w", shardID, newHeight, err)
	}

	// If committee changed, we increase the swapID for this block
	found := pickInstructionWithType(insts, strconv.Itoa(meta))
	if len(found) > 0 {
		swapID += 1
	}

	// Update swapID for next block
	fmt.Printf("[db] storing SWAPID = %v for block = %d insts = %v\n", swapID, newHeight+1, insts)
	if err := statedb.StoreSwapIDForBlock(stateDB, shardID, newHeight+1, swapID); err != nil {
		return fmt.Errorf("error storing swapID for shardID = %v, newHeight = %v, swapID = %v: %w", shardID, newHeight, swapID, err)
		return NewBlockChainError(StoreShardBlockError, err)
	}
	return nil
}
