package statedb

import (
	"fmt"

	"github.com/incognitochain/incognito-chain/common"
)

func StoreBlockMerkleNode(stateDB *StateDB, shardID, level byte, height uint64, hash common.Hash) error {
	key := GenerateBlockMerkleObjectKey(shardID, level, height)
	if err := stateDB.SetStateObject(BlockMerkleObjectType, key, hash); err != nil {
		return NewStatedbError(StoreBlockMerkleError, err)
	}
	return nil
}

func GetBlockMerkleNode(stateDB *StateDB, shardID, level byte, height uint64) (common.Hash, error) {
	key := GenerateBlockMerkleObjectKey(shardID, level, height)
	node, has, err := stateDB.getBlockMerkleNode(key)
	if err != nil {
		return common.Hash{}, NewStatedbError(GetBlockMerkleError, err)
	}
	if !has {
		return common.Hash{}, NewStatedbError(GetBlockMerkleError, fmt.Errorf("block merkle node not found for shardID = %v, level = %d, height = %d", shardID, level, height))
	}
	return node, nil
}
