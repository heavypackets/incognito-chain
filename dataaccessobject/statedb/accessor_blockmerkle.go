package statedb

import (
	"fmt"

	"github.com/incognitochain/incognito-chain/common"
)

func StoreBlockMerkleNode(stateDB *StateDB, shardID, level byte, height uint64, hash common.Hash) error {
	key := GenerateBlockMerkleObjectKey(shardID, level, height)
	value := hash[:]
	if err := stateDB.SetStateObject(BlockMerkleObjectType, key, value); err != nil {
		return NewStatedbError(StoreBlockMerkleError, err)
	}
	return nil
}

func GetBlockMerkleNode(stateDB *StateDB, shardID, level byte, height uint64) ([]byte, error) {
	key := GenerateBlockMerkleObjectKey(shardID, level, height)
	node, has, err := stateDB.getBlockMerkleNode(key)
	if err != nil {
		return nil, NewStatedbError(GetBlockMerkleError, err)
	}
	if !has {
		return nil, NewStatedbError(GetBlockMerkleError, fmt.Errorf("block merkle node not found for shardID = %v, level = %d, height = %d", shardID, level, height))
	}
	return node, nil
}
