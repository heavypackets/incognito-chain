package statedb

import (
	"fmt"

	"github.com/incognitochain/incognito-chain/common"
)

func StoreBlockMerkleNode(stateDB *StateDB, shardID, level byte, index uint64, hash common.Hash) error {
	key := GenerateBlockMerkleObjectKey(shardID, level, index)
	if err := stateDB.SetStateObject(BlockMerkleObjectType, key, hash); err != nil {
		return NewStatedbError(StoreBlockMerkleError, err)
	}
	return nil
}

func GetBlockMerkleNode(stateDB *StateDB, shardID, level byte, index uint64) (common.Hash, error) {
	key := GenerateBlockMerkleObjectKey(shardID, level, index)
	node, has, err := stateDB.getBlockMerkleNode(key)
	if err != nil {
		return common.Hash{}, NewStatedbError(GetBlockMerkleError, err)
	}
	if !has {
		return common.Hash{}, NewStatedbError(GetBlockMerkleError, fmt.Errorf("block merkle node not found for shardID = %v, level = %d, index = %d", shardID, level, index))
	}
	return node, nil
}

func StoreLatestSwapID(stateDB *StateDB, shardID byte, id uint64) error {
	key := GenerateLatestSwapIDObjectKey(shardID)
	if err := stateDB.SetStateObject(LatestSwapIDObjectType, key, id); err != nil {
		return NewStatedbError(StoreLatestSwapIDError, err)
	}
	return nil
}

func GetLatestSwapID(stateDB *StateDB, shardID byte) (uint64, error) {
	key := GenerateLatestSwapIDObjectKey(shardID)
	id, has, err := stateDB.getLatestSwapID(key)
	if err != nil {
		return 0, NewStatedbError(GetLatestSwapIDError, err)
	}
	if !has {
		return 0, NewStatedbError(GetLatestSwapIDError, fmt.Errorf("latest swap id not found for shardID = %v", shardID))
	}
	return id, nil
}
