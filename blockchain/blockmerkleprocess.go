package blockchain

import (
	"math"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
)

// addToBlockMerkle adds a new block to the block merkle tree, commits everything
// and return the updated root hash
func addToBlockMerkle(
	blockStateDB *statedb.StateDB,
	blockStateDBRootHash common.Hash,
	shardID byte,
	blkHeight uint64,
	blkHash common.Hash,
) (common.Hash, error) {
	if err := storeBlockMerkle(blockStateDB, blockStateDBRootHash, shardID, blkHeight, blkHash); err != nil {
		return common.Hash{}, NewBlockChainError(StoreShardBlockError, err)
	}
	newBlockRootHash, err := blockStateDB.Commit(true)
	if err != nil {
		return common.Hash{}, NewBlockChainError(StoreShardBlockError, err)
	}
	err = blockStateDB.Database().TrieDB().Commit(newBlockRootHash, false)
	if err != nil {
		return common.Hash{}, NewBlockChainError(StoreShardBlockError, err)
	}
	return newBlockRootHash, nil
}

// storeBlockMerkle updates the block merkle tree and stores the (updated) nodes into statedb
// The block merkle tree root hash is loaded from a previous best state and the new block is added
// This method doesn't commit the new root hash though, caller must call commit and save the root hash accordingly
func storeBlockMerkle(
	blockStateDB *statedb.StateDB,
	blockStateDBRootHash common.Hash,
	shardID byte,
	blkHeight uint64,
	blkHash common.Hash,
) error {
	// Load the current merkle tree
	tree, err := loadIncrementalMerkle(
		blockStateDB,
		blockStateDBRootHash,
		shardID,
		blkHeight-1,
	)
	if err != nil {
		return err
	}

	// Add the new block to the tree and get the changed nodes
	hash := blkHash
	nodes, indices, err := tree.SimulateAdd(hash[:])
	if err != nil {
		return err
	}

	// Store the merkle tree's nodes changed by the new block
	for level, h := range nodes {
		hash := common.BytesToHash(h)
		index := indices[level]
		if err := statedb.StoreBlockMerkleNode(blockStateDB, shardID, byte(level), index, hash); err != nil {
			return err
		}
	}

	return nil
}

// loadIncrementalMerkle reads each node of a merkle tree from statedb and rebuilds it
// To read from statedb, we must provide rootHash of the tree, shardID to calculate
// the key in the database and the blockHeight to know the height of the tree.
func loadIncrementalMerkle(
	stateDB *statedb.StateDB,
	rootHash common.Hash,
	shardID byte,
	blkHeight uint64,
) (*IncrementalMerkleTree, error) {
	index := blkHeight - 1                          // Block h is stored at the leaf with index h-1 in the tree
	maxLevel := byte(math.Log2(float64(blkHeight))) // Height of the merkle tree

	hashes := make([][]byte, maxLevel)
	for level := byte(0); level <= maxLevel; level++ {
		indexAtLevel := (index + 1) >> level
		if indexAtLevel%2 == 0 {
			// Left subtree at this level, therefore the IncrementalMerkleTree
			// doesn't store this node
			continue
		}

		if hash, err := statedb.GetBlockMerkleNode(stateDB, shardID, level, indexAtLevel-1); err == nil {
			hashes[level] = hash[:]
		} else {
			return nil, err
		}
	}

	tree := InitIncrementalMerkleTree(common.Keccak256Bytes, hashes, blkHeight)
	return tree, nil
}
