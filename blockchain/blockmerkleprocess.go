package blockchain

import (
	"fmt"
	"math"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
)

// addToBlockMerkle adds a new block to the block merkle tree, commits everything
// and return the updated root hash
func addToBlockMerkle(
	blockStateDB *statedb.StateDB,
	shardID byte,
	blkHeight uint64,
	blkHash common.Hash,
) (common.Hash, error) {
	fmt.Printf("[db] addToBlockMerkle: shardID %d, blkHeight %d blkHash %s\n", shardID, blkHeight, blkHash.String())
	if err := storeBlockMerkle(
		blockStateDB,
		shardID,
		blkHeight,
		blkHash,
	); err != nil {
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
	shardID byte,
	blkHeight uint64,
	blkHash common.Hash,
) error {
	// Load the latest merkle tree
	tree, err := loadIncrementalMerkle(
		blockStateDB,
		shardID,
		blkHeight, // Previous tree has X blocks (including dummy block with height = 0)
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
	fmt.Printf("[db] storeBlockMerkle: nodes: %+v, indices: %+v\n", nodes, indices)
	for level, h := range nodes {
		hash := common.BytesToHash(h)
		index := indices[level]
		fmt.Printf("[db] store block merkle node: level %d index %d hash %s\n", level, index, hash.String())
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
	shardID byte,
	treeLen uint64, // Number of leaves in the merkle tree (i.e., blockHeight-1)
) (*IncrementalMerkleTree, error) {
	fmt.Printf("[db] loadIncrementalMerkle: shardID %d, treeLen %d\n", shardID, treeLen)
	if treeLen == 0 {
		return InitIncrementalMerkleTree(common.Keccak256Bytes, [][]byte{}, 0), nil
	}

	index := uint64(treeLen) - 1                  // Block h is stored at the leaf with index h-1 in the tree
	maxLevel := byte(math.Log2(float64(treeLen))) // Height of the merkle tree

	hashes := make([][]byte, maxLevel+1)
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

	tree := InitIncrementalMerkleTree(common.Keccak256Bytes, hashes, treeLen)
	return tree, nil
}

func GetMerkleProofWithRoot(
	stateDB *statedb.StateDB,
	shardID byte,
	leafID uint64,
	treeLen uint64,
) ([][]byte, []bool, error) {
	// Get merkle tree at that height
	tree, err := loadIncrementalMerkle(
		stateDB,
		shardID,
		treeLen,
	)
	if err != nil {
		return nil, nil, err
	}

	// Precompute 'phantom' nodes: those that are duplicated to calculate the hash of parent's node
	phantoms := tree.GetPathToRoot()

	maxLevel := byte(math.Log2(float64(treeLen-1))) + 1 // Height of the full merkle tree without root
	path := make([][]byte, maxLevel)                    // No need to return root
	left := make([]bool, maxLevel)
	maxID := treeLen - 1 // ID of the right-most node at leaf level
	for level := byte(0); level < maxLevel; level++ {
		sibling := leafID ^ 1
		fmt.Printf("[db] getting node: level = %v, id = %v, max = %v\n", level, sibling, maxID)
		if sibling <= maxID { // The merkle tree must have stored this node
			if hash, err := statedb.GetBlockMerkleNode(stateDB, shardID, level, sibling); err == nil {
				path[level] = hash[:]
				left[level] = sibling < leafID
			} else {
				return nil, nil, err
			}
		} else {
			path[level] = phantoms[level]
			left[level] = sibling < leafID
		}

		leafID /= 2
		maxID = (maxID - 1) / 2
	}
	return path, left, nil
}
