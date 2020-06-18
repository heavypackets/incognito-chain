package blockchain

import "github.com/incognitochain/incognito-chain/common"

// FullMerkleTree represents a merkle tree using a given hash function.
// All nodes in the merkle tree is stored directly in the struct,
// therefore we can get any nodes as well as their merkle proof
type FullMerkleTree struct {
	nodes  [][][]byte // [height][index][hash]
	hasher common.Hasher
}

func NewFullMerkleTree(hasher common.Hasher) *FullMerkleTree {
	return &FullMerkleTree{
		nodes:  make([][][]byte, 0),
		hasher: hasher,
	}
}

// Add receives a list of new leaf nodes and update the tree accordingly.
// All data are hashed and add to level 0 of the tree
func (tree *FullMerkleTree) Add(data [][]byte) {
	for _, d := range data {
		// Get hash of the leaf of new node
		hash := common.Keccak256(d)
		h := hash[:]

		for level := 0; level < len(tree.nodes); level++ {
			id := len(tree.nodes[level])
			tree.nodes[level] = append(tree.nodes[level], h)
			if id%2 == 0 {
				continue
			}

			if level+1 >= len(tree.nodes) {
				tree.nodes = append(tree.nodes, [][]byte{}) // New height
			}
			tree.nodes[level+1] = append(tree.nodes[level+1], tree.hasher(tree.nodes[level][id-1], tree.nodes[level][id]))
			break
		}
	}
}

// GetRoot returns the current root of the tree
func (tree *FullMerkleTree) GetRoot() []byte {
	return tree.nodes[len(tree.nodes)][0] // Highest level always has 1 node
}

// GetLength returns number of leaves in the tree
func (tree *FullMerkleTree) GetLength() uint64 {
	return uint64(len(tree.nodes[0]))
}
