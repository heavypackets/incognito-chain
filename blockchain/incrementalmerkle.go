package blockchain

import (
	"github.com/incognitochain/incognito-chain/common"
)

// IncrementalMerkleTree represents a merkle tree using Keccak256 hash function.
// We can incrementally add an element and get the root hash at each step.
// Note: this data structure is optimized for storage, therefore we cannot get
// a merkle proof at an arbitrary position.
type IncrementalMerkleTree struct {
	nodes  [][]byte
	length uint64
	hasher hash2
}

type hash2 func(...[]byte) []byte // Receive 2 childs and return the parent hash

func NewIncrementalMerkleTree(hasher hash2) *IncrementalMerkleTree {
	return &IncrementalMerkleTree{
		nodes:  make([][]byte, 0),
		length: 0,
		hasher: hasher,
	}
}

func InitIncrementalMerkleTree(hasher hash2, nodes [][]byte, length uint64) *IncrementalMerkleTree {
	return &IncrementalMerkleTree{
		nodes:  nodes,
		length: length,
		hasher: hasher,
	}
}

// Add receives a list of new leaf nodes and update the tree accordingly
func (tree *IncrementalMerkleTree) Add(data [][]byte) {
	for _, d := range data {
		// Get hash of the leaf of new node
		hash := common.Keccak256(d)
		h := hash[:]

		added := false // If it stays false, the tree height grew by 1
		for i, sibling := range tree.nodes {
			if sibling != nil {
				h = tree.hasher(sibling, h) // Exist, must be left sibling
				tree.nodes[i] = nil         // Reset the node at this height
			} else {
				tree.nodes[i] = h // Not exist, save the new node at this height
				added = true
				break
			}
		}

		if !added {
			tree.nodes = append(tree.nodes, h)
		}
	}
	tree.length += uint64(len(data))
}

func (tree *IncrementalMerkleTree) SimulateAdd(data []byte) ([][]byte, []uint64, error) {
	return nil, nil, nil
}

// GetRoot calculates the root of the merkle tree built so far
// For an empty tree, the root is 32 bytes of 0
// For a tree with one element, the root is the element itself
// Otherwise, calculate bottom up to get the root
func (tree *IncrementalMerkleTree) GetRoot() []byte {
	if tree.length == 0 {
		return make([]byte, 32)
	}

	// Find the newest subtree that all nodes have values:
	// i.e.: first non-nil value in our tree
	var root []byte
	k := 0
	for i, sibling := range tree.nodes {
		if sibling != nil {
			root = sibling
			k = i
			break
		}
	}
	if k+1 >= len(tree.nodes) {
		return root // If it's the last node, we have a full binary merkle tree
	}

	// Since there's still some nodes left at higher levels,
	// this subtree must be the left subtree
	root = tree.hasher(root, root) // Duplicate and get hash of parent

	// Go up the tree and calculate the root of the parent node
	for _, sibling := range tree.nodes[k+1:] {
		if sibling == nil {
			sibling = root
		}
		root = tree.hasher(sibling, root)
	}
	return root
}

func (tree *IncrementalMerkleTree) GetLength() uint64 {
	return tree.length
}
