package blockchain

import (
	"fmt"

	"github.com/incognitochain/incognito-chain/common"
)

// IncrementalMerkleTree represents a merkle tree using an arbitrary hash function.
// We can incrementally add an element and get the root hash at each step.
// Note: this data structure is optimized for storage, therefore we cannot get
// a merkle proof at an arbitrary position.
type IncrementalMerkleTree struct {
	nodes  [][]byte
	length uint64
	hasher common.Hasher
}

func NewIncrementalMerkleTree(hasher common.Hasher) *IncrementalMerkleTree {
	return &IncrementalMerkleTree{
		nodes:  make([][]byte, 0),
		length: 0,
		hasher: hasher,
	}
}

func InitIncrementalMerkleTree(hasher common.Hasher, nodes [][]byte, length uint64) *IncrementalMerkleTree {
	return &IncrementalMerkleTree{
		nodes:  nodes,
		length: length,
		hasher: hasher,
	}
}

// Add receives a list of new leaf nodes and update the tree accordingly
func (tree *IncrementalMerkleTree) Add(data [][]byte) {
	for k, d := range data {
		// Get hash of the leaf of new node
		pos := tree.length + uint64(k)
		hash := common.HashLR(tree.hasher, pos, d)
		h := hash[:]

		added := false // If it stays false, the tree height grew by 1
		for i, sibling := range tree.nodes {
			pos /= 2
			if sibling != nil {
				h = common.HashLR(tree.hasher, pos, sibling, h) // Exist, must be left sibling
				tree.nodes[i] = nil                             // Reset the node at this height
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

// SimulateAdd simulates adding a single element to the tree and returns the updated nodes
// This method helps updating the merkle tree in database without having to update all nodes
// The return values are the hash of the updated nodes and their indices at each level
func (tree *IncrementalMerkleTree) SimulateAdd(data []byte) ([][]byte, []uint64, error) {
	fmt.Printf("[db] SimulateAdd: tree length %d, tree.nodes %d len(data) %d\n", tree.length, len(tree.nodes), len(data))
	// Get hash of the leaf of new node
	id := tree.length // Index of the adding leaf
	h := common.HashLR(tree.hasher, id, data)

	updatedNodes := [][]byte{}
	updatedIdxs := []uint64{}
	added := false // If it stays false, the tree height grew by 1
	for _, sibling := range tree.nodes {
		updatedNodes = append(updatedNodes, h)
		updatedIdxs = append(updatedIdxs, id)
		id = id / 2 // Parent's index

		if sibling != nil {
			h = common.HashLR(tree.hasher, id, sibling, h) // Exist, must be left sibling
		} else {
			added = true // Not exist, save the new node at this height
			break
		}
	}

	if !added {
		updatedNodes = append(updatedNodes, h)
		updatedIdxs = append(updatedIdxs, id)
	}
	return updatedNodes, updatedIdxs, nil
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
	id := (tree.length - 1) / 2
	root = common.HashLR(tree.hasher, id, root, root) // Duplicate and get hash of parent

	// Go up the tree and calculate the root of the parent node
	for _, sibling := range tree.nodes[k+1:] {
		id = id / 2
		if sibling == nil {
			sibling = root
		}
		root = common.HashLR(tree.hasher, id, sibling, root)
	}
	return root
}

func (tree *IncrementalMerkleTree) GetLength() uint64 {
	return tree.length
}
