package jsonresult

type GetInstructionProof struct {
	Instruction  string // Hex-encoded swap inst
	BeaconHeight string // Hex encoded height of the block contains the inst
	BridgeHeight string

	BeaconInstPath       []string // Hex encoded path of the inst in merkle tree
	BeaconInstPathIsLeft []bool   // Indicate if it is the left or right node
	BeaconInstRoot       string   // Hex encoded root of the inst merkle tree
	BeaconBlkData        string   // Hex encoded hash of the block meta
	BeaconSigs           []string // Hex encoded signature (r, s, v)
	BeaconSigIdxs        []int    // Idxs of signer

	BridgeInstPath       []string
	BridgeInstPathIsLeft []bool
	BridgeInstRoot       string
	BridgeBlkData        string
	BridgeSigs           []string
	BridgeSigIdxs        []int
}

// GetFinalityProof contains the proof that 2 blocks N and N+1 is valid and N is finalled
type GetFinalityProof struct {
	Instructions [2]string   // BlockMerkleRootMeta instruction
	InstPaths    [2][]string // Proofs that the above insts are in the blocks
	IDs          [2]int64    // Index of the instruction in the block

	BlkData [2]string
	Sigs    [2][]string // Hex encoded signature (r, s, v)
	SigIdxs [2][]int    // Idxs of signer
}

type GetAncestorProof struct {
	Path []string
	ID   int64
}
