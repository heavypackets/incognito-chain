package blockchain

import (
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
