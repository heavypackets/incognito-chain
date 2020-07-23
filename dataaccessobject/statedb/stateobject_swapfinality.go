package statedb

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/incognitochain/incognito-chain/common"
)

type DefaultStateObject struct {
	db *StateDB
	// Write caches.
	trie Trie // storage trie, which becomes non-nil on first access

	publicKeyHash common.Hash

	version    int
	objectType int
	deleted    bool

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error
}

func (c DefaultStateObject) GetVersion() int {
	return c.version
}

// setError remembers the first non-nil error it is called with.
func (c *DefaultStateObject) SetError(err error) {
	if c.dbErr == nil {
		c.dbErr = err
	}
}

func (c DefaultStateObject) GetTrie(db DatabaseAccessWarper) Trie {
	return c.trie
}

func (c DefaultStateObject) GetType() int {
	return c.objectType
}

// MarkDelete will delete an object in trie
func (c *DefaultStateObject) MarkDelete() {
	c.deleted = true
}

func (c DefaultStateObject) IsDeleted() bool {
	return c.deleted
}

// reset all shard committee value into default value
func (c *DefaultStateObject) Reset() bool {
	return true
}

func (c DefaultStateObject) GetHash() common.Hash {
	return c.publicKeyHash
}

type BlockMerkleObject struct {
	DefaultStateObject

	blockHash common.Hash
}

func newBlockMerkleObject(db *StateDB, hash common.Hash) *BlockMerkleObject {
	return &BlockMerkleObject{
		DefaultStateObject: DefaultStateObject{
			version:       defaultVersion,
			db:            db,
			publicKeyHash: hash,
			objectType:    BlockMerkleObjectType,
			deleted:       false,
		},
		blockHash: common.Hash{},
	}
}

func newBlockMerkleObjectWithValue(db *StateDB, key common.Hash, data interface{}) (*BlockMerkleObject, error) {
	var newBlockMerkleHash = common.Hash{}
	if dataHash, ok := data.(common.Hash); ok {
		newBlockMerkleHash = dataHash
	} else if dataBytes, ok := data.([]byte); ok {
		err := json.Unmarshal(dataBytes, &newBlockMerkleHash)
		if err != nil {
			return nil, fmt.Errorf("%+v, unmarshal err %+v", ErrInvalidBlockMerkleHashType, err)
		}
	} else {
		return nil, fmt.Errorf("%+v, got type %+v", ErrInvalidBlockMerkleHashType, reflect.TypeOf(data))
	}
	return &BlockMerkleObject{
		DefaultStateObject: DefaultStateObject{
			version:       defaultVersion,
			db:            db,
			publicKeyHash: key,
			objectType:    BlockMerkleObjectType,
			deleted:       false,
		},
		blockHash: newBlockMerkleHash,
	}, nil
}

func GenerateBlockMerkleObjectKey(shardID, level byte, index uint64) common.Hash {
	data := append(blockMerklePrefix, []byte{shardID, level}...)
	data = append(data, common.Uint64ToBytes(index)...)
	h := common.HashH(data)
	return h
}

func (c BlockMerkleObject) GetValue() interface{} {
	return c.blockHash
}

func (c BlockMerkleObject) GetValueBytes() []byte {
	data := c.GetValue()
	value, err := json.Marshal(data)
	if err != nil {
		panic("failed to marshal all shard committee")
	}
	return value
}

func (c *BlockMerkleObject) SetValue(data interface{}) error {
	blkHash, ok := data.(common.Hash)
	if !ok {
		return fmt.Errorf("%+v, got type %+v", ErrInvalidBlockMerkleHashType, reflect.TypeOf(data))
	}
	c.blockHash = blkHash
	return nil
}

// value is either default or nil
func (c BlockMerkleObject) IsEmpty() bool {
	temp := common.Hash{}
	return reflect.DeepEqual(temp, c.blockHash)
}

type SwapIDForBlockObject struct {
	DefaultStateObject

	id uint64
}

func newSwapIDForBlockObject(db *StateDB, hash common.Hash) *SwapIDForBlockObject {
	return &SwapIDForBlockObject{
		DefaultStateObject: DefaultStateObject{
			version:       defaultVersion,
			db:            db,
			publicKeyHash: hash,
			objectType:    SwapIDForBlockObjectType,
			deleted:       false,
		},
		id: 0,
	}
}

func newSwapIDForBlockObjectWithValue(db *StateDB, key common.Hash, data interface{}) (*SwapIDForBlockObject, error) {
	var newSwapIDForBlock uint64
	if id, ok := data.(uint64); ok {
		newSwapIDForBlock = id
	} else if dataBytes, ok := data.([]byte); ok {
		err := json.Unmarshal(dataBytes, &newSwapIDForBlock)
		if err != nil {
			return nil, fmt.Errorf("%+v, unmarshal err %+v", ErrInvalidSwapIDForBlockType, err)
		}
	} else {
		return nil, fmt.Errorf("%+v, got type %+v", ErrInvalidSwapIDForBlockType, reflect.TypeOf(data))
	}
	return &SwapIDForBlockObject{
		DefaultStateObject: DefaultStateObject{
			version:       defaultVersion,
			db:            db,
			publicKeyHash: key,
			objectType:    SwapIDForBlockObjectType,
			deleted:       false,
		},
		id: newSwapIDForBlock,
	}, nil
}

func GenerateSwapIDForBlockObjectKey(shardID byte, block uint64) common.Hash {
	data := append(swapIDPrefix, shardID)
	data = append(data, common.Uint64ToBytes(block)...)
	h := common.HashH(data)
	return h
}

func (c SwapIDForBlockObject) GetValue() interface{} {
	return c.id
}

func (c SwapIDForBlockObject) GetValueBytes() []byte {
	data := c.GetValue()
	value, err := json.Marshal(data)
	if err != nil {
		panic("failed to marshal all shard committee")
	}
	return value
}

func (c *SwapIDForBlockObject) SetValue(data interface{}) error {
	id, ok := data.(uint64)
	if !ok {
		return fmt.Errorf("%+v, got type %+v", ErrInvalidSwapIDForBlockType, reflect.TypeOf(data))
	}
	c.id = id
	return nil
}

// value is either default or nil
func (c SwapIDForBlockObject) IsEmpty() bool {
	return c.id == 0
}
