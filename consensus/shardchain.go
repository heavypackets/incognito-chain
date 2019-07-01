package consensus

import (
	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/consensus/bft"
	"github.com/incognitochain/incognito-chain/wire"
	"time"
)

type ShardChain struct {
	ShardID    byte
	Node       Node
	BlockGen   blockchain.BlkTmplGenerator
	Blockchain blockchain.BlockChain
}

func (s *ShardChain) PushMessageToValidator(msg wire.Message) error {
	return s.Node.PushMessageToShard(s.ShardID, msg)
}

func (s *ShardChain) GetNodePubKey() string {
	return s.Node.GetNodePubKey()
}

func (s *ShardChain) GetLastBlockTimeStamp() uint64 {
	return uint64(s.Blockchain.BestState.Shard[s.ShardID].BestBlock.Header.Timestamp)
}

func (s *ShardChain) GetBlkMinTime() time.Duration {
	return time.Second * 5

}

func (s *ShardChain) IsReady() bool {
	return s.Blockchain.Synker.IsLatest(true, s.ShardID)
}

func (s *ShardChain) GetHeight() uint64 {
	return s.Blockchain.BestState.Shard[s.ShardID].BestBlock.Header.Height
}

func (s *ShardChain) GetCommitteeSize() int {
	return len(s.Blockchain.BestState.Shard[s.ShardID].ShardCommittee)
}

func (s *ShardChain) GetNodePubKeyIndex() int {
	pubkey := s.Node.GetNodePubKey()
	return common.IndexOfStr(pubkey, s.Blockchain.BestState.Shard[s.ShardID].ShardCommittee)
}

func (s *ShardChain) GetLastProposerIndex() int {
	return common.IndexOfStr(base58.Base58Check{}.Encode(s.Blockchain.BestState.Shard[s.ShardID].BestBlock.Header.ProducerAddress.Pk, common.ZeroByte), s.Blockchain.BestState.Shard[s.ShardID].ShardCommittee)
}

func (s *ShardChain) CreateNewBlock(round int) bft.BlockInterface {
	userKeyset := s.Node.GetUserKeySet()
	newBlock, err := s.BlockGen.NewBlockShard(&userKeyset, s.ShardID, round, s.Blockchain.Synker.GetClosestShardToBeaconPoolState(), s.Blockchain.BestState.Beacon.BeaconHeight, time.Now())
	if err != nil {
		return nil
	} else {
		err = s.BlockGen.FinalizeShardBlock(newBlock, &userKeyset)
		if err != nil {
			return nil
		}
	}
	return newBlock
}

func (s *ShardChain) ValidateBlock(interface{}) bool {
	return true
}

func (s *ShardChain) ValidateSignature(interface{}, string) bool {
	return true
}

func (s *ShardChain) InsertBlk(block interface{}, isValid bool) {
	if isValid {
		s.Blockchain.InsertShardBlock(block.(*blockchain.ShardBlock), true)
	}
}
