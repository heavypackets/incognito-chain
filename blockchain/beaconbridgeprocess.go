package blockchain

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/incognitochain/incognito-chain/database"
	"math/big"
	"strconv"

	rCommon "github.com/ethereum/go-ethereum/common"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/pkg/errors"
)

// NOTE: for whole bridge's deposit process, anytime an error occurs it will be logged for debugging and the request will be skipped for retry later. No error will be returned so that the network can still continue to process others.

type UpdatingInfo struct {
	countUpAmt      uint64
	deductAmt       uint64
	tokenID         common.Hash
	externalTokenID []byte
	isCentralized   bool
}

type BurningReqAction struct {
	Meta          metadata.BurningRequest `json:"meta"`
	RequestedTxID *common.Hash            `json:"RequestedTxID"`
}

func (blockchain *BlockChain) processBridgeInstructions(block *BeaconBlock, bd *[]database.BatchData) error {
	updatingInfoByTokenID := map[common.Hash]UpdatingInfo{}
	for _, inst := range block.Body.Instructions {
		if len(inst) < 2 {
			continue // Not error, just not bridge instruction
		}
		var err error
		switch inst[0] {
		case strconv.Itoa(metadata.IssuingETHRequestMeta):
			updatingInfoByTokenID, err = blockchain.processIssuingETHReq(inst, updatingInfoByTokenID)

		case strconv.Itoa(metadata.IssuingRequestMeta):
			updatingInfoByTokenID, err = blockchain.processIssuingReq(inst, updatingInfoByTokenID)

		case strconv.Itoa(metadata.ContractingRequestMeta):
			updatingInfoByTokenID, err = blockchain.processContractingReq(inst, updatingInfoByTokenID)

		case strconv.Itoa(metadata.BurningConfirmMeta):
			updatingInfoByTokenID, err = blockchain.processBurningReq(inst, updatingInfoByTokenID)

		}
		if err != nil {
			return err
		}
	}
	for _, updatingInfo := range updatingInfoByTokenID {
		var updatingAmt uint64
		var updatingType string
		if updatingInfo.countUpAmt > updatingInfo.deductAmt {
			updatingAmt = updatingInfo.countUpAmt - updatingInfo.deductAmt
			updatingType = "+"
		}
		if updatingInfo.countUpAmt < updatingInfo.deductAmt {
			updatingAmt = updatingInfo.deductAmt - updatingInfo.countUpAmt
			updatingType = "-"
		}
		err := blockchain.GetDatabase().UpdateBridgeTokenInfo(
			updatingInfo.tokenID,
			updatingInfo.externalTokenID,
			updatingInfo.isCentralized,
			updatingAmt,
			updatingType,
			bd,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (blockchain *BlockChain) processContractingReq(instruction []string, updatingInfoByTokenID map[common.Hash]UpdatingInfo) (map[common.Hash]UpdatingInfo, error) {
	if len(instruction) != 4 {
		return nil, nil // skip the instruction
	}
	if instruction[2] == "rejected" {
		return nil, nil // skip the instruction
	}
	contentBytes, err := base64.StdEncoding.DecodeString(instruction[3])
	if err != nil {
		fmt.Println("WARNING: an error occured while decoding content string of accepted contracting instruction: ", err)
		return nil, nil
	}
	var contractingReqAction metadata.ContractingReqAction
	err = json.Unmarshal(contentBytes, &contractingReqAction)
	if err != nil {
		fmt.Println("WARNING: an error occured while unmarshaling accepted contracting instruction: ", err)
		return nil, nil
	}
	md := contractingReqAction.Meta
	updatingInfo, found := updatingInfoByTokenID[md.TokenID]
	if found {
		updatingInfo.deductAmt += md.BurnedAmount
	} else {
		updatingInfo = UpdatingInfo{
			countUpAmt:    0,
			deductAmt:     md.BurnedAmount,
			tokenID:       md.TokenID,
			isCentralized: true,
		}
	}
	updatingInfoByTokenID[md.TokenID] = updatingInfo
	return updatingInfoByTokenID, nil
}

func (blockchain *BlockChain) processBurningReq(instruction []string, updatingInfoByTokenID map[common.Hash]UpdatingInfo) (map[common.Hash]UpdatingInfo, error) {
	if len(instruction) < 8 {
		return nil, nil // skip the instruction
	}

	externalTokenID, _, errExtToken := base58.Base58Check{}.Decode(instruction[2])
	incTokenIDBytes, _, errIncToken := base58.Base58Check{}.Decode(instruction[6])
	amountBytes, _, errAmount := base58.Base58Check{}.Decode(instruction[4])
	if err := common.CheckError(errExtToken, errIncToken, errAmount); err != nil {
		BLogger.log.Error(errors.WithStack(err))
		return nil, nil
	}
	amt := big.NewInt(0).SetBytes(amountBytes)
	amount := uint64(0)
	if bytes.Equal(externalTokenID, rCommon.HexToAddress(common.EthAddrStr).Bytes()) {
		amount = big.NewInt(0).Div(amt, big.NewInt(1000000000)).Uint64()
	} else {
		amount = amt.Uint64()
	}

	incTokenID := &common.Hash{}
	incTokenID, _ = (*incTokenID).NewHash(incTokenIDBytes)
	updatingInfo, found := updatingInfoByTokenID[*incTokenID]
	if found {
		updatingInfo.deductAmt += amount
	} else {
		updatingInfo = UpdatingInfo{
			countUpAmt:      0,
			deductAmt:       amount,
			tokenID:         *incTokenID,
			externalTokenID: externalTokenID,
			isCentralized:   false,
		}
	}
	updatingInfoByTokenID[*incTokenID] = updatingInfo
	return updatingInfoByTokenID, nil
}

func (blockchain *BlockChain) processIssuingETHReq(instruction []string, updatingInfoByTokenID map[common.Hash]UpdatingInfo) (map[common.Hash]UpdatingInfo, error) {
	if len(instruction) != 4 {
		return nil, nil // skip the instruction
	}

	if instruction[2] == "rejected" {
		txReqID, err := common.Hash{}.NewHashFromStr(instruction[3])
		if err != nil {
			fmt.Println("WARNING: an error occured while building tx request id in bytes from string: ", err)
			return nil, nil
		}
		err = blockchain.GetDatabase().TrackBridgeReqWithStatus(*txReqID, common.BridgeRequestRejectedStatus, nil)
		if err != nil {
			fmt.Println("WARNING: an error occured while tracking bridge request with rejected status to leveldb: ", err)
		}
		return nil, nil
	}

	db := blockchain.GetDatabase()
	contentBytes, err := base64.StdEncoding.DecodeString(instruction[3])
	if err != nil {
		fmt.Println("WARNING: an error occured while decoding content string of accepted issuance instruction: ", err)
		return nil, nil
	}
	var issuingETHAcceptedInst metadata.IssuingETHAcceptedInst
	err = json.Unmarshal(contentBytes, &issuingETHAcceptedInst)
	if err != nil {
		fmt.Println("WARNING: an error occured while unmarshaling accepted issuance instruction: ", err)
		return nil, nil
	}
	err = db.InsertETHTxHashIssued(issuingETHAcceptedInst.UniqETHTx)
	if err != nil {
		fmt.Println("WARNING: an error occured while inserting ETH tx hash issued to leveldb: ", err)
		return nil, nil
	}

	updatingInfo, found := updatingInfoByTokenID[issuingETHAcceptedInst.IncTokenID]
	if found {
		updatingInfo.countUpAmt += issuingETHAcceptedInst.IssuingAmount
	} else {
		updatingInfo = UpdatingInfo{
			countUpAmt:      issuingETHAcceptedInst.IssuingAmount,
			deductAmt:       0,
			tokenID:         issuingETHAcceptedInst.IncTokenID,
			externalTokenID: issuingETHAcceptedInst.ExternalTokenID,
			isCentralized:   false,
		}
	}
	updatingInfoByTokenID[issuingETHAcceptedInst.IncTokenID] = updatingInfo
	return updatingInfoByTokenID, nil
}

func (blockchain *BlockChain) processIssuingReq(instruction []string, updatingInfoByTokenID map[common.Hash]UpdatingInfo) (map[common.Hash]UpdatingInfo, error) {
	if len(instruction) != 4 {
		return nil, nil // skip the instruction
	}

	if instruction[2] == "rejected" {
		txReqID, err := common.Hash{}.NewHashFromStr(instruction[3])
		if err != nil {
			fmt.Println("WARNING: an error occured while building tx request id in bytes from string: ", err)
			return nil, nil
		}
		err = blockchain.GetDatabase().TrackBridgeReqWithStatus(*txReqID, common.BridgeRequestRejectedStatus, nil)
		if err != nil {
			fmt.Println("WARNING: an error occured while tracking bridge request with rejected status to leveldb: ", err)
		}
		return nil, nil
	}

	contentBytes, err := base64.StdEncoding.DecodeString(instruction[3])
	if err != nil {
		fmt.Println("WARNING: an error occured while decoding content string of accepted issuance instruction: ", err)
		return nil, nil
	}
	var issuingAcceptedInst metadata.IssuingAcceptedInst
	err = json.Unmarshal(contentBytes, &issuingAcceptedInst)
	if err != nil {
		fmt.Println("WARNING: an error occured while unmarshaling accepted issuance instruction: ", err)
		return nil, nil
	}

	updatingInfo, found := updatingInfoByTokenID[issuingAcceptedInst.IncTokenID]
	if found {
		updatingInfo.countUpAmt += issuingAcceptedInst.DepositedAmount
	} else {
		updatingInfo = UpdatingInfo{
			countUpAmt:    issuingAcceptedInst.DepositedAmount,
			deductAmt:     0,
			tokenID:       issuingAcceptedInst.IncTokenID,
			isCentralized: true,
		}
	}
	updatingInfoByTokenID[issuingAcceptedInst.IncTokenID] = updatingInfo
	return updatingInfoByTokenID, nil
}

func decodeContent(content string, action interface{}) error {
	contentBytes, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return err
	}
	return json.Unmarshal(contentBytes, &action)
}

func (blockchain *BlockChain) storeBurningConfirm(block *ShardBlock, bd *[]database.BatchData) error {
	for _, inst := range block.Body.Instructions {
		if inst[0] != strconv.Itoa(metadata.BurningConfirmMeta) {
			continue
		}
		BLogger.log.Infof("storeBurningConfirm for block %d, inst %v", block.Header.Height, inst)

		txID, err := common.Hash{}.NewHashFromStr(inst[5])
		if err != nil {
			return errors.Wrap(err, "txid invalid")
		}
		if err := blockchain.config.DataBase.StoreBurningConfirm(*txID, block.Header.Height, bd); err != nil {
			return errors.Wrapf(err, "store failed, txID: %x", txID)
		}
	}
	return nil
}

func (blockchain *BlockChain) updateBridgeIssuanceStatus(block *ShardBlock, bd *[]database.BatchData) error {
	db := blockchain.config.DataBase
	for _, tx := range block.Body.Transactions {
		metaType := tx.GetMetadataType()
		var reqTxID common.Hash
		if metaType == metadata.IssuingETHResponseMeta {
			meta := tx.GetMetadata().(*metadata.IssuingETHResponse)
			reqTxID = meta.RequestedTxID
		} else if metaType == metadata.IssuingResponseMeta {
			meta := tx.GetMetadata().(*metadata.IssuingResponse)
			reqTxID = meta.RequestedTxID
		}
		var err error
		err = db.TrackBridgeReqWithStatus(reqTxID, common.BridgeRequestAcceptedStatus, bd)
		if err != nil {
			return err
		}
	}
	return nil
}
