package rpcservice

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/database"
	"github.com/incognitochain/incognito-chain/incognitokey"
	"github.com/incognitochain/incognito-chain/mempool"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/rpcserver/bean"
	"github.com/incognitochain/incognito-chain/rpcserver/jsonresult"
	"github.com/incognitochain/incognito-chain/transaction"
	"github.com/incognitochain/incognito-chain/wallet"
	"github.com/incognitochain/incognito-chain/wire"
	"math/big"
	"sort"

	error2 "github.com/pkg/errors"
)

type TxService struct {
	DB           *database.DatabaseInterface
	BlockChain   *blockchain.BlockChain
	Wallet       *wallet.Wallet
	FeeEstimator map[byte]*mempool.FeeEstimator
	TxMemPool    *mempool.TxPool
}

// chooseBestOutCoinsToSpent returns list of unspent coins for spending with amount
func (txService TxService) chooseBestOutCoinsToSpent(outCoins []*privacy.OutputCoin, amount uint64) (resultOutputCoins []*privacy.OutputCoin, remainOutputCoins []*privacy.OutputCoin, totalResultOutputCoinAmount uint64, err error) {
	resultOutputCoins = make([]*privacy.OutputCoin, 0)
	remainOutputCoins = make([]*privacy.OutputCoin, 0)
	totalResultOutputCoinAmount = uint64(0)

	// either take the smallest coins, or a single largest one
	var outCoinOverLimit *privacy.OutputCoin
	outCoinsUnderLimit := make([]*privacy.OutputCoin, 0)

	for _, outCoin := range outCoins {
		if outCoin.CoinDetails.GetValue() < amount {
			outCoinsUnderLimit = append(outCoinsUnderLimit, outCoin)
		} else if outCoinOverLimit == nil {
			outCoinOverLimit = outCoin
		} else if outCoinOverLimit.CoinDetails.GetValue() > outCoin.CoinDetails.GetValue() {
			remainOutputCoins = append(remainOutputCoins, outCoin)
		} else {
			remainOutputCoins = append(remainOutputCoins, outCoinOverLimit)
			outCoinOverLimit = outCoin
		}
	}

	sort.Slice(outCoinsUnderLimit, func(i, j int) bool {
		return outCoinsUnderLimit[i].CoinDetails.GetValue() < outCoinsUnderLimit[j].CoinDetails.GetValue()
	})

	for _, outCoin := range outCoinsUnderLimit {
		if totalResultOutputCoinAmount < amount {
			totalResultOutputCoinAmount += outCoin.CoinDetails.GetValue()
			resultOutputCoins = append(resultOutputCoins, outCoin)
		} else {
			remainOutputCoins = append(remainOutputCoins, outCoin)
		}
	}

	if outCoinOverLimit != nil && (outCoinOverLimit.CoinDetails.GetValue() > 2*amount || totalResultOutputCoinAmount < amount) {
		remainOutputCoins = append(remainOutputCoins, resultOutputCoins...)
		resultOutputCoins = []*privacy.OutputCoin{outCoinOverLimit}
		totalResultOutputCoinAmount = outCoinOverLimit.CoinDetails.GetValue()
	} else if outCoinOverLimit != nil {
		remainOutputCoins = append(remainOutputCoins, outCoinOverLimit)
	}

	if totalResultOutputCoinAmount < amount {
		return resultOutputCoins, remainOutputCoins, totalResultOutputCoinAmount, errors.New("Not enough coin")
	} else {
		return resultOutputCoins, remainOutputCoins, totalResultOutputCoinAmount, nil
	}
}

func (txService TxService) filterMemPoolOutcoinsToSpent(outCoins []*privacy.OutputCoin) ([]*privacy.OutputCoin, error) {
	remainOutputCoins := make([]*privacy.OutputCoin, 0)

	for _, outCoin := range outCoins {
		if txService.TxMemPool.ValidateSerialNumberHashH(outCoin.CoinDetails.GetSerialNumber().Compress()) == nil {
			remainOutputCoins = append(remainOutputCoins, outCoin)
		}
	}
	return remainOutputCoins, nil
}

func (txService TxService) chooseOutsCoinByKeyset(paymentInfos []*privacy.PaymentInfo,
	estimateFeeCoinPerKb int64, numBlock uint64, keyset *incognitokey.KeySet, shardIDSender byte,
	hasPrivacy bool,
	metadataParam metadata.Metadata,
	customTokenParams *transaction.CustomTokenParamTx,
	privacyCustomTokenParams *transaction.CustomTokenPrivacyParamTx,
) ([]*privacy.InputCoin, uint64, *RPCError) {
	// estimate fee according to 8 recent block
	if numBlock == 0 {
		numBlock = 1000
	}
	// calculate total amount to send
	totalAmmount := uint64(0)
	for _, receiver := range paymentInfos {
		totalAmmount += receiver.Amount
	}

	// get list outputcoins tx
	prvCoinID := &common.Hash{}
	prvCoinID.SetBytes(common.PRVCoinID[:])
	outCoins, err := txService.BlockChain.GetListOutputCoinsByKeyset(keyset, shardIDSender, prvCoinID)
	if err != nil {
		return nil, 0, NewRPCError(GetOutputCoinError, err)
	}
	// remove out coin in mem pool
	outCoins, err = txService.filterMemPoolOutcoinsToSpent(outCoins)
	if err != nil {
		return nil, 0, NewRPCError(GetOutputCoinError, err)
	}
	if len(outCoins) == 0 && totalAmmount > 0 {
		return nil, 0, NewRPCError(GetOutputCoinError, errors.New("not enough output coin"))
	}
	// Use Knapsack to get candiate output coin
	candidateOutputCoins, outCoins, candidateOutputCoinAmount, err := txService.chooseBestOutCoinsToSpent(outCoins, totalAmmount)
	if err != nil {
		return nil, 0, NewRPCError(GetOutputCoinError, err)
	}
	// refund out put for sender
	overBalanceAmount := candidateOutputCoinAmount - totalAmmount
	if overBalanceAmount > 0 {
		// add more into output for estimate fee
		paymentInfos = append(paymentInfos, &privacy.PaymentInfo{
			PaymentAddress: keyset.PaymentAddress,
			Amount:         overBalanceAmount,
		})
	}

	// check real fee(nano PRV) per tx
	realFee, _, _ := txService.EstimateFee(estimateFeeCoinPerKb, candidateOutputCoins,
		paymentInfos, shardIDSender, numBlock, hasPrivacy,
		metadataParam, customTokenParams,
		privacyCustomTokenParams)

	if totalAmmount == 0 && realFee == 0 {
		if metadataParam != nil {
			metadataType := metadataParam.GetType()
			switch metadataType {
			case metadata.WithDrawRewardRequestMeta:
				{
					return nil, realFee, nil
				}
			}
			return nil, realFee, NewRPCError(RejectInvalidFeeError, errors.New(fmt.Sprintf("totalAmmount: %+v, realFee: %+v", totalAmmount, realFee)))
		}
		if privacyCustomTokenParams != nil {
			// for privacy token
			return nil, 0, nil
		}
	}

	needToPayFee := int64((totalAmmount + realFee) - candidateOutputCoinAmount)
	// if not enough to pay fee
	if needToPayFee > 0 {
		if len(outCoins) > 0 {
			candidateOutputCoinsForFee, _, _, err1 := txService.chooseBestOutCoinsToSpent(outCoins, uint64(needToPayFee))
			if err != nil {
				return nil, 0, NewRPCError(GetOutputCoinError, err1)
			}
			candidateOutputCoins = append(candidateOutputCoins, candidateOutputCoinsForFee...)
		}
	}
	// convert to inputcoins
	inputCoins := transaction.ConvertOutputCoinToInputCoin(candidateOutputCoins)
	return inputCoins, realFee, nil
}

// EstimateFee - estimate fee from tx data and return real full fee, fee per kb and real tx size
func (txService TxService) EstimateFee(
	defaultFee int64,
	candidateOutputCoins []*privacy.OutputCoin,
	paymentInfos []*privacy.PaymentInfo, shardID byte,
	numBlock uint64, hasPrivacy bool,
	metadata metadata.Metadata,
	customTokenParams *transaction.CustomTokenParamTx,
	privacyCustomTokenParams *transaction.CustomTokenPrivacyParamTx) (uint64, uint64, uint64) {
	if numBlock == 0 {
		numBlock = 1000
	}
	// check real fee(nano PRV) per tx
	var realFee uint64
	estimateFeeCoinPerKb := uint64(0)
	estimateTxSizeInKb := uint64(0)

	tokenId := &common.Hash{}
	if privacyCustomTokenParams != nil {
		tokenId, _ = common.Hash{}.NewHashFromStr(privacyCustomTokenParams.PropertyID)
	}

	estimateFeeCoinPerKb = txService.EstimateFeeWithEstimator(defaultFee, shardID, numBlock, tokenId)

	if txService.Wallet != nil {
		estimateFeeCoinPerKb += uint64(txService.Wallet.GetConfig().IncrementalFee)
	}

	limitFee := uint64(0)
	if feeEstimator, ok := txService.FeeEstimator[shardID]; ok {
		limitFee = feeEstimator.GetLimitFee()
	}
	estimateTxSizeInKb = transaction.EstimateTxSize(transaction.NewEstimateTxSizeParam(candidateOutputCoins, paymentInfos, hasPrivacy, metadata, customTokenParams, privacyCustomTokenParams, limitFee))

	realFee = uint64(estimateFeeCoinPerKb) * uint64(estimateTxSizeInKb)
	return realFee, estimateFeeCoinPerKb, estimateTxSizeInKb
}

// EstimateFeeWithEstimator - only estimate fee by estimator and return fee per kb
func (txService TxService) EstimateFeeWithEstimator(defaultFee int64, shardID byte, numBlock uint64, tokenId *common.Hash) uint64 {
	estimateFeeCoinPerKb := uint64(0)
	if defaultFee == -1 {
		if _, ok := txService.FeeEstimator[shardID]; ok {
			temp, _ := txService.FeeEstimator[shardID].EstimateFee(numBlock, tokenId)
			estimateFeeCoinPerKb = uint64(temp)
		}
		if estimateFeeCoinPerKb == 0 {
			if feeEstimator, ok := txService.FeeEstimator[shardID]; ok {
				estimateFeeCoinPerKb = feeEstimator.GetLimitFee()
			}
		}
	} else {
		estimateFeeCoinPerKb = uint64(defaultFee)
	}
	return estimateFeeCoinPerKb
}

func (txService TxService) BuildRawTransaction(params *bean.CreateRawTxParam, meta metadata.Metadata) (*transaction.Tx, *RPCError) {
	Logger.log.Infof("Params: \n%+v\n\n\n", params)

	// get output coins to spend and real fee
	inputCoins, realFee, err1 := txService.chooseOutsCoinByKeyset(
		params.PaymentInfos, params.EstimateFeeCoinPerKb, 0,
		params.SenderKeySet, params.ShardIDSender, params.HasPrivacyCoin,
		meta, nil, nil)
	if err1 != nil {
		return nil, err1
	}

	// init tx
	tx := transaction.Tx{}
	err := tx.Init(
		transaction.NewTxPrivacyInitParams(
			&params.SenderKeySet.PrivateKey,
			params.PaymentInfos,
			inputCoins,
			realFee,
			params.HasPrivacyCoin,
			*txService.DB,
			nil, // use for prv coin -> nil is valid
			meta,
			params.Info,
		))
	if err != nil {
		return nil, NewRPCError(CreateTxDataError, err)
	}

	return &tx, nil
}

func (txService TxService) CreateRawTransaction(params *bean.CreateRawTxParam, meta metadata.Metadata) (*common.Hash, []byte, byte, *RPCError) {
	var err error
	tx, err := txService.BuildRawTransaction(params, meta)
	if err.(*RPCError) != nil {
		Logger.log.Critical(err)
		return nil, nil, byte(0), NewRPCError(CreateTxDataError, err)
	}

	txBytes, err := json.Marshal(tx)
	if err != nil {
		// return hex for a new tx
		return nil, nil, byte(0), NewRPCError(CreateTxDataError, err)
	}

	txShardID := common.GetShardIDFromLastByte(tx.GetSenderAddrLastByte())

	return tx.Hash(), txBytes, txShardID, nil
}

func (txService TxService) SendRawTransaction(txB58Check string) (wire.Message, *common.Hash, byte, *RPCError) {
	rawTxBytes, _, err := base58.Base58Check{}.Decode(txB58Check)
	if err != nil {
		Logger.log.Errorf("handleSendRawTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, byte(0), NewRPCError(SendTxDataError, err)
	}
	var tx transaction.Tx
	err = json.Unmarshal(rawTxBytes, &tx)
	if err != nil {
		Logger.log.Errorf("handleSendRawTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, byte(0), NewRPCError(SendTxDataError, err)
	}

	hash, _, err := txService.TxMemPool.MaybeAcceptTransaction(&tx)
	//httpServer.config.NetSync.HandleCacheTxHash(*tx.Hash())
	if err != nil {
		mempoolErr, ok := err.(*mempool.MempoolTxError)
		if ok {
			if mempoolErr.Code == mempool.ErrCodeMessage[mempool.RejectInvalidFee].Code {
				Logger.log.Errorf("handleSendRawTransaction result: %+v, err: %+v", nil, err)
				return nil, nil, byte(0), NewRPCError(RejectInvalidFeeError, mempoolErr)
			}
		}
		Logger.log.Errorf("handleSendRawTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, byte(0), NewRPCError(SendTxDataError, err)
	}

	Logger.log.Debugf("New transaction hash: %+v \n", *hash)

	// broadcast Message
	txMsg, err := wire.MakeEmptyMessage(wire.CmdTx)
	if err != nil {
		Logger.log.Errorf("handleSendRawTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, byte(0), NewRPCError(SendTxDataError, err)
	}

	txMsg.(*wire.MessageTx).Transaction = &tx

	return txMsg, tx.Hash(), tx.PubKeyLastByteSender, nil
}

func (txService TxService) BuildTokenParam(tokenParamsRaw map[string]interface{}, senderKeySet *incognitokey.KeySet, shardIDSender byte) (
	*transaction.CustomTokenParamTx, *transaction.CustomTokenPrivacyParamTx, *RPCError) {

	var customTokenParams *transaction.CustomTokenParamTx
	var customPrivacyTokenParam *transaction.CustomTokenPrivacyParamTx
	var err *RPCError

	isPrivacy := tokenParamsRaw["Privacy"].(bool)
	if !isPrivacy {
		// Check normal custom token param
		customTokenParams, _, err = txService.BuildCustomTokenParam(tokenParamsRaw, senderKeySet)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Check privacy custom token param
		customPrivacyTokenParam, _, _, err = txService.BuildPrivacyCustomTokenParam(tokenParamsRaw, senderKeySet, shardIDSender)
		if err != nil {
			return nil, nil, err
		}
	}

	return customTokenParams, customPrivacyTokenParam, nil

}

func (txService TxService) BuildCustomTokenParam(tokenParamsRaw map[string]interface{}, senderKeySet *incognitokey.KeySet) (*transaction.CustomTokenParamTx, map[common.Hash]transaction.TxNormalToken, *RPCError) {
	tokenParams := &transaction.CustomTokenParamTx{
		PropertyID:     tokenParamsRaw["TokenID"].(string),
		PropertyName:   tokenParamsRaw["TokenName"].(string),
		PropertySymbol: tokenParamsRaw["TokenSymbol"].(string),
		TokenTxType:    int(tokenParamsRaw["TokenTxType"].(float64)),
		Amount:         uint64(tokenParamsRaw["TokenAmount"].(float64)),
	}
	voutsAmount := int64(0)
	tokenParams.Receiver, voutsAmount, _ = transaction.CreateCustomTokenReceiverArray(tokenParamsRaw["TokenReceivers"])
	switch tokenParams.TokenTxType {
	case transaction.CustomTokenTransfer:
		{
			tokenID, err := common.Hash{}.NewHashFromStr(tokenParams.PropertyID)
			if err != nil {
				return nil, nil, NewRPCError(RPCInvalidParamsError, error2.Wrap(err, "Token ID is invalid"))
			}

			//if _, ok := listCustomTokens[*tokenID]; !ok {
			//	return nil, nil, NewRPCError(ErrRPCInvalidParams, errors.New("Invalid Token ID"))
			//}

			existed := txService.BlockChain.CustomTokenIDExisted(tokenID)
			if !existed {
				return nil, nil, NewRPCError(RPCInvalidParamsError, errors.New("Invalid Token ID"))
			}

			unspentTxTokenOuts, err := txService.BlockChain.GetUnspentTxCustomTokenVout(*senderKeySet, tokenID)
			Logger.log.Info("BuildRawCustomTokenTransaction ", unspentTxTokenOuts)
			if err != nil {
				return nil, nil, NewRPCError(GetOutputCoinError, errors.New("Token out invalid"))
			}
			if len(unspentTxTokenOuts) == 0 {
				return nil, nil, NewRPCError(GetOutputCoinError, errors.New("Token out invalid"))
			}
			txTokenIns := []transaction.TxTokenVin{}
			txTokenInsAmount := uint64(0)
			for _, out := range unspentTxTokenOuts {
				item := transaction.TxTokenVin{
					PaymentAddress:  out.PaymentAddress,
					TxCustomTokenID: out.GetTxCustomTokenID(),
					VoutIndex:       out.GetIndex(),
				}
				// create signature by keyset -> base58check.encode of txtokenout double hash
				signature, err := senderKeySet.Sign(out.Hash()[:])
				if err != nil {
					return nil, nil, NewRPCError(CanNotSignError, err)
				}
				// add signature to TxTokenVin to use token utxo
				item.Signature = base58.Base58Check{}.Encode(signature, 0)
				txTokenIns = append(txTokenIns, item)
				txTokenInsAmount += out.Value
				voutsAmount -= int64(out.Value)
				if voutsAmount <= 0 {
					break
				}
			}
			tokenParams.SetVins(txTokenIns)
			tokenParams.SetVinsAmount(txTokenInsAmount)
		}
	case transaction.CustomTokenInit:
		{
			if tokenParams.Receiver[0].Value != tokenParams.Amount { // Init with wrong max amount of custom token
				return nil, nil, NewRPCError(RPCInvalidParamsError, errors.New("Init with wrong max amount of property"))
			}
		}
	}
	//return tokenParams, listCustomTokens, nil
	return tokenParams, nil, nil
}

// BuildRawCustomTokenTransaction ...
func (txService TxService) BuildRawCustomTokenTransaction(
	params interface{},
	metaData metadata.Metadata,
) (*transaction.TxNormalToken, *RPCError) {
	// all params
	arrayParams := common.InterfaceSlice(params)

	// param #1: private key of sender
	senderKeyParam := arrayParams[0]
	var err error
	senderKeySet, shardIDSender, err := GetKeySetFromPrivateKeyParams(senderKeyParam.(string))
	if err != nil {
		return nil, NewRPCError(GetKeySetFromPrivateKeyError, err)
	}

	// param #2: list receiver
	receiversPaymentAddressParam := make(map[string]interface{})
	if arrayParams[1] != nil {
		receiversPaymentAddressParam = arrayParams[1].(map[string]interface{})
	}
	paymentInfos := make([]*privacy.PaymentInfo, 0)
	for paymentAddressStr, amount := range receiversPaymentAddressParam {
		keyWalletReceiver, err := wallet.Base58CheckDeserialize(paymentAddressStr)
		if err != nil {
			return nil, NewRPCError(InvalidReceiverPaymentAddressError, err)
		}
		paymentInfo := &privacy.PaymentInfo{
			Amount:         uint64(amount.(float64)),
			PaymentAddress: keyWalletReceiver.KeySet.PaymentAddress,
		}
		paymentInfos = append(paymentInfos, paymentInfo)
	}

	// param #3: estimation fee coin per kb
	estimateFeeCoinPerKb := int64(arrayParams[2].(float64))

	// param #4: hasPrivacyCoin flag
	hasPrivacyCoin := int(arrayParams[3].(float64)) > 0

	// param #5: token params
	tokenParamsRaw := arrayParams[4].(map[string]interface{})
	tokenParams, listCustomTokens, err := txService.BuildCustomTokenParam(tokenParamsRaw, senderKeySet)
	_ = listCustomTokens
	if err.(*RPCError) != nil {
		return nil, err.(*RPCError)
	}
	/******* START choose output coins native coins(PRV), which is used to create tx *****/
	inputCoins, realFee, err := txService.chooseOutsCoinByKeyset(paymentInfos, estimateFeeCoinPerKb, 0,
		senderKeySet, shardIDSender, hasPrivacyCoin,
		metaData, tokenParams, nil)
	if err.(*RPCError) != nil {
		return nil, err.(*RPCError)
	}
	if len(paymentInfos) == 0 && realFee == 0 {
		hasPrivacyCoin = false
	}
	/******* END GET output coins native coins(PRV), which is used to create tx *****/

	tx := &transaction.TxNormalToken{}
	err = tx.Init(
		transaction.NewTxNormalTokenInitParam(&senderKeySet.PrivateKey,
			nil,
			inputCoins,
			realFee,
			tokenParams,
			//listCustomTokens,
			*txService.DB,
			metaData,
			hasPrivacyCoin,
			shardIDSender))
	if err != nil {
		return nil, NewRPCError(CreateTxDataError, err)
	}

	return tx, nil
}

func (txService TxService) BuildPrivacyCustomTokenParam(tokenParamsRaw map[string]interface{}, senderKeySet *incognitokey.KeySet, shardIDSender byte) (*transaction.CustomTokenPrivacyParamTx, map[common.Hash]transaction.TxCustomTokenPrivacy, map[common.Hash]blockchain.CrossShardTokenPrivacyMetaData, *RPCError) {
	tokenParams := &transaction.CustomTokenPrivacyParamTx{
		PropertyID:     tokenParamsRaw["TokenID"].(string),
		PropertyName:   tokenParamsRaw["TokenName"].(string),
		PropertySymbol: tokenParamsRaw["TokenSymbol"].(string),
		TokenTxType:    int(tokenParamsRaw["TokenTxType"].(float64)),
		Amount:         uint64(tokenParamsRaw["TokenAmount"].(float64)),
		TokenInput:     nil,
		Fee:            uint64(tokenParamsRaw["TokenFee"].(float64)),
	}
	voutsAmount := int64(0)
	tokenParams.Receiver, voutsAmount = transaction.CreateCustomTokenPrivacyReceiverArray(tokenParamsRaw["TokenReceivers"])

	// get list custom token
	switch tokenParams.TokenTxType {
	case transaction.CustomTokenTransfer:
		{
			tokenID, err := common.Hash{}.NewHashFromStr(tokenParams.PropertyID)
			if err != nil {
				return nil, nil, nil, NewRPCError(RPCInvalidParamsError, err)
			}
			existed := txService.BlockChain.PrivacyCustomTokenIDExisted(tokenID)
			existedCrossShard := txService.BlockChain.PrivacyCustomTokenIDCrossShardExisted(tokenID)
			if !existed && !existedCrossShard {
				return nil, nil, nil, NewRPCError(RPCInvalidParamsError, errors.New("Invalid Token ID"))
			}
			outputTokens, err := txService.BlockChain.GetListOutputCoinsByKeyset(senderKeySet, shardIDSender, tokenID)
			if err != nil {
				return nil, nil, nil, NewRPCError(GetOutputCoinError, err)
			}
			outputTokens, err = txService.filterMemPoolOutcoinsToSpent(outputTokens)
			if err != nil {
				return nil, nil, nil, NewRPCError(GetOutputCoinError, err)
			}
			candidateOutputTokens, _, _, err := txService.chooseBestOutCoinsToSpent(outputTokens, uint64(voutsAmount))
			if err != nil {
				return nil, nil, nil, NewRPCError(GetOutputCoinError, err)
			}
			intputToken := transaction.ConvertOutputCoinToInputCoin(candidateOutputTokens)
			tokenParams.TokenInput = intputToken
		}
	case transaction.CustomTokenInit:
		{
			if tokenParams.Receiver[0].Amount != tokenParams.Amount { // Init with wrong max amount of custom token
				return nil, nil, nil, NewRPCError(RPCInvalidParamsError, errors.New("Init with wrong max amount of property"))
			}
		}
	}
	return tokenParams, nil, nil, nil
}

// BuildRawCustomTokenTransaction ...
func (txService TxService) BuildRawPrivacyCustomTokenTransaction(
	params interface{},
	metaData metadata.Metadata,
) (*transaction.TxCustomTokenPrivacy, *RPCError) {
	txParam, errParam := bean.NewCreateRawPrivacyTokenTxParam(params)
	if errParam != nil {
		return nil, NewRPCError(RPCInvalidParamsError, errParam)
	}
	tokenParamsRaw := txParam.TokenParamsRaw
	var err error
	tokenParams, listCustomTokens, listCustomTokenCrossShard, err := txService.BuildPrivacyCustomTokenParam(tokenParamsRaw, txParam.SenderKeySet, txParam.ShardIDSender)

	_ = listCustomTokenCrossShard
	_ = listCustomTokens
	if err.(*RPCError) != nil {
		return nil, err.(*RPCError)
	}

	/******* START choose output native coins(PRV), which is used to create tx *****/
	var inputCoins []*privacy.InputCoin
	var realFeePrv uint64
	inputCoins, realFeePrv, err = txService.chooseOutsCoinByKeyset(txParam.PaymentInfos,
		txParam.EstimateFeeCoinPerKb, 0, txParam.SenderKeySet,
		txParam.ShardIDSender, txParam.HasPrivacyCoin, nil,
		nil, tokenParams)
	if err.(*RPCError) != nil {
		return nil, err.(*RPCError)
	}
	if len(txParam.PaymentInfos) == 0 && realFeePrv == 0 {
		txParam.HasPrivacyCoin = false
	}
	/******* END GET output coins native coins(PRV), which is used to create tx *****/

	tx := &transaction.TxCustomTokenPrivacy{}
	err = tx.Init(
		transaction.NewTxPrivacyTokenInitParams(&txParam.SenderKeySet.PrivateKey,
			txParam.PaymentInfos,
			inputCoins,
			realFeePrv,
			tokenParams,
			*txService.DB,
			metaData,
			txParam.HasPrivacyCoin,
			txParam.HasPrivacyToken,
			txParam.ShardIDSender, txParam.Info))

	if err != nil {
		return nil, NewRPCError(CreateTxDataError, err)
	}

	return tx, nil
}

func (txService TxService) GetTransactionHashByReceiver(paymentAddressParam string) (map[byte][]common.Hash, error) {
	var keySet *incognitokey.KeySet

	if paymentAddressParam != "" {
		senderKey, err := wallet.Base58CheckDeserialize(paymentAddressParam)
		if err != nil {
			return nil, errors.New("key component invalid")
		}

		keySet = &senderKey.KeySet
	} else {
		return nil, errors.New("key component invalid")
	}

	return txService.BlockChain.GetTransactionHashByReceiver(keySet)
}

func (txService TxService) GetTransactionByHash(txHashStr string) (*jsonresult.TransactionDetail, *RPCError) {
	txHash, _ := common.Hash{}.NewHashFromStr(txHashStr)
	Logger.log.Infof("Get Transaction By Hash %+v", *txHash)

	shardID, blockHash, index, tx, err := txService.BlockChain.GetTransactionByHash(*txHash)
	if err != nil {
		// maybe tx is still in tx mempool -> check mempool
		tx, errM := txService.TxMemPool.GetTx(txHash)
		if errM != nil {
			return nil, NewRPCError(TxNotExistedInMemAndBLockError, errors.New("Tx is not existed in block or mempool"))
		}
		shardIDTemp := common.GetShardIDFromLastByte(tx.GetSenderAddrLastByte())
		result, errM := jsonresult.NewTransactionDetail(tx, nil, 0, 0, shardIDTemp)
		if errM != nil {
			return nil, NewRPCError(UnexpectedError, errM)
		}
		result.IsInMempool = true
		return result, nil
	}

	blockHeight, _, err := (*txService.DB).GetIndexOfBlock(blockHash)
	if err != nil {
		return nil, NewRPCError(UnexpectedError, err)
	}
	result, err := jsonresult.NewTransactionDetail(tx, &blockHash, blockHeight, index, shardID)
	if err != nil {
		return nil, NewRPCError(UnexpectedError, err)
	}
	result.IsInBlock = true
	Logger.log.Debugf("handleGetTransactionByHash result: %+v", result)
	return result, nil
}

func (txService TxService) SendRawCustomTokenTransaction(base58CheckData string) (wire.Message, *transaction.TxNormalToken, *RPCError) {
	rawTxBytes, _, err := base58.Base58Check{}.Decode(base58CheckData)
	if err != nil {
		Logger.log.Debugf("handleSendRawCustomTokenTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, NewRPCError(SendTxDataError, err)
	}

	tx := transaction.TxNormalToken{}
	err = json.Unmarshal(rawTxBytes, &tx)
	if err != nil {
		Logger.log.Debugf("handleSendRawCustomTokenTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, NewRPCError(SendTxDataError, err)
	}

	hash, _, err := txService.TxMemPool.MaybeAcceptTransaction(&tx)
	//httpServer.config.NetSync.HandleCacheTxHash(*tx.Hash())
	if err != nil {
		Logger.log.Debugf("handleSendRawCustomTokenTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, NewRPCError(SendTxDataError, err)
	}

	Logger.log.Debugf("New Custom Token Transaction: %s\n", hash.String())

	// broadcast message
	txMsg, err := wire.MakeEmptyMessage(wire.CmdCustomToken)
	if err != nil {
		Logger.log.Debugf("handleSendRawCustomTokenTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, NewRPCError(SendTxDataError, err)
	}

	txMsg.(*wire.MessageTxToken).Transaction = &tx

	return txMsg, &tx, nil
}

func (txService TxService) GetListCustomTokenHolders(tokenIDString string) (map[string]uint64, *RPCError) {
	tokenID, err := common.Hash{}.NewHashFromStr(tokenIDString)
	if err != nil {
		return nil, NewRPCError(RPCInvalidParamsError, errors.New("TokenID is invalid"))
	}
	result, err := txService.BlockChain.GetListTokenHolders(tokenID)
	if err != nil {
		return nil, NewRPCError(UnexpectedError, err)
	}

	return result, nil
}

func (txService TxService) GetListCustomTokenBalance(accountParam string) (jsonresult.ListCustomTokenBalance, error) {
	result := jsonresult.ListCustomTokenBalance{ListCustomTokenBalance: []jsonresult.CustomTokenBalance{}}
	account, err := wallet.Base58CheckDeserialize(accountParam)
	if err != nil {
		Logger.log.Debugf("handleGetListCustomTokenBalance result: %+v, err: %+v", nil, err)
		return jsonresult.ListCustomTokenBalance{}, nil
	}
	result.PaymentAddress = accountParam
	accountPaymentAddress := account.KeySet.PaymentAddress
	temps, err := txService.BlockChain.ListCustomToken()
	if err != nil {
		Logger.log.Debugf("handleGetListCustomTokenBalance result: %+v, err: %+v", nil, err)
		return jsonresult.ListCustomTokenBalance{}, err
	}
	for _, tx := range temps {
		item := jsonresult.CustomTokenBalance{}
		item.Name = tx.TxTokenData.PropertyName
		item.Symbol = tx.TxTokenData.PropertySymbol
		item.TokenID = tx.TxTokenData.PropertyID.String()
		item.TokenImage = common.Render([]byte(item.TokenID))
		tokenID := tx.TxTokenData.PropertyID
		res, err := txService.BlockChain.GetListTokenHolders(&tokenID)
		if err != nil {
			return jsonresult.ListCustomTokenBalance{}, err
		}
		paymentAddressInStr := base58.Base58Check{}.Encode(accountPaymentAddress.Bytes(), 0x00)
		item.Amount = res[paymentAddressInStr]
		if item.Amount == 0 {
			continue
		}
		result.ListCustomTokenBalance = append(result.ListCustomTokenBalance, item)
		result.PaymentAddress = account.Base58CheckSerialize(wallet.PaymentAddressType)
	}
	Logger.log.Debugf("handleGetListCustomTokenBalance result: %+v", result)

	return result, nil
}

func (txService TxService) GetListPrivacyCustomTokenBalance(privateKey string) (jsonresult.ListCustomTokenBalance, *RPCError) {
	result := jsonresult.ListCustomTokenBalance{ListCustomTokenBalance: []jsonresult.CustomTokenBalance{}}
	account, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		Logger.log.Debugf("handleGetListPrivacyCustomTokenBalance result: %+v, err: %+v", nil, err)
		return jsonresult.ListCustomTokenBalance{}, NewRPCError(UnexpectedError, err)
	}
	err = account.KeySet.InitFromPrivateKey(&account.KeySet.PrivateKey)
	if err != nil {
		Logger.log.Debugf("handleGetListPrivacyCustomTokenBalance result: %+v, err: %+v", nil, err)
		return jsonresult.ListCustomTokenBalance{}, NewRPCError(UnexpectedError, err)
	}

	result.PaymentAddress = account.Base58CheckSerialize(wallet.PaymentAddressType)
	temps, listCustomTokenCrossShard, err := txService.BlockChain.ListPrivacyCustomToken()
	if err != nil {
		Logger.log.Debugf("handleGetListPrivacyCustomTokenBalance result: %+v, err: %+v", nil, err)
		return jsonresult.ListCustomTokenBalance{}, NewRPCError(UnexpectedError, err)
	}
	tokenIDs := make(map[common.Hash]interface{})
	for tokenID, tx := range temps {
		tokenIDs[tokenID] = 0
		item := jsonresult.CustomTokenBalance{}
		item.Name = tx.TxPrivacyTokenData.PropertyName
		item.Symbol = tx.TxPrivacyTokenData.PropertySymbol
		item.TokenID = tx.TxPrivacyTokenData.PropertyID.String()
		item.TokenImage = common.Render([]byte(item.TokenID))
		tokenID := tx.TxPrivacyTokenData.PropertyID

		balance := uint64(0)
		// get balance for accountName in wallet
		lastByte := account.KeySet.PaymentAddress.Pk[len(account.KeySet.PaymentAddress.Pk)-1]
		shardIDSender := common.GetShardIDFromLastByte(lastByte)
		prvCoinID := &common.Hash{}
		err := prvCoinID.SetBytes(common.PRVCoinID[:])
		if err != nil {
			return jsonresult.ListCustomTokenBalance{}, NewRPCError(TokenIsInvalidError, err)
		}
		outcoints, err := txService.BlockChain.GetListOutputCoinsByKeyset(&account.KeySet, shardIDSender, &tokenID)
		if err != nil {
			Logger.log.Debugf("handleGetListPrivacyCustomTokenBalance result: %+v, err: %+v", nil, err)
			return jsonresult.ListCustomTokenBalance{}, NewRPCError(UnexpectedError, err)
		}
		for _, out := range outcoints {
			balance += out.CoinDetails.GetValue()
		}

		item.Amount = balance
		if item.Amount == 0 {
			continue
		}
		item.IsPrivacy = true
		result.ListCustomTokenBalance = append(result.ListCustomTokenBalance, item)
		result.PaymentAddress = account.Base58CheckSerialize(wallet.PaymentAddressType)
	}
	for tokenID, customTokenCrossShard := range listCustomTokenCrossShard {
		if _, ok := tokenIDs[tokenID]; ok {
			continue
		}
		item := jsonresult.CustomTokenBalance{}
		item.Name = customTokenCrossShard.PropertyName
		item.Symbol = customTokenCrossShard.PropertySymbol
		item.TokenID = customTokenCrossShard.TokenID.String()
		item.TokenImage = common.Render([]byte(item.TokenID))
		tokenID := customTokenCrossShard.TokenID

		balance := uint64(0)
		// get balance for accountName in wallet
		lastByte := account.KeySet.PaymentAddress.Pk[len(account.KeySet.PaymentAddress.Pk)-1]
		shardIDSender := common.GetShardIDFromLastByte(lastByte)
		prvCoinID := &common.Hash{}
		err := prvCoinID.SetBytes(common.PRVCoinID[:])
		if err != nil {
			return jsonresult.ListCustomTokenBalance{}, NewRPCError(TokenIsInvalidError, err)
		}
		outcoints, err := txService.BlockChain.GetListOutputCoinsByKeyset(&account.KeySet, shardIDSender, &tokenID)
		if err != nil {
			return jsonresult.ListCustomTokenBalance{}, NewRPCError(UnexpectedError, err)
		}
		for _, out := range outcoints {
			balance += out.CoinDetails.GetValue()
		}

		item.Amount = balance
		if item.Amount == 0 {
			continue
		}
		item.IsPrivacy = true
		result.ListCustomTokenBalance = append(result.ListCustomTokenBalance, item)
		result.PaymentAddress = account.Base58CheckSerialize(wallet.PaymentAddressType)
	}

	return result, nil
}

func (txService TxService) GetBalancePrivacyCustomToken(privateKey string, tokenID string) (uint64, *RPCError) {
	account, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		Logger.log.Debugf("handleGetBalancePrivacyCustomToken result: %+v, err: %+v", nil, err)
		return uint64(0), NewRPCError(UnexpectedError, err)
	}
	err = account.KeySet.InitFromPrivateKey(&account.KeySet.PrivateKey)
	if err != nil {
		Logger.log.Debugf("handleGetBalancePrivacyCustomToken result: %+v, err: %+v", nil, err)
		return uint64(0), NewRPCError(UnexpectedError, err)
	}

	temps, listCustomTokenCrossShard, err := txService.BlockChain.ListPrivacyCustomToken()
	if err != nil {
		Logger.log.Debugf("handleGetListPrivacyCustomTokenBalance result: %+v, err: %+v", nil, err)
		return uint64(0), NewRPCError(UnexpectedError, err)
	}
	totalValue := uint64(0)
	for tempTokenID := range temps {
		if tokenID == tempTokenID.String() {
			lastByte := account.KeySet.PaymentAddress.Pk[len(account.KeySet.PaymentAddress.Pk)-1]
			shardIDSender := common.GetShardIDFromLastByte(lastByte)
			outcoints, err := txService.BlockChain.GetListOutputCoinsByKeyset(&account.KeySet, shardIDSender, &tempTokenID)
			if err != nil {
				Logger.log.Debugf("handleGetBalancePrivacyCustomToken result: %+v, err: %+v", nil, err)
				return uint64(0), NewRPCError(UnexpectedError, err)
			}
			for _, out := range outcoints {
				totalValue += out.CoinDetails.GetValue()
			}
		}
	}
	for tempTokenID := range listCustomTokenCrossShard {
		if tokenID == tempTokenID.String() {
			lastByte := account.KeySet.PaymentAddress.Pk[len(account.KeySet.PaymentAddress.Pk)-1]
			shardIDSender := common.GetShardIDFromLastByte(lastByte)
			outcoints, err := txService.BlockChain.GetListOutputCoinsByKeyset(&account.KeySet, shardIDSender, &tempTokenID)
			if err != nil {
				Logger.log.Debugf("handleGetBalancePrivacyCustomToken result: %+v, err: %+v", nil, err)
				return uint64(0), NewRPCError(UnexpectedError, err)
			}
			for _, out := range outcoints {
				totalValue += out.CoinDetails.GetValue()
			}
		}
	}

	return totalValue, nil
}

func (txService TxService) CustomTokenDetail(tokenIDStr string) ([]common.Hash, error) {
	tokenID, err := common.Hash{}.NewHashFromStr(tokenIDStr)
	if err != nil {
		Logger.log.Debugf("handleCustomTokenDetail result: %+v, err: %+v", nil, err)
		return nil, err
	}
	txs, _ := txService.BlockChain.GetCustomTokenTxsHash(tokenID)
	return txs, nil
}

func (txService TxService) PrivacyCustomTokenDetail(tokenIDStr string) ([]common.Hash, error) {
	tokenID, err := common.Hash{}.NewHashFromStr(tokenIDStr)
	if err != nil {
		Logger.log.Debugf("handlePrivacyCustomTokenDetail result: %+v, err: %+v", nil, err)
		return nil, err
	}
	txs, _ := txService.BlockChain.GetPrivacyCustomTokenTxsHash(tokenID)
	return txs, nil
}

func (txService TxService) ListUnspentCustomToken(senderKeyParam string, tokenIDParam string) ([]transaction.TxTokenVout, error) {
	senderKey, err := wallet.Base58CheckDeserialize(senderKeyParam)
	if err != nil {
		Logger.log.Debugf("handleListUnspentCustomToken result: %+v, err: %+v", nil, err)
		return nil, err
	}
	senderKeyset := senderKey.KeySet

	tokenID, _ := common.Hash{}.NewHashFromStr(tokenIDParam)

	unspentTxTokenOuts, err := txService.BlockChain.GetUnspentTxCustomTokenVout(senderKeyset, tokenID)
	if err != nil {
		Logger.log.Debugf("handleListUnspentCustomToken result: %+v, err: %+v", nil, err)
		return nil, err
	}

	return unspentTxTokenOuts, nil
}

func (txService TxService) GetBalanceCustomToken(senderKeyParam string, tokenIDParam string) (uint64, error) {
	senderKey, err := wallet.Base58CheckDeserialize(senderKeyParam)
	if err != nil {
		Logger.log.Debugf("handleGetBalanceCustomToken result: %+v, err: %+v", nil, err)
		return uint64(0), err
	}
	senderKeyset := senderKey.KeySet

	tokenID, _ := common.Hash{}.NewHashFromStr(tokenIDParam)
	unspentTxTokenOuts, err := txService.BlockChain.GetUnspentTxCustomTokenVout(senderKeyset, tokenID)

	if err != nil {
		Logger.log.Debugf("handleGetBalanceCustomToken result: %+v, err: %+v", nil, err)
		return uint64(0), NewRPCError(UnexpectedError, err)
	}
	totalValue := uint64(0)
	for _, temp := range unspentTxTokenOuts {
		totalValue += temp.Value
	}

	return totalValue, nil
}

func (txService TxService) CreateSignatureOnCustomTokenTx(base58CheckDate string, senderKeyParam string) (string, error) {
	rawTxBytes, _, err := base58.Base58Check{}.Decode(base58CheckDate)

	if err != nil {
		return "", err
	}
	tx := transaction.TxNormalToken{}
	err = json.Unmarshal(rawTxBytes, &tx)
	if err != nil {
		return "", err
	}

	keySet, _, err := GetKeySetFromPrivateKeyParams(senderKeyParam)
	if err != nil {
		Logger.log.Debugf("handleCreateSignatureOnCustomTokenTx result: %+v, err: %+v", nil, err)
		return "", err
	}

	jsSignByteArray, err := tx.GetTxCustomTokenSignature(*keySet)
	if err != nil {
		Logger.log.Debugf("handleCreateSignatureOnCustomTokenTx result: %+v, err: %+v", nil, err)
		return "", errors.New("failed to sign the custom token")
	}
	result := hex.EncodeToString(jsSignByteArray)

	return result, nil
}

func (txService TxService) RandomCommitments(paymentAddressStr string, outputs []interface{}, tokenID *common.Hash) ([]uint64, []uint64, [][]byte, *RPCError) {
	_, shardIDSender, err := GetKeySetFromPaymentAddressParam(paymentAddressStr)
	if err != nil {
		Logger.log.Debugf("handleRandomCommitments result: %+v, err: %+v", nil, err)
		return nil, nil, nil, NewRPCError(UnexpectedError, err)
	}

	usableOutputCoins := []*privacy.OutputCoin{}
	for _, item := range outputs {
		out, err1 := jsonresult.NewOutcoinFromInterface(item)
		if err1 != nil {
			return nil, nil, nil, NewRPCError(RPCInvalidParamsError, errors.New(fmt.Sprint("outputs is invalid", out)))
		}
		temp := big.Int{}
		temp.SetString(out.Value, 10)
		coin := &privacy.Coin{}
		coin.SetValue(temp.Uint64())
		i := &privacy.OutputCoin{
			CoinDetails: coin,
		}
		RandomnessInBytes, _, _ := base58.Base58Check{}.Decode(out.Randomness)
		i.CoinDetails.SetRandomness(new(big.Int).SetBytes(RandomnessInBytes))

		SNDerivatorInBytes, _, _ := base58.Base58Check{}.Decode(out.SNDerivator)
		i.CoinDetails.SetSNDerivator(new(big.Int).SetBytes(SNDerivatorInBytes))

		CoinCommitmentBytes, _, _ := base58.Base58Check{}.Decode(out.CoinCommitment)
		CoinCommitment := &privacy.EllipticPoint{}
		_ = CoinCommitment.Decompress(CoinCommitmentBytes)
		i.CoinDetails.SetCoinCommitment(CoinCommitment)

		PublicKeyBytes, _, _ := base58.Base58Check{}.Decode(out.PublicKey)
		PublicKey := &privacy.EllipticPoint{}
		_ = PublicKey.Decompress(PublicKeyBytes)
		i.CoinDetails.SetPublicKey(PublicKey)

		InfoBytes, _, _ := base58.Base58Check{}.Decode(out.Info)
		i.CoinDetails.SetInfo(InfoBytes)

		usableOutputCoins = append(usableOutputCoins, i)
	}
	usableInputCoins := transaction.ConvertOutputCoinToInputCoin(usableOutputCoins)

	commitmentIndexs, myCommitmentIndexs, commitments := txService.BlockChain.RandomCommitmentsProcess(usableInputCoins, 0, shardIDSender, tokenID)
	return commitmentIndexs, myCommitmentIndexs, commitments, nil
}

func (txService TxService) SendRawPrivacyCustomTokenTransaction(base58CheckData string) (wire.Message, *transaction.TxCustomTokenPrivacy, error) {
	rawTxBytes, _, err := base58.Base58Check{}.Decode(base58CheckData)
	if err != nil {
		Logger.log.Debugf("handleSendRawPrivacyCustomTokenTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, err
	}

	tx := transaction.TxCustomTokenPrivacy{}
	err = json.Unmarshal(rawTxBytes, &tx)
	if err != nil {
		Logger.log.Debugf("handleSendRawPrivacyCustomTokenTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, err
	}

	hash, _, err := txService.TxMemPool.MaybeAcceptTransaction(&tx)
	//httpServer.config.NetSync.HandleCacheTxHash(*tx.Hash())
	if err != nil {
		Logger.log.Debugf("handleSendRawPrivacyCustomTokenTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, err
	}

	Logger.log.Debugf("there is hash of transaction: %s\n", hash.String())

	txMsg, err := wire.MakeEmptyMessage(wire.CmdPrivacyCustomToken)
	if err != nil {
		Logger.log.Debugf("handleSendRawPrivacyCustomTokenTransaction result: %+v, err: %+v", nil, err)
		return nil, nil, err
	}

	txMsg.(*wire.MessageTxPrivacyToken).Transaction = &tx

	return txMsg, &tx, nil
}

func (txService TxService) BuildRawDefragmentAccountTransaction(params interface{}, meta metadata.Metadata) (*transaction.Tx, *RPCError) {
	arrayParams := common.InterfaceSlice(params)
	if len(arrayParams) < 4 {
		return nil, NewRPCError(RPCInvalidParamsError, nil)
	}
	senderKeyParam, ok := arrayParams[0].(string)
	if !ok {
		return nil, NewRPCError(RPCInvalidParamsError, errors.New("senderKeyParam is invalid"))
	}
	maxValTemp, ok := arrayParams[1].(float64)
	if !ok {
		return nil, NewRPCError(RPCInvalidParamsError, errors.New("maxVal is invalid"))
	}
	maxVal := uint64(maxValTemp)
	estimateFeeCoinPerKbtemp, ok := arrayParams[2].(float64)
	if !ok {
		return nil, NewRPCError(RPCInvalidParamsError, errors.New("estimateFeeCoinPerKb is invalid"))
	}
	estimateFeeCoinPerKb := int64(estimateFeeCoinPerKbtemp)
	// param #4: hasPrivacyCoin flag: 1 or -1
	hasPrivacyCoin := int(arrayParams[3].(float64)) > 0
	/********* END Fetch all component to *******/

	// param #1: private key of sender
	senderKeySet, shardIDSender, err := GetKeySetFromPrivateKeyParams(senderKeyParam)
	if err != nil {
		return nil, NewRPCError(InvalidSenderPrivateKeyError, err)
	}

	prvCoinID := &common.Hash{}
	err1 := prvCoinID.SetBytes(common.PRVCoinID[:])
	if err1 != nil {
		return nil, NewRPCError(TokenIsInvalidError, err1)
	}
	outCoins, err := txService.BlockChain.GetListOutputCoinsByKeyset(senderKeySet, shardIDSender, prvCoinID)
	if err != nil {
		return nil, NewRPCError(GetOutputCoinError, err)
	}
	// remove out coin in mem pool
	outCoins, err = txService.filterMemPoolOutcoinsToSpent(outCoins)
	if err != nil {
		return nil, NewRPCError(GetOutputCoinError, err)
	}
	outCoins, amount := txService.calculateOutputCoinsByMinValue(outCoins, maxVal)
	if len(outCoins) == 0 {
		return nil, NewRPCError(GetOutputCoinError, nil)
	}
	paymentInfo := &privacy.PaymentInfo{
		Amount:         uint64(amount),
		PaymentAddress: senderKeySet.PaymentAddress,
	}
	paymentInfos := []*privacy.PaymentInfo{paymentInfo}
	// check real fee(nano PRV) per tx
	realFee, _, _ := txService.EstimateFee(estimateFeeCoinPerKb, outCoins, paymentInfos, shardIDSender, 8, hasPrivacyCoin, nil, nil, nil)
	if len(outCoins) == 0 {
		realFee = 0
	}

	if uint64(amount) < realFee {
		return nil, NewRPCError(GetOutputCoinError, err)
	}
	paymentInfo.Amount = uint64(amount) - realFee

	inputCoins := transaction.ConvertOutputCoinToInputCoin(outCoins)

	/******* END GET output native coins(PRV), which is used to create tx *****/
	// START create tx
	// missing flag for privacy
	// false by default
	tx := transaction.Tx{}
	err = tx.Init(
		transaction.NewTxPrivacyInitParams(&senderKeySet.PrivateKey,
			paymentInfos,
			inputCoins,
			realFee,
			hasPrivacyCoin,
			*txService.DB,
			nil, // use for prv coin -> nil is valid
			meta, nil))
	// END create tx

	if err != nil {
		return nil, NewRPCError(CreateTxDataError, err)
	}

	return &tx, nil
}

//calculateOutputCoinsByMinValue
func (txService TxService) calculateOutputCoinsByMinValue(outCoins []*privacy.OutputCoin, maxVal uint64) ([]*privacy.OutputCoin, uint64) {
	outCoinsTmp := make([]*privacy.OutputCoin, 0)
	amount := uint64(0)
	for _, outCoin := range outCoins {
		if outCoin.CoinDetails.GetValue() <= maxVal {
			outCoinsTmp = append(outCoinsTmp, outCoin)
			amount += outCoin.CoinDetails.GetValue()
		}
	}
	return outCoinsTmp, amount
}

func (txService TxService) SendRawTxWithMetadata(base58CheckDate string) (wire.Message, *common.Hash, *RPCError) {
	rawTxBytes, _, err := base58.Base58Check{}.Decode(base58CheckDate)
	if err != nil {
		return nil, nil, NewRPCError(RPCInvalidParamsError, err)
	}

	tx := transaction.Tx{}
	err = json.Unmarshal(rawTxBytes, &tx)
	if err != nil {
		return nil, nil, NewRPCError(JsonError, err)
	}

	hash, _, err := txService.TxMemPool.MaybeAcceptTransaction(&tx)
	if err != nil {
		return nil, nil, NewRPCError(TxPoolRejectTxError, err)
	}

	Logger.log.Debugf("there is hash of transaction: %s\n", hash.String())

	// broadcast message
	txMsg, err := wire.MakeEmptyMessage(wire.CmdTx)
	if err != nil {
		return nil, nil, NewRPCError(UnexpectedError, err)
	}

	txMsg.(*wire.MessageTx).Transaction = &tx

	return txMsg, hash, nil
}

func (txService TxService) SendRawCustomTokenTxWithMetadata(base58CheckDate string) (wire.Message, *common.Hash, *RPCError) {
	rawTxBytes, _, err := base58.Base58Check{}.Decode(base58CheckDate)
	if err != nil {
		return nil, nil, NewRPCError(RPCInvalidParamsError, err)
	}

	tx := transaction.TxNormalToken{}
	err = json.Unmarshal(rawTxBytes, &tx)
	fmt.Printf("%+v\n", tx)
	if err != nil {
		return nil, nil, NewRPCError(JsonError, err)
	}

	hash, _, err := txService.TxMemPool.MaybeAcceptTransaction(&tx)
	if err != nil {
		return nil, nil, NewRPCError(TxPoolRejectTxError, err)
	}

	Logger.log.Debugf("there is hash of transaction: %s\n", hash.String())

	// broadcast message
	txMsg, err := wire.MakeEmptyMessage(wire.CmdCustomToken)
	if err != nil {
		return nil, nil, NewRPCError(UnexpectedError, err)
	}

	txMsg.(*wire.MessageTxToken).Transaction = &tx

	return txMsg, hash, nil
}