package rpcserver

import (
	"errors"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/rpcserver/rpcservice"
)

func (httpServer *HttpServer) handleGetBalanceFinalized(params interface{}, closeChan <-chan struct{}) (interface{}, *rpcservice.RPCError) {
	if httpServer.config.Wallet == nil {
		return uint64(0), rpcservice.NewRPCError(rpcservice.UnexpectedError, errors.New("wallet is not existed"))
	}
	if len(httpServer.config.Wallet.MasterAccount.Child) == 0 {
		return uint64(0), rpcservice.NewRPCError(rpcservice.UnexpectedError, errors.New("no account is existed"))
	}

	// convert component to array
	arrayParams := common.InterfaceSlice(params)
	if arrayParams == nil || len(arrayParams) < 3 {
		return uint64(0), rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array at least 3 elements"))
	}
	// Param #1: account "*" for all or a particular account
	accountName, ok := arrayParams[0].(string)
	if !ok {
		return uint64(0), rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("accountName is invalid"))
	}

	// Param #2: the minimum number of confirmations an output must have
	_, ok = arrayParams[1].(float64) //min
	if !ok {
		return uint64(0), rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("min is invalid"))
	}

	// Param #3: passphrase to access local wallet of node
	passPhrase, ok := arrayParams[2].(string)
	if !ok {
		return uint64(0), rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("passPhrase is invalid"))
	}

	if passPhrase != httpServer.config.Wallet.PassPhrase {
		return uint64(0), rpcservice.NewRPCError(rpcservice.UnexpectedError, errors.New("password phrase is wrong for local wallet"))
	}

	return httpServer.walletService.GetBalanceFinalized(accountName)
}

func (httpServer *HttpServer) handleGetBalanceByPrivatekeyFinalized(params interface{}, closeChan <-chan struct{}) (interface{}, *rpcservice.RPCError) {
	// all component
	arrayParams := common.InterfaceSlice(params)
	if arrayParams == nil || len(arrayParams) != 1 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array at least 1 element"))
	}
	// param #1: private key of sender
	senderKeyParam, ok := arrayParams[0].(string)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("invalid private key"))
	}

	return httpServer.walletService.GetBalanceByPrivateKeyFinalized(senderKeyParam)
}

func (httpServer *HttpServer) handleGetBalanceByPaymentAddressFinalized(params interface{}, closeChan <-chan struct{}) (interface{}, *rpcservice.RPCError) {
	// all component
	arrayParams := common.InterfaceSlice(params)
	if arrayParams == nil || len(arrayParams) != 1 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array at least 1 element"))
	}
	// param #1: private key of sender
	paymentAddressParam, ok := arrayParams[0].(string)
	if !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("payment address is invalid"))
	}

	return httpServer.walletService.GetBalanceByPaymentAddressFinalized(paymentAddressParam)
}

func (httpServer *HttpServer) handleGetBalancePrivacyCustomTokenFinalized(params interface{}, closeChan <-chan struct{}) (interface{}, *rpcservice.RPCError) {
	arrayParams := common.InterfaceSlice(params)
	if arrayParams == nil || len(arrayParams) < 2 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array at least 2 elements"))
	}

	privateKey, ok := arrayParams[0].(string)
	if len(privateKey) == 0 || !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("private key is invalid"))
	}

	tokenID, ok := arrayParams[1].(string)
	if len(tokenID) == 0 || !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("tokenID is invalid"))
	}

	totalValue, err2 := httpServer.txService.GetBalancePrivacyCustomTokenFinalized(privateKey, tokenID)
	if err2 != nil {
		return nil, err2
	}
	return totalValue, nil
}

func (httpServer *HttpServer) handleGetListPrivacyCustomTokenBalanceFinalized(params interface{}, closeChan <-chan struct{}) (interface{}, *rpcservice.RPCError) {

	arrayParams := common.InterfaceSlice(params)
	if arrayParams == nil || len(arrayParams) < 1 {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("param must be an array at least 1 element"))
	}

	privateKey, ok := arrayParams[0].(string)
	if len(privateKey) == 0 || !ok {
		return nil, rpcservice.NewRPCError(rpcservice.RPCInvalidParamsError, errors.New("Param is invalid"))
	}

	result, err := httpServer.txService.GetListPrivacyCustomTokenBalanceFinalized(privateKey)
	if err != nil {
		return nil, err
	}
	return result, nil
}
