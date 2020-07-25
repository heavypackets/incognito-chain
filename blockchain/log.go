package blockchain

import (
	"github.com/incognitochain/incognito-chain/common"
	"go.uber.org/zap"
)

type BlockChainLogger struct {
	log common.Logger
}

func (self *BlockChainLogger) Init(inst common.Logger) {
	self.log = inst
}

type DeBridgeLogger struct {
	log common.Logger
}

func (self *DeBridgeLogger) Init(inst common.Logger) {
	self.log = inst
}

// Global instant to use
var Logger = BlockChainLogger{}
var BLogger = DeBridgeLogger{}

var logger *zap.SugaredLogger // General logger package chain

func InitLogger(baseLogger *zap.SugaredLogger) {
	// Init package's logger here with distinct name here
	logger = baseLogger.Named("Blockchain log")
}
