package netsync

import (
	"github.com/incognitochain/incognito-chain/common"
	"go.uber.org/zap"
)

type NetSyncLogger struct {
	log common.Logger
}

func (netSyncLogger *NetSyncLogger) Init(inst common.Logger) {
	netSyncLogger.log = inst
}

// Global instant to use
var Logger = NetSyncLogger{}

var logger *zap.SugaredLogger // General logger package chain

func InitLogger(baseLogger *zap.SugaredLogger) {
	// Init package's logger here with distinct name here
	logger = baseLogger.Named("Peerv2 log")
}
