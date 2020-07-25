package syncker

import "go.uber.org/zap"

var logger *zap.SugaredLogger // General logger package chain

func InitLogger(baseLogger *zap.SugaredLogger) {
	// Init package's logger here with distinct name here
	logger = baseLogger.Named("Syncker log")
}

type DummyIdentifier struct {
	uuid string
}

func (dI *DummyIdentifier) SetUUID(uuid string) {
	dI.uuid = uuid
}

func (dI *DummyIdentifier) GetUUID() string {
	return dI.uuid
}
