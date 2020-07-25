package proto

func (req *GetBlockShardByHashRequest) SetUUID(uuid string) {
	req.UUID = uuid
}

func (req *GetBlockBeaconByHashRequest) SetUUID(uuid string) {
	req.UUID = uuid
}

func (req *GetBlockCrossShardByHashRequest) SetUUID(uuid string) {
	req.UUID = uuid
}

func (req *BlockByHeightRequest) SetUUID(uuid string) {
	req.UUID = uuid
}

func (req *BlockByHashRequest) SetUUID(uuid string) {
	req.UUID = uuid
}
