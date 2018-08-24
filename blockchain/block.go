package blockchain

import (
	"github.com/ninjadotorg/cash-prototype/transaction"
	"github.com/ninjadotorg/cash-prototype/common"
	"strconv"
	"encoding/json"
	"github.com/pkg/errors"
)

const (
	// Default length of list tx in block
	defaultTransactionAlloc = 2048
)

type Block struct {
	Header       BlockHeader
	Transactions []transaction.Transaction
	blockHash    *common.Hash
}

/**
Customer UnmarshalJSON to parse list Tx
 */
func (self *Block) UnmarshalJSON(data []byte) (error) {
	type Alias Block
	temp := &struct {
		Transactions []map[string]interface{}
		*Alias
	}{
		Alias: (*Alias)(self),
	}

	err := json.Unmarshal(data, &temp)
	if err != nil {
		return err
	}

	// process tx from tx interface of temp
	for _, txTemp := range temp.Transactions {
		if txTemp["Type"].(string) == common.TxNormalType {
			// init a tx
			txNormal := &transaction.Tx{
				Version:  int(txTemp["Version"].(float64)),
				Type:     txTemp["Type"].(string),
				LockTime: int(txTemp["LockTime"].(float64)),
			}
			// process for txin
			txTempTxIn := txTemp["TxIn"].([]map[string]interface{})
			txIn := make([]transaction.TxIn, 0)
			for _, v := range txTempTxIn {
				tempOutPoint := v["OutPoint"].(map[string]interface{})
				preHash, _ := common.Hash{}.NewHashFromStr(tempOutPoint["Hash"].(string))
				pOutPoint := transaction.OutPoint{
					Hash: *preHash,
					Vout: int(tempOutPoint["Vout"].(float64)),
				}
				t := transaction.TxIn{
					Sequence:         int(v["Sequence"].(float64)),
					SignatureScript:  []byte(v["SignatureScript"].(string)),
					PreviousOutPoint: pOutPoint,
				}
				txIn = append(txIn, t)
			}
			txNormal.TxIn = txIn

			// process for txout
			txTempTxOut := txTemp["TxOut"].([]map[string]interface{})
			txOut := make([]transaction.TxOut, 0)
			for _, v := range txTempTxOut {
				t := transaction.TxOut{
					TxOutType: v["TxOutType"].(string),
					Value:     v["Value"].(float64),
					PkScript:  []byte(v["PkScript"].(string)),
				}
				txOut = append(txOut, t)
			}
			txNormal.TxOut = txOut

			self.Transactions = append(self.Transactions, txNormal)
		} else if txTemp["Type"].(string) == common.TxActionParamsType {
			// init a tx
			param := transaction.Param{
				Tax:               txTemp["Tax"].(float64),
				AgentID:           txTemp["AgentID"].(string),
				NumOfIssuingBonds: int(txTemp["NumOfIssuingBonds"].(float64)),
				NumOfIssuingCoins: int(txTemp["NumOfIssuingCoins"].(float64)),
			}
			txAction := transaction.ActionParamTx{
				LockTime: int64(txTemp["LockTime"].(float64)),
				Type:     txTemp["Type"].(string),
				Version:  int(txTemp["Version"].(float64)),
				Param:    &param,
			}
			self.Transactions = append(self.Transactions, &txAction)
		} else {
			return errors.New("Can not parse a wrong tx")
		}
	}

	self.Header = temp.Alias.Header
	return nil
}

func (self *Block) AddTransaction(tx transaction.Transaction) error {
	self.Transactions = append(self.Transactions, tx)
	return nil
}

func (self *Block) ClearTransactions() {
	self.Transactions = make([]transaction.Transaction, 0, defaultTransactionAlloc)
}

func (self *Block) Hash() (*common.Hash) {
	//if self.blockHash != nil {
	//	return self.blockHash
	//}
	record := strconv.Itoa(self.Header.Version) + self.Header.MerkleRoot.String() + self.Header.Timestamp.String() + self.Header.PrevBlockHash.String() + strconv.Itoa(self.Header.Nonce) + strconv.Itoa(len(self.Transactions))
	hash := common.DoubleHashH([]byte(record))
	//self.blockHash = &hash
	//return self.blockHash
	return &hash
}
