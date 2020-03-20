package zkp

import (
	"errors"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/privacy/coin"
	errhandler "github.com/incognitochain/incognito-chain/privacy/errorhandler"
	"github.com/incognitochain/incognito-chain/privacy/operation"
	"github.com/incognitochain/incognito-chain/privacy/privacy_util"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v1/zeroknowledge/aggregatedrange"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v1/zeroknowledge/oneoutofmany"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v1/zeroknowledge/serialnumbernoprivacy"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v1/zeroknowledge/serialnumberprivacy"
)

// PaymentWitness contains all of witness for proving when spending coins
type PaymentWitness struct {
	privateKey          *operation.Scalar
	inputCoins          []*coin.InputCoin
	outputCoins         []*coin.OutputCoin
	commitmentIndices   []uint64
	myCommitmentIndices []uint64

	oneOfManyWitness             []*oneoutofmany.OneOutOfManyWitness
	serialNumberWitness          []*serialnumberprivacy.SNPrivacyWitness
	serialNumberNoPrivacyWitness []*serialnumbernoprivacy.SNNoPrivacyWitness

	aggregatedRangeWitness *aggregatedrange.AggregatedRangeWitness

	comOutputValue                 []*operation.Point
	comOutputSerialNumberDerivator []*operation.Point
	comOutputShardID               []*operation.Point

	comInputSecretKey             *operation.Point
	comInputValue                 []*operation.Point
	comInputSerialNumberDerivator []*operation.Point
	comInputShardID               *operation.Point

	randSecretKey *operation.Scalar
}

func (paymentWitness PaymentWitness) GetRandSecretKey() *operation.Scalar {
	return paymentWitness.randSecretKey
}

type PaymentWitnessParam struct {
	HasPrivacy              bool
	PrivateKey              *operation.Scalar
	InputCoins              []*coin.InputCoin
	OutputCoins             []*coin.OutputCoin
	PublicKeyLastByteSender byte
	Commitments             []*operation.Point
	CommitmentIndices       []uint64
	MyCommitmentIndices     []uint64
	Fee                     uint64
}

// Build prepares witnesses for all protocol need to be proved when create tx
// if hashPrivacy = false, witness includes spending key, input coins, output coins
// otherwise, witness includes all attributes in PaymentWitness struct
func (wit *PaymentWitness) Init(PaymentWitnessParam PaymentWitnessParam) *errhandler.PrivacyError {

	hasPrivacy := PaymentWitnessParam.HasPrivacy
	privateKey := PaymentWitnessParam.PrivateKey
	inputCoins := PaymentWitnessParam.InputCoins
	outputCoins := PaymentWitnessParam.OutputCoins
	publicKeyLastByteSender := PaymentWitnessParam.PublicKeyLastByteSender
	commitments := PaymentWitnessParam.Commitments
	commitmentIndices := PaymentWitnessParam.CommitmentIndices
	myCommitmentIndices := PaymentWitnessParam.MyCommitmentIndices
	_ = PaymentWitnessParam.Fee

	if !hasPrivacy {
		for _, outCoin := range outputCoins {
			outCoin.CoinDetails.SetRandomness(operation.RandomScalar())
			err := outCoin.CoinDetails.CommitAll()
			if err != nil {
				return errhandler.NewPrivacyErr(errhandler.CommitNewOutputCoinNoPrivacyErr, nil)
			}
		}
		wit.privateKey = privateKey
		wit.inputCoins = inputCoins
		wit.outputCoins = outputCoins

		if len(inputCoins) > 0 {
			publicKey := inputCoins[0].CoinDetails.GetPublicKey()

			wit.serialNumberNoPrivacyWitness = make([]*serialnumbernoprivacy.SNNoPrivacyWitness, len(inputCoins))
			for i := 0; i < len(inputCoins); i++ {
				/***** Build witness for proving that serial number is derived from the committed derivator *****/
				if wit.serialNumberNoPrivacyWitness[i] == nil {
					wit.serialNumberNoPrivacyWitness[i] = new(serialnumbernoprivacy.SNNoPrivacyWitness)
				}
				wit.serialNumberNoPrivacyWitness[i].Set(inputCoins[i].CoinDetails.GetSerialNumber(), publicKey, inputCoins[i].CoinDetails.GetSNDerivator(), wit.privateKey)
			}
		}

		return nil
	}

	wit.privateKey = privateKey
	wit.inputCoins = inputCoins
	wit.outputCoins = outputCoins
	wit.commitmentIndices = commitmentIndices
	wit.myCommitmentIndices = myCommitmentIndices

	numInputCoin := len(wit.inputCoins)
	numOutputCoin := len(wit.outputCoins)

	randInputSK := operation.RandomScalar()
	// set rand sk for Schnorr signature
	wit.randSecretKey = new(operation.Scalar).Set(randInputSK)

	cmInputSK := operation.PedCom.CommitAtIndex(wit.privateKey, randInputSK, operation.PedersenPrivateKeyIndex)
	wit.comInputSecretKey = new(operation.Point).Set(cmInputSK)

	randInputShardID := operation.RandomScalar()
	senderShardID := common.GetShardIDFromLastByte(publicKeyLastByteSender)
	wit.comInputShardID = operation.PedCom.CommitAtIndex(new(operation.Scalar).FromUint64(uint64(senderShardID)), randInputShardID, operation.PedersenShardIDIndex)

	wit.comInputValue = make([]*operation.Point, numInputCoin)
	wit.comInputSerialNumberDerivator = make([]*operation.Point, numInputCoin)
	// It is used for proving 2 commitments commit to the same value (input)
	//cmInputSNDIndexSK := make([]*operation.Point, numInputCoin)

	randInputValue := make([]*operation.Scalar, numInputCoin)
	randInputSND := make([]*operation.Scalar, numInputCoin)
	//randInputSNDIndexSK := make([]*big.Int, numInputCoin)

	// cmInputValueAll is sum of all input coins' value commitments
	cmInputValueAll := new(operation.Point).Identity()
	randInputValueAll := new(operation.Scalar).FromUint64(0)

	// Summing all commitments of each input coin into one commitment and proving the knowledge of its Openings
	cmInputSum := make([]*operation.Point, numInputCoin)
	randInputSum := make([]*operation.Scalar, numInputCoin)
	// randInputSumAll is sum of all randomess of coin commitments
	randInputSumAll := new(operation.Scalar).FromUint64(0)

	wit.oneOfManyWitness = make([]*oneoutofmany.OneOutOfManyWitness, numInputCoin)
	wit.serialNumberWitness = make([]*serialnumberprivacy.SNPrivacyWitness, numInputCoin)

	commitmentTemps := make([][]*operation.Point, numInputCoin)
	randInputIsZero := make([]*operation.Scalar, numInputCoin)

	preIndex := 0

	for i, inputCoin := range wit.inputCoins {
		// tx only has fee, no output, Rand_Value_Input = 0
		if numOutputCoin == 0 {
			randInputValue[i] = new(operation.Scalar).FromUint64(0)
		} else {
			randInputValue[i] = operation.RandomScalar()
		}
		// commit each component of coin commitment
		randInputSND[i] = operation.RandomScalar()

		wit.comInputValue[i] = operation.PedCom.CommitAtIndex(new(operation.Scalar).FromUint64(inputCoin.CoinDetails.GetValue()), randInputValue[i], operation.PedersenValueIndex)
		wit.comInputSerialNumberDerivator[i] = operation.PedCom.CommitAtIndex(inputCoin.CoinDetails.GetSNDerivator(), randInputSND[i], operation.PedersenSndIndex)

		cmInputValueAll.Add(cmInputValueAll, wit.comInputValue[i])
		randInputValueAll.Add(randInputValueAll, randInputValue[i])

		/***** Build witness for proving one-out-of-N commitments is a commitment to the coins being spent *****/
		cmInputSum[i] = new(operation.Point).Add(cmInputSK, wit.comInputValue[i])
		cmInputSum[i].Add(cmInputSum[i], wit.comInputSerialNumberDerivator[i])
		cmInputSum[i].Add(cmInputSum[i], wit.comInputShardID)

		randInputSum[i] = new(operation.Scalar).Set(randInputSK)
		randInputSum[i].Add(randInputSum[i], randInputValue[i])
		randInputSum[i].Add(randInputSum[i], randInputSND[i])
		randInputSum[i].Add(randInputSum[i], randInputShardID)

		randInputSumAll.Add(randInputSumAll, randInputSum[i])

		// commitmentTemps is a list of commitments for protocol one-out-of-N
		commitmentTemps[i] = make([]*operation.Point, privacy_util.CommitmentRingSize)

		randInputIsZero[i] = new(operation.Scalar).FromUint64(0)
		randInputIsZero[i].Sub(inputCoin.CoinDetails.GetRandomness(), randInputSum[i])

		for j := 0; j < privacy_util.CommitmentRingSize; j++ {
			commitmentTemps[i][j] = new(operation.Point).Sub(commitments[preIndex+j], cmInputSum[i])
		}

		if wit.oneOfManyWitness[i] == nil {
			wit.oneOfManyWitness[i] = new(oneoutofmany.OneOutOfManyWitness)
		}
		indexIsZero := myCommitmentIndices[i] % privacy_util.CommitmentRingSize

		wit.oneOfManyWitness[i].Set(commitmentTemps[i], randInputIsZero[i], indexIsZero)
		preIndex = privacy_util.CommitmentRingSize * (i + 1)
		// ---------------------------------------------------

		/***** Build witness for proving that serial number is derived from the committed derivator *****/
		if wit.serialNumberWitness[i] == nil {
			wit.serialNumberWitness[i] = new(serialnumberprivacy.SNPrivacyWitness)
		}
		stmt := new(serialnumberprivacy.SerialNumberPrivacyStatement)
		stmt.Set(inputCoin.CoinDetails.GetSerialNumber(), cmInputSK, wit.comInputSerialNumberDerivator[i])
		wit.serialNumberWitness[i].Set(stmt, privateKey, randInputSK, inputCoin.CoinDetails.GetSNDerivator(), randInputSND[i])
		// ---------------------------------------------------
	}

	randOutputValue := make([]*operation.Scalar, numOutputCoin)
	randOutputSND := make([]*operation.Scalar, numOutputCoin)
	cmOutputValue := make([]*operation.Point, numOutputCoin)
	cmOutputSND := make([]*operation.Point, numOutputCoin)

	cmOutputSum := make([]*operation.Point, numOutputCoin)
	randOutputSum := make([]*operation.Scalar, numOutputCoin)

	cmOutputSumAll := new(operation.Point).Identity()

	// cmOutputValueAll is sum of all value coin commitments
	cmOutputValueAll := new(operation.Point).Identity()

	randOutputValueAll := new(operation.Scalar).FromUint64(0)

	randOutputShardID := make([]*operation.Scalar, numOutputCoin)
	cmOutputShardID := make([]*operation.Point, numOutputCoin)

	for i, outputCoin := range wit.outputCoins {
		if i == len(outputCoins)-1 {
			randOutputValue[i] = new(operation.Scalar).Sub(randInputValueAll, randOutputValueAll)
		} else {
			randOutputValue[i] = operation.RandomScalar()
		}

		randOutputSND[i] = operation.RandomScalar()
		randOutputShardID[i] = operation.RandomScalar()

		cmOutputValue[i] = operation.PedCom.CommitAtIndex(new(operation.Scalar).FromUint64(outputCoin.CoinDetails.GetValue()), randOutputValue[i], operation.PedersenValueIndex)
		cmOutputSND[i] = operation.PedCom.CommitAtIndex(outputCoin.CoinDetails.GetSNDerivator(), randOutputSND[i], operation.PedersenSndIndex)

		receiverShardID := common.GetShardIDFromLastByte(outputCoins[i].CoinDetails.GetPubKeyLastByte())
		cmOutputShardID[i] = operation.PedCom.CommitAtIndex(new(operation.Scalar).FromUint64(uint64(receiverShardID)), randOutputShardID[i], operation.PedersenShardIDIndex)

		randOutputSum[i] = new(operation.Scalar).FromUint64(0)
		randOutputSum[i].Add(randOutputValue[i], randOutputSND[i])
		randOutputSum[i].Add(randOutputSum[i], randOutputShardID[i])

		cmOutputSum[i] = new(operation.Point).Identity()
		cmOutputSum[i].Add(cmOutputValue[i], cmOutputSND[i])
		cmOutputSum[i].Add(cmOutputSum[i], outputCoins[i].CoinDetails.GetPublicKey())
		cmOutputSum[i].Add(cmOutputSum[i], cmOutputShardID[i])

		cmOutputValueAll.Add(cmOutputValueAll, cmOutputValue[i])
		randOutputValueAll.Add(randOutputValueAll, randOutputValue[i])

		// calculate final commitment for output coins
		outputCoins[i].CoinDetails.SetCoinCommitment(cmOutputSum[i])
		outputCoins[i].CoinDetails.SetRandomness(randOutputSum[i])

		cmOutputSumAll.Add(cmOutputSumAll, cmOutputSum[i])
	}

	// For Multi Range Protocol
	// proving each output value is less than vmax
	// proving sum of output values is less than vmax
	outputValue := make([]uint64, numOutputCoin)
	for i := 0; i < numOutputCoin; i++ {
		if outputCoins[i].CoinDetails.GetValue() > 0 {
			outputValue[i] = outputCoins[i].CoinDetails.GetValue()
		} else {
			return errhandler.NewPrivacyErr(errhandler.UnexpectedErr, errors.New("output coin's value is less than 0"))
		}
	}
	if wit.aggregatedRangeWitness == nil {
		wit.aggregatedRangeWitness = new(aggregatedrange.AggregatedRangeWitness)
	}
	wit.aggregatedRangeWitness.Set(outputValue, randOutputValue)
	// ---------------------------------------------------

	// save partial commitments (value, input, shardID)
	wit.comOutputValue = cmOutputValue
	wit.comOutputSerialNumberDerivator = cmOutputSND
	wit.comOutputShardID = cmOutputShardID

	return nil
}

// Prove creates big proof
func (wit *PaymentWitness) Prove(hasPrivacy bool) (*PaymentProof, *errhandler.PrivacyError) {
	proof := new(PaymentProof)
	proof.Init()

	proof.inputCoins = wit.inputCoins
	proof.outputCoins = wit.outputCoins
	proof.commitmentOutputValue = wit.comOutputValue
	proof.commitmentOutputSND = wit.comOutputSerialNumberDerivator
	proof.commitmentOutputShardID = wit.comOutputShardID

	proof.commitmentInputSecretKey = wit.comInputSecretKey
	proof.commitmentInputValue = wit.comInputValue
	proof.commitmentInputSND = wit.comInputSerialNumberDerivator
	proof.commitmentInputShardID = wit.comInputShardID
	proof.commitmentIndices = wit.commitmentIndices

	// if hasPrivacy == false, don't need to create the zero knowledge proof
	// proving user has spending key corresponding with public key in input coins
	// is proved by signing with spending key
	if !hasPrivacy {
		// Proving that serial number is derived from the committed derivator
		for i := 0; i < len(wit.inputCoins); i++ {
			snNoPrivacyProof, err := wit.serialNumberNoPrivacyWitness[i].Prove(nil)
			if err != nil {
				return nil, errhandler.NewPrivacyErr(errhandler.ProveSerialNumberNoPrivacyErr, err)
			}
			proof.serialNumberNoPrivacyProof = append(proof.serialNumberNoPrivacyProof, snNoPrivacyProof)
		}
		return proof, nil
	}

	// if hasPrivacy == true
	numInputCoins := len(wit.oneOfManyWitness)

	for i := 0; i < numInputCoins; i++ {
		// Proving one-out-of-N commitments is a commitment to the coins being spent
		oneOfManyProof, err := wit.oneOfManyWitness[i].Prove()
		if err != nil {
			return nil, errhandler.NewPrivacyErr(errhandler.ProveOneOutOfManyErr, err)
		}
		proof.oneOfManyProof = append(proof.oneOfManyProof, oneOfManyProof)

		// Proving that serial number is derived from the committed derivator
		serialNumberProof, err := wit.serialNumberWitness[i].Prove(nil)
		if err != nil {
			return nil, errhandler.NewPrivacyErr(errhandler.ProveSerialNumberPrivacyErr, err)
		}
		proof.serialNumberProof = append(proof.serialNumberProof, serialNumberProof)
	}
	var err error

	// Proving that each output values and sum of them does not exceed v_max
	proof.aggregatedRangeProof, err = wit.aggregatedRangeWitness.Prove()
	if err != nil {
		return nil, errhandler.NewPrivacyErr(errhandler.ProveAggregatedRangeErr, err)
	}

	if len(proof.inputCoins) == 0 {
		proof.commitmentIndices = nil
		proof.commitmentInputSecretKey = nil
		proof.commitmentInputShardID = nil
		proof.commitmentInputSND = nil
		proof.commitmentInputValue = nil
	}

	if len(proof.outputCoins) == 0 {
		proof.commitmentOutputValue = nil
		proof.commitmentOutputSND = nil
		proof.commitmentOutputShardID = nil
	}

	//privacy.Logger.Log.Debug("Privacy log: PROVING DONE!!!")
	return proof, nil
}