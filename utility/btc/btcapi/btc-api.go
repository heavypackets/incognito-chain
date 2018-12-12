package btcapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"strconv"
	"time"
)

// type of timestamp in blockheader is int64
// const API_KEY = "a2f2bad22feb460482efe5fbbefde77f"
var (
	blockTimestamp int64
	blockHeight    int
)

const (
	MAX_TIMESTAMP = 4762368000
)

func GetNonceByTimestamp(timestamp int64) (int64, error) {
	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go
	resp, err := http.Get("https://api.blockcypher.com/v1/btc/test3")
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		chainBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return -1, err
		}
		chain := make(map[string]interface{})
		json.Unmarshal(chainBytes, &chain)
		chainHeight := int(chain["height"].(float64))
		chainTimestamp, err := makeTimestamp2(chain["time"].(string))
		if err != nil {
			return -1, err
		}
		blockHeight, err := estimateBlockHeight(timestamp, chainHeight, chainTimestamp)
		if err != nil {
			return -1, err
		}
		// TODO: 0xmerman calculate timestamp to get the right nonce
		// get list of block with timestamp > given timestamp then get block with min timestamp value
		fmt.Println("BlockTimestamp 0", blockTimestamp, blockHeight, timestamp)
		_, blockTimestamp, err = GetNonceOrTimeStampByBlock(strconv.Itoa(blockHeight), false)
		if err != nil {
			fmt.Println(err)
			return -1, err
		}
		if blockTimestamp == MAX_TIMESTAMP {
			return -1, errors.New("API error")
		}
		fmt.Println("BlockTimestamp 1", blockTimestamp, blockHeight, timestamp)
		if blockTimestamp > timestamp {
			for blockTimestamp > timestamp {
				fmt.Println("BlockTimestamp 2", blockTimestamp, blockHeight, timestamp)
				blockHeight--
				_, blockTimestamp, err = GetNonceOrTimeStampByBlock(strconv.Itoa(blockHeight), false)
				if err != nil {
					fmt.Println(err)
					return -1, err
				}
				if blockTimestamp == MAX_TIMESTAMP {
					return -1, errors.New("API error")
				}
				if blockTimestamp <= timestamp {
					fmt.Println("BlockTimestamp 2-2", blockTimestamp, blockHeight, timestamp)
					blockHeight++
					break
				}
			}
		} else {
			for blockTimestamp <= timestamp {
				fmt.Println("BlockTimestamp 3", blockTimestamp, blockHeight, timestamp)
				blockHeight++
				if blockHeight > chainHeight {
					return -1, errors.New("Timestamp is greater than timestamp of highest block")
				}
				_, blockTimestamp, err = GetNonceOrTimeStampByBlock(strconv.Itoa(blockHeight), false)
				if err != nil {
					fmt.Println(err)
					return -1, err
				}
				if blockTimestamp == MAX_TIMESTAMP {
					return -1, errors.New("API error")
				}
				if blockTimestamp > timestamp {
					break
				}
			}
		}
		fmt.Println("blockHeight", blockHeight)
		nonce, _, err := GetNonceOrTimeStampByBlock(strconv.Itoa(blockHeight), true)
		fmt.Println("Nonce", nonce)
		if err != nil {
			return -1, err
		}
		// common.Logger.Infof("Found nonce %d match timestamp %d", nonce, timestamp)
		return nonce, nil
	}
	return -1, errors.New("ERROR Getting Nonce By Timestamp Bitcoin")
}

func VerifyNonceWithTimestamp(timestamp int64, nonce int64) (bool, error) {
	res, err := GetNonceByTimestamp(timestamp)
	if err != nil {
		return false, err
	}
	return res == nonce, nil
}

//true for nonce, false for time
// return param:
// #param 1: nonce -> flag true
// #param 2: timestamp -> flag false
func GetNonceOrTimeStampByBlock(blockHeight string, nonceOrTime bool) (int64, int64, error) {
	time.Sleep(5 * time.Second)
	resp, err := http.Get("https://api.blockcypher.com/v1/btc/test3/blocks/" + blockHeight + "?start=1&limit=1")
	if err != nil {
		return -1, MAX_TIMESTAMP, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		blockBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return -1, MAX_TIMESTAMP, err
		}
		block := make(map[string]interface{})
		json.Unmarshal(blockBytes, &block)
		if nonceOrTime {
			return int64(block["nonce"].(float64)), -1, nil
		} else {
			timeTime, err := time.Parse(time.RFC3339, block["time"].(string))
			if err != nil {
				return -1, MAX_TIMESTAMP, err
			}
			timeInt64 := makeTimestamp(timeTime)
			return -1, timeInt64, nil
		}
	}
	return -1, MAX_TIMESTAMP, errors.New("ERROR Getting Nonce or Timestamp from Bitcoin")
}

// count in second
// use t.UnixNano() / int64(time.Millisecond) for milisecond
func makeTimestamp(t time.Time) int64 {
	return t.Unix()
}

// convert time.RFC3339 -> int64 value
// t,_ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
func makeTimestamp2(t string) (int64, error) {
	res, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return -1, err
	}
	return makeTimestamp(res), nil
}

// assume that each block will be produced in 10 mins ~= 600s
// this function will based on the given #param1 timestamp and #param3 chainTimestamp
// to calculate blockheight with approximate timestamp with #param1
// blockHeight = chainHeight - (chainTimestamp - timestamp) / 600
func estimateBlockHeight(timestamp int64, chainHeight int, chainTimestamp int64) (int, error) {
	var estimateBlockHeight int
	fmt.Printf("EstimateBlockHeight timestamp %d, chainHeight %d, chainTimestamp %d\n", timestamp, chainHeight, chainTimestamp)
	offsetSeconds := timestamp - chainTimestamp
	if offsetSeconds > 0 {
		return chainHeight, nil
	} else {
		estimateBlockHeight = chainHeight
		// diff is negative
		for true {
			diff := int(offsetSeconds / 600)
			estimateBlockHeight = estimateBlockHeight + diff
			fmt.Printf("Estimate blockHeight %d \n", estimateBlockHeight)
			if math.Abs(float64(diff)) < 3 {
				return estimateBlockHeight, nil
			}
			_, blockTimestamp, err := GetNonceOrTimeStampByBlock(strconv.Itoa(estimateBlockHeight), false)
			fmt.Printf("Try to estimate block with timestamp %d \n", blockTimestamp)
			if err != nil {
				fmt.Println(err)
				return -1, err
			}
			if blockTimestamp == MAX_TIMESTAMP {
				return -1, errors.New("API error")
			}
			offsetSeconds = timestamp - blockTimestamp
		}
	}
	return chainHeight, errors.New("Can't estimate block")
}
