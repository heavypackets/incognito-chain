package common

import (
	"sync"

	"github.com/0xBahamoot/go-bigcompressor"
)

var bigCompress bigcompressor.BigCompressor
var bigCompresslock sync.Mutex

const (
	maxPrecompressChunkSize int64 = 1048576
	maxDecompressBufferSize int64 = 1048576
)

func CompressDatabase(src string, dst string) error {
	bigCompresslock.Lock()
	defer bigCompresslock.Unlock()
	bigCompress.CombineChunk = true
	bigCompress.MaxPrecompressChunkSize = maxPrecompressChunkSize
	err := bigCompress.Compress(src, dst)
	if err != nil {
		return err
	}
	return nil
}

func DecompressDatabaseBackup(src string, dst string) error {
	bigCompresslock.Lock()
	defer bigCompresslock.Unlock()
	bigCompress.MaxDecompressBufferSize = maxDecompressBufferSize
	err := bigCompress.Decompress(src, dst)
	if err != nil {
		return err
	}
	return nil
}
