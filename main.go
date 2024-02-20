package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	gethkzg4844 "github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/holiman/uint256"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type TxArgs struct {
    Network            string `json:"network"` // Required
    BlobData          string  `json:"blobData"` // Required
    To                string  `json:"to"` // Required
	PrivateKey        string  `json:"privateKey"` // Required
	// ChainID           string `json:"chainId"` // Required
	GasPrice          string `json:"gasPrice"` // Optional
    Value             *string `json:"value"` // Optional, has default
    Nonce             *int64  `json:"nonce"` // Optional, has default
    GasLimit          *uint64 `json:"gasLimit"` // Optional, has default
    PriorityGasPrice  string `json:"priorityGasPrice"` // Optional, has default
    MaxFeePerBlobGas  *string `json:"maxFeePerBlobGas"` // Optional, has default
    Calldata          *string `json:"calldata"` // Optional, has default
}

type TxResponse struct {
	TxHash      common.Hash `json:"txHash"`
	BlockNumber string `json:"blockNumber"`
}

type TxResponseError struct {
	Error string `json:"error"`
}

const (
	sepoliaChainID = "11155111" // Sepolia Chain ID
	goerliChainID  = "5"        // Goerli Chain ID
	sepoliaURL     = "https://eth-sepolia.g.alchemy.com/v2/KcE8JeoEPftn8jQ_abtWr58CvpcpZ4Xq"
	goerliURL      = "https://eth-goerli.g.alchemy.com/v2/KcE8JeoEPftn8jQ_abtWr58CvpcpZ4Xq"
)



func setDefaultValues(req *TxArgs) {
    if req.Value == nil {
        defaultValue := "0x0"
        req.Value = &defaultValue
    }
    if req.Nonce == nil {
        defaultNonce := int64(-1)
        req.Nonce = &defaultNonce
    }
    if req.GasLimit == nil {
        defaultGasLimit := uint64(21000)
        req.GasLimit = &defaultGasLimit
    }

	// if req.PriorityGasPrice == nil {
    //     defaultPriorityGasPrice := ""
    //     req.PriorityGasPrice = &defaultPriorityGasPrice
    // }
    if req.MaxFeePerBlobGas == nil {
        defaultMaxFeePerBlobGas := ""
        req.MaxFeePerBlobGas = &defaultMaxFeePerBlobGas
    }

    if req.Calldata == nil {
        defaultCalldata := "0x"
        req.Calldata = &defaultCalldata
    }
}


func TxHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
        return
    }
	var req TxArgs
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

	setDefaultValues(&req)

	TxApi(&req, &w)

}


func main() {

	http.HandleFunc("/tx", TxHandler)
    // http.HandleFunc("/download", DownloadHandler) // Implement similarly
    // http.HandleFunc("/proof", ProofHandler)       // Implement similarly

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		// log.Fatal("Port is empty")
	}
	
    log.Println("Server starting on port hello", port)
    if err := http.ListenAndServe(":"+port, nil); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }

}

func serveError(w *http.ResponseWriter, errorMsg string) {
	(*w).Header().Set("Content-Type", "application/json")

	(*w).WriteHeader(http.StatusBadRequest)
	res := TxResponseError{Error: errorMsg}
	json.NewEncoder(*w).Encode(res)		
}

func TxApi(txArgs *TxArgs, w *http.ResponseWriter) (error) {
	network := txArgs.Network
	to := common.HexToAddress(txArgs.To)
	prv := txArgs.PrivateKey
	blobData := txArgs.BlobData
	gasPrice := txArgs.GasPrice
	// chainID := txArgs.ChainID
	nonce := *txArgs.Nonce
	value := *txArgs.Value
	gasLimit := *txArgs.GasLimit
	priorityGasPrice := txArgs.PriorityGasPrice
	maxFeePerBlobGas := *txArgs.MaxFeePerBlobGas
	calldata := *txArgs.Calldata

	value256, err := uint256.FromHex(value)
	if err != nil {
		serveError(w, "invalid valule param")
		return fmt.Errorf("invalid value param: %v", err)
	}

	data := []byte(blobData)
	// data, err := os.ReadFile(file)
	// if err != nil {
	// 	(*w).WriteHeader(http.StatusBadRequest)
	// 	res := TxResponseError{Error: "error reading blob file"}
	// 	json.NewEncoder(*w).Encode(res)		
	// 	return fmt.Errorf("error reading blob file: %v", err)
	// }

	// chain ID defaults to Sepolia
	chainId, _ := new(big.Int).SetString(sepoliaChainID, 0)

	ctx := context.Background()

	if network == "sepolia" {
		network = sepoliaURL
	} else {
		network = goerliURL
		chainId, _ = new(big.Int).SetString(goerliChainID, 0)
	}

	client, err := ethclient.DialContext(ctx, network)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to connect to the Ethereum client: %v", err)
		serveError(w, errorMsg)
	}

	key, err := crypto.HexToECDSA(prv)
	if err != nil {
		errorMsg := fmt.Sprintf("invalid private key: %v", err)
		serveError(w, errorMsg)
		return fmt.Errorf("%w: invalid private key", err)
	}

	if nonce == -1 {
		pendingNonce, err := client.PendingNonceAt(ctx, crypto.PubkeyToAddress(key.PublicKey))
		if err != nil {
			errorMsg := fmt.Sprintf("Error getting nonce: %v", err)
			serveError(w, errorMsg)
		}
		nonce = int64(pendingNonce)
	}

	var gasPrice256 *uint256.Int
	if gasPrice == "" {
		fmt.Println("Getting suggested gas price")
		val, err := client.SuggestGasPrice(ctx)
		if err != nil {
			errorMsg := fmt.Sprintf("Error getting suggested gas price: %v", err)
			serveError(w, errorMsg)
		}
		var nok bool
		gasPrice256, nok = uint256.FromBig(val)
		if nok {
			errorMsg := fmt.Sprintf("gas price is too high! got %v", val.String())
			serveError(w, errorMsg)
		}
		fmt.Println("Suggested gas price", gasPrice256)
	} else {
		gasPrice256, err = DecodeUint256String(gasPrice)
		if err != nil {
			errorMsg := fmt.Sprintf("invalid gas price: %v", err)
			serveError(w, errorMsg)
			return fmt.Errorf("%w: invalid gas price", err)
		}
	}

	priorityGasPrice256 := gasPrice256
	if priorityGasPrice != "" {
		priorityGasPrice256, err = DecodeUint256String(priorityGasPrice)
		if err != nil {
			errorMsg := fmt.Sprintf("invalid priority gas price: %v", err)
			serveError(w, errorMsg)
			return fmt.Errorf("%w: invalid priority gas price", err)
		}
	}

	maxFeePerBlobGas256, err := DecodeUint256String(maxFeePerBlobGas)
	if err != nil {
		errorMsg := fmt.Sprintf("invalid max_fee_per_blob_gas: %v", err)
		serveError(w, errorMsg)
		return fmt.Errorf("%w: invalid max_fee_per_blob_gas", err)
	}

	// ensure data is a multiple of 32 bytes
	if len(data)%32 != 0 {
		// first just print something if its not
		// fmt.Printf("data is not a multiple of 32 bytes: %d\n", len(data))
		data = append(data, make([]byte, 32-len(data)%32)...)
	}

	// ensure data is a multiple of 32 bytes
	if len(data)%32 != 0 {
		// first just print something if its not
		fmt.Printf("data is still not a multiple of 32 bytes: %d\n", len(data))
		// data = append(data, make([]byte, 32 - len(data) % 32)...)
	}

	newData := make([]byte, len(data))
	// loop through all 32 byte chunks, seeing which one fails this:
	// v, err := BigEndian.Element((*[Bytes]byte)(e))
	// if err != nil {
	// 	return err
	// }
	for i := 0; i < len(data); i += 32 {
		piece := data[i : i+32]
		_, err := fr.BigEndian.Element((*[fr.Bytes]byte)(piece))
		if err != nil {
			// print utf 8 string
			// fmt.Printf("error parsing blob data: %v, %s\n", err, string(piece))

			// get the modulus
			modulus := fr.Modulus()

			// cut off the end of the data until it is lower than the modulus
			for j := 32; j >= 0; j-- {
				cutOff := piece[:j]

				// print cutOff bigint num
				intCutOff := new(big.Int).SetBytes(cutOff)
				// fmt.Printf("cutOff: %v\n", intCutOff)
				// fmt.Printf("modulus: %v\n", modulus)

				// if this new cut off is less than the modulus, use it
				if intCutOff.Cmp(modulus) == -1 {
					// fmt.Printf("using cutOff: %v\n", intCutOff)
					// left pad the cut off with 0s
					cutOff = append(make([]byte, 32-len(cutOff)), cutOff...)
					piece = cutOff
					i += j - 32
					// fmt.Printf("using cutOff: %v\n", string(piece))
					// fmt.Printf("what is the next piece: %v\n", string(data[i:i+32]))

					break
				}
			}

			// print utf 8 string
			fmt.Printf("error+- parsing blob data: %s\n", string(piece))

			// modify the data to be below the modulus, so it is as similar to
			// utf8 as possible

			// return fmt.Errorf("error parsing blob data: %v, %x", err, data[i:i+32])
		} else {

			// print utf 8 string
			fmt.Printf("success parsing blob data: %s\n", string(piece))
		}

		newData = append(newData, piece...)
	}

	// ensure data is a multiple of 32 bytes
	if len(newData)%32 != 0 {
		// first just print something if its not
		// fmt.Printf("data is not a multiple of 32 bytes: %d\n", len(data))
		newData = append(newData, make([]byte, 32-len(newData)%32)...)
	}

	// ensure data is a multiple of 32 bytes
	if len(newData)%32 != 0 {
		// first just print something if its not
		fmt.Printf("data is still not a multiple of 32 bytes: %d\n", len(newData))
		// data = append(data, make([]byte, 32 - len(data) % 32)...)
	}

	data = newData
	for i := 0; i < len(data); i += 32 {
		piece := data[i : i+32]
		_, err := fr.BigEndian.Element((*[fr.Bytes]byte)(piece))
		if err != nil {
			// print utf 8 string
			fmt.Printf("error parsing blob data: %v, %s\n", err, string(piece))
		}
	}

	// put each 32 byte chunk into a blob
	blob := gethkzg4844.Blob{}
	for i := 0; i < len(data); i += 32 {
		piece := data[i : i+32]
		// do not copy all zeros
		if bytes.Equal(piece, make([]byte, 32)) {
			continue
		}
		copy(blob[i:], piece)
	}

	blobs := []gethkzg4844.Blob{blob}

	for _, blob := range blobs {
		_, err := gethkzg4844.BlobToCommitment(blob)
		if err != nil {
			errorMsg := fmt.Sprintf("failed to compute commitments oof: %v", err)
			serveError(w, errorMsg)
			return fmt.Errorf("failed to compute commitments oof: %v", err)
		}
	}

	blobs, commitments, proofs, versionedHashes, err := EncodeBlobsTwo(blobs)
	if err != nil {
		errorMsg := fmt.Sprintf("failed to compute commitments: %v", err)
		serveError(w, errorMsg)
		return fmt.Errorf(errorMsg)
	}

	// blobs, commitments, proofs, versionedHashes, err = EncodeBlobs(data)
	// if err != nil {
	// 	log.Fatalf("failed to compute commitments: %v", err)
	// }

	for _, blob := range blobs {
		// print blob as if utf8
		fmt.Printf("blob: %s\n", string(blob[:]))
	}


	calldataBytes, err := common.ParseHexOrString(calldata)
	if err != nil {
		errorMsg := fmt.Sprintf("failed to parse calldata: %v", err)
		serveError(w, errorMsg)
		return fmt.Errorf(errorMsg)
	}

	fmt.Println("max gas fee", gasPrice256, "priority fee", priorityGasPrice256, "chain ID", 
		uint256.MustFromBig(chainId), "nonce", uint64(nonce), gasLimit, to, value256, calldataBytes,
		"max fee per blob", maxFeePerBlobGas256, versionedHashes)

	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.MustFromBig(chainId),
		Nonce:      uint64(nonce),
		GasTipCap:  priorityGasPrice256,
		GasFeeCap:  gasPrice256,
		Gas:        gasLimit,
		To:         to,
		Value:      value256,
		Data:       calldataBytes,
		BlobFeeCap: maxFeePerBlobGas256,
		BlobHashes: versionedHashes,
		Sidecar:    &types.BlobTxSidecar{Blobs: blobs, Commitments: commitments, Proofs: proofs},
	})
	signedTx, _ := types.SignTx(tx, types.NewCancunSigner(chainId), key)


	for {
		err = client.SendTransaction(context.Background(), signedTx)

		if err != nil && err.Error() == "transaction type not supported" {
			log.Printf("waiting for cancun to activate, RPC returned `%v`...", err)
			time.Sleep(100 * time.Millisecond)
		} else if err != nil {
			errorMsg := fmt.Sprintf("failed to send transaction: %v", err)
			serveError(w, errorMsg)
			return fmt.Errorf(errorMsg)
		} else {
			log.Printf("successfully sent transaction. txhash=%v", signedTx.Hash())
			break
		}
	}

	var receipt *types.Receipt
	for {
		receipt, err = client.TransactionReceipt(context.Background(), signedTx.Hash())
		if err == ethereum.NotFound {
			time.Sleep(1 * time.Second)
		} else if err != nil {
			if _, ok := err.(*json.UnmarshalTypeError); ok {
				// TODO: ignore other errors for now. Some clients are treating the blobGasUsed as big.Int rather than uint64
				break
			}
		} else {
			break
		}
	}

	// log.Printf("Transaction included. nonce=%d hash=%v", nonce, signedTx.Hash())
	log.Printf("Transaction included. nonce=%d hash=%v, block=%d", nonce, signedTx.Hash(), receipt.BlockNumber.Int64())
	fmt.Println("receipt",receipt)

	res := TxResponse{TxHash: signedTx.Hash(), BlockNumber: fmt.Sprint(receipt.BlockNumber.Int64())}
    (*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(http.StatusOK)
    err = json.NewEncoder(*w).Encode(res)	

	return nil
}
