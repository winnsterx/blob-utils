package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
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
	"github.com/urfave/cli"
)


func main() {
	app := cli.NewApp()
	app.Commands = []cli.Command{
		{
			Name:   "tx",
			Usage:  "send a blob transaction",
			Action: TxApp,
			Flags:  TxFlags,
		},
		{
			Name:   "download",
			Usage:  "download blobs from the beacon net",
			Action: DownloadApp,
			Flags:  DownloadFlags,
		},
		{
			Name:   "proof",
			Usage:  "generate kzg proof for any input point by using jth blob polynomial",
			Action: ProofApp,
			Flags:  ProofFlags,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("App failed: %v", err)
	}
}

func TxApp(cliCtx *cli.Context) error {
	addr := cliCtx.String(TxRPCURLFlag.Name)
	to := common.HexToAddress(cliCtx.String(TxToFlag.Name))
	prv := cliCtx.String(TxPrivateKeyFlag.Name)
	file := cliCtx.String(TxBlobFileFlag.Name)
	nonce := cliCtx.Int64(TxNonceFlag.Name)
	value := cliCtx.String(TxValueFlag.Name)
	gasLimit := cliCtx.Uint64(TxGasLimitFlag.Name)
	gasPrice := cliCtx.String(TxGasPriceFlag.Name)
	priorityGasPrice := cliCtx.String(TxPriorityGasPrice.Name)
	maxFeePerBlobGas := cliCtx.String(TxMaxFeePerBlobGas.Name)
	chainID := cliCtx.String(TxChainID.Name)
	calldata := cliCtx.String(TxCalldata.Name)

	value256, err := uint256.FromHex(value)
	if err != nil {
		return fmt.Errorf("invalid value param: %v", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("error reading blob file: %v", err)
	}

	chainId, _ := new(big.Int).SetString(chainID, 0)

	ctx := context.Background()
	client, err := ethclient.DialContext(ctx, addr)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	key, err := crypto.HexToECDSA(prv)
	if err != nil {
		return fmt.Errorf("%w: invalid private key", err)
	}

	if nonce == -1 {
		pendingNonce, err := client.PendingNonceAt(ctx, crypto.PubkeyToAddress(key.PublicKey))
		if err != nil {
			log.Fatalf("Error getting nonce: %v", err)
		}
		nonce = int64(pendingNonce)
	}

	var gasPrice256 *uint256.Int
	if gasPrice == "" {
		val, err := client.SuggestGasPrice(ctx)
		if err != nil {
			log.Fatalf("Error getting suggested gas price: %v", err)
		}
		var nok bool
		gasPrice256, nok = uint256.FromBig(val)
		if nok {
			log.Fatalf("gas price is too high! got %v", val.String())
		}
	} else {
		gasPrice256, err = DecodeUint256String(gasPrice)
		if err != nil {
			return fmt.Errorf("%w: invalid gas price", err)
		}
	}

	priorityGasPrice256 := gasPrice256
	if priorityGasPrice != "" {
		priorityGasPrice256, err = DecodeUint256String(priorityGasPrice)
		if err != nil {
			return fmt.Errorf("%w: invalid priority gas price", err)
		}
	}

	maxFeePerBlobGas256, err := DecodeUint256String(maxFeePerBlobGas)
	if err != nil {
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
			log.Fatalf("failed to compute commitments oof: %v", err)
		}
	}

	blobs, commitments, proofs, versionedHashes, err := EncodeBlobsTwo(blobs)
	if err != nil {
		log.Fatalf("failed to compute commitments: %v", err)
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
		log.Fatalf("failed to parse calldata: %v", err)
	}

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
			log.Fatalf("failed to send transaction: %v", err)
		} else {
			log.Printf("successfully sent transaction. txhash=%v", signedTx.Hash())
			break
		}
	}

	//var receipt *types.Receipt
	for {
		_, err = client.TransactionReceipt(context.Background(), tx.Hash())
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

	log.Printf("Transaction included. nonce=%d hash=%v", nonce, tx.Hash())
	//log.Printf("Transaction included. nonce=%d hash=%v, block=%d", nonce, tx.Hash(), receipt.BlockNumber.Int64())
	return nil
}

func ProofApp(cliCtx *cli.Context) error {
	file := cliCtx.String(ProofBlobFileFlag.Name)
	blobIndex := cliCtx.Uint64(ProofBlobIndexFlag.Name)
	inputPoint := cliCtx.String(ProofInputPointFlag.Name)

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("error reading blob file: %v", err)
	}
	blobs, commitments, _, versionedHashes, err := EncodeBlobs(data)
	if err != nil {
		log.Fatalf("failed to compute commitments: %v", err)
	}

	if blobIndex >= uint64(len(blobs)) {
		return fmt.Errorf("error reading %d blob", blobIndex)
	}

	if len(inputPoint) != 64 {
		return fmt.Errorf("wrong input point, len is %d", len(inputPoint))
	}

	var x gethkzg4844.Point
	ip, _ := hex.DecodeString(inputPoint)
	copy(x[:], ip)
	proof, claimedValue, err := gethkzg4844.ComputeProof(gethkzg4844.Blob(blobs[blobIndex]), x)
	if err != nil {
		log.Fatalf("failed to compute proofs: %v", err)
	}

	pointEvalInput := bytes.Join(
		[][]byte{
			versionedHashes[blobIndex][:],
			x[:],
			claimedValue[:],
			commitments[blobIndex][:],
			proof[:],
		},
		[]byte{},
	)
	log.Printf(
		"\nversionedHash %x \n"+"x %x \n"+"y %x \n"+"commitment %x \n"+"proof %x \n"+"pointEvalInput %x",
		versionedHashes[blobIndex][:], x[:], claimedValue[:], commitments[blobIndex][:], proof[:], pointEvalInput[:])
	return nil
}
