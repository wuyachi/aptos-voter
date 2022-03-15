/**
 * Copyright (C) 2021 The poly network Authors
 * This file is part of The poly network library.
 *
 * The poly network is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The poly network is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the poly network.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package voter

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	autils "github.com/polynetwork/poly/native/service/utils"
	ripplesdk "github.com/polynetwork/ripple-sdk"
	"github.com/polynetwork/ripple-voter/config"
	"github.com/polynetwork/ripple-voter/pkg/db"
	"github.com/polynetwork/ripple-voter/pkg/log"
	"github.com/rubblelabs/ripple/data"
)

type Voter struct {
	polySdk          *sdk.PolySdk
	signer           *sdk.Account
	rippleSdk        *ripplesdk.RippleSdk
	conf             *config.Config
	bdb              *db.BoltDB
	multisignAccount string
}

func New(polySdk *sdk.PolySdk, rippleSdk *ripplesdk.RippleSdk, signer *sdk.Account, conf *config.Config) *Voter {
	return &Voter{polySdk: polySdk, rippleSdk: rippleSdk, signer: signer, conf: conf}
}

func (v *Voter) Init() (err error) {
	bdb, err := db.NewBoltDB(v.conf.BoltDbPath)
	if err != nil {
		return
	}
	v.bdb = bdb
	v.multisignAccount = v.conf.SideConfig.MultisignAccount

	return
}

func (v *Voter) StartReplenish(ctx context.Context) {
	var nextPolyHeight uint64
	if v.conf.ForceConfig.PolyHeight != 0 {
		nextPolyHeight = v.conf.ForceConfig.PolyHeight
	} else {
		h, err := v.polySdk.GetCurrentBlockHeight()
		if err != nil {
			panic(fmt.Sprintf("v.polySdk.GetCurrentBlockHeight failed:%v", err))
		}
		nextPolyHeight = uint64(h)
		log.Infof("start from current poly height:%d", h)
	}
	ticker := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-ticker.C:
			h, err := v.polySdk.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("v.polySdk.GetCurrentBlockHeight failed:%v", err)
				continue
			}
			height := uint64(h)
			log.Infof("current poly height:%d", height)
			if height < nextPolyHeight {
				continue
			}

			for nextPolyHeight <= height {
				select {
				case <-ctx.Done():
					return
				default:
				}
				log.Infof("handling poly height:%d", nextPolyHeight)
				events, err := v.polySdk.GetSmartContractEventByBlock(uint32(nextPolyHeight))
				if err != nil {
					log.Errorf("poly failed to fetch smart contract events for height %d, err %v", height, err)
					continue
				}
				txHashList := make([]interface{}, 0)
				for _, event := range events {
					for _, notify := range event.Notify {
						if notify.ContractAddress != autils.ReplenishContractAddress.ToHexString() {
							continue
						}
						states, ok := notify.States.([]interface{})
						if !ok || states[0].(string) != "ReplenishTx" {
							continue
						}

						chainId := states[2].(float64)
						if uint64(chainId) == v.conf.SideConfig.SideChainId {
							txHashes := states[1].([]interface{})
							txHashList = append(txHashList, txHashes...)
						}
					}
				}

				for _, txHash := range txHashList {
					err = v.fetchLockDepositEventByTxHash(txHash.(string))
					if err != nil {
						log.Errorf("fetchLockDepositEventByTxHash failed:%v", err)
						continue
					}
				}
				nextPolyHeight++
			}
		}
	}
}

func (v *Voter) StartVoter(ctx context.Context) {
	nextSideHeight := v.bdb.GetSideHeight()
	if v.conf.ForceConfig.SideHeight > 0 {
		nextSideHeight = v.conf.ForceConfig.SideHeight
	}
	ticker := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-ticker.C:
			height, err := v.rippleSdk.GetRpcClient().GetCurrentHeight()
			if err != nil {
				log.Errorf("ripple GetCurrentHeight failed:%v", err)
				continue
			}
			log.Infof("current ripple height:%d", height)
			if height < nextSideHeight+v.conf.SideConfig.BlocksToWait+1 {
				continue
			}

			for nextSideHeight < height-v.conf.SideConfig.BlocksToWait-1 {
				select {
				case <-ctx.Done():
					return
				default:
				}
				log.Infof("handling side height:%d", nextSideHeight)
				err = v.fetchLockDepositTx(nextSideHeight)
				if err != nil {
					log.Errorf("fetchLockDepositEvents failed:%v", err)
					sleep()
					continue
				}
				nextSideHeight++
			}

			err = v.bdb.UpdateSideHeight(nextSideHeight)
			if err != nil {
				log.Errorf("UpdateSideHeight failed:%v", err)
			}

		case <-ctx.Done():
			log.Info("quiting from signal...")
			return
		}
	}
}

type CrossTransfer struct {
	txIndex string
	txId    []byte
	value   []byte
	toChain uint32
	height  uint64
}

func (v *Voter) fetchLockDepositEventByTxHash(txHash string) error {
	tx, err := v.rippleSdk.GetRpcClient().GetTx(txHash)
	if err != nil {
		return fmt.Errorf("fetchLockDepositEventByTxHash: cannot get tx %s info, err: %s", txHash, err)
	}

	if tx.MetaData.TransactionResult.Success() { // tx status is success
		if payment, ok := tx.Transaction.(*data.Payment); ok && // payment tx
			payment.Amount.Currency.Machine() == "XRP" && // payment xrp
			payment.Memos != nil && // judge memos
			payment.Destination.String() == v.multisignAccount {
			// check if tx has done
			raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
				append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), tx.GetHash().Bytes()...))
			if len(raw) != 0 {
				log.Infof("fetchLockDepositEvents - ccid %s (tx_hash: %s) already on poly",
					hex.EncodeToString(tx.GetHash().Bytes()), hex.EncodeToString(tx.GetHash().Bytes()))
				return nil
			}

			// tx is deposit payment
			// parse cross chain info
			var dstChainId uint64
			var dstAddress []byte
			for _, memo := range payment.Memos {
				//636861696E6964 means chainid
				if memo.Memo.MemoType.String() == "636861696E6964" {
					id := new(big.Int).SetBytes(memo.Memo.MemoData.Bytes())
					dstChainId = id.Uint64()
				}
				//61646472657373 means address
				if memo.Memo.MemoType.String() == "61646472657373" {
					dstAddress = memo.Memo.MemoData.Bytes()
				}
			}
			l := len(dstAddress)
			if dstChainId == 0 || l == 0 {
				return fmt.Errorf("fetchLockDepositEventByTxHash: cross chain info is empty, txHash is: %s", tx.GetHash().String())
			}
			toContractAddress, err := v.polySdk.GetStorage(autils.SideChainManagerContractAddress.ToHexString(), []byte{})
			if err != nil {
				return fmt.Errorf("fetchLockDepositTx: get to asset contract address error:%s, dst chain id: %d, txHash is: %s",
					err, dstChainId, tx.GetHash().String())
			}

			// create args
			native, err := tx.MetaData.DeliveredAmount.Native()
			if err != nil {
				return fmt.Errorf("fetchLockDepositEventByTxHash: value parse to native error:%s, amount is: %s, txHash is: %s",
					err, tx.MetaData.DeliveredAmount.String(), tx.GetHash().String())
			}
			sink := common.NewZeroCopySink(nil)
			sink.WriteVarBytes(dstAddress)
			sink.WriteBytes(native.Bytes())

			param := &common2.MakeTxParam{
				TxHash:              tx.GetHash().Bytes(),
				CrossChainID:        tx.GetHash().Bytes(),
				FromContractAddress: payment.Destination[:],
				ToChainID:           dstChainId,
				ToContractAddress:   toContractAddress,
				Method:              "unlock",
				Args:                sink.Bytes(),
			}

			sink2 := common.NewZeroCopySink(nil)
			param.Serialization(sink2)

			// commit vote
			var txHash string
			txHash, err = v.commitVote(tx.LedgerSequence, sink2.Bytes(), param.TxHash)
			if err != nil {
				log.Errorf("commitVote failed:%v", err)
				return err
			}
			err = v.waitTx(txHash)
			if err != nil {
				log.Errorf("waitTx failed:%v", err)
				return err
			}
		}
	}
	return nil
}

func (v *Voter) fetchLockDepositTx(height uint32) error {
	ledger, err := v.rippleSdk.GetRpcClient().GetLedger(height)
	if err != nil {
		return fmt.Errorf("fetchDepositTx: cannot get leger %d info, err: %s", height, err)
	}
	empty := true
	for _, txData := range ledger.Ledger.Transactions {
		if txData.MetaData.TransactionResult.Success() { // tx status is success
			if payment, ok := txData.Transaction.(*data.Payment); ok && // payment tx
				payment.Amount.Currency.Machine() == "XRP" && // payment xrp
				payment.Memos != nil && // judge memos
				payment.Destination.String() == v.multisignAccount {
				empty = false
				// check if tx has done
				raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
					append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), txData.GetHash().Bytes()...))
				if len(raw) != 0 {
					log.Infof("fetchLockDepositEvents - ccid %s (tx_hash: %s) already on poly",
						hex.EncodeToString(txData.GetHash().Bytes()), hex.EncodeToString(txData.GetHash().Bytes()))
					return nil
				}

				// tx is deposit payment
				// parse cross chain info
				var dstChainId uint64
				var dstAddress []byte
				for _, memo := range payment.Memos {
					//636861696E6964 means chainid
					if memo.Memo.MemoType.String() == "636861696E6964" {
						id := new(big.Int).SetBytes(memo.Memo.MemoData.Bytes())
						dstChainId = id.Uint64()
					}
					//61646472657373 means address
					if memo.Memo.MemoType.String() == "61646472657373" {
						dstAddress = memo.Memo.MemoData.Bytes()
					}
				}
				l := len(dstAddress)
				if dstChainId == 0 || l == 0 {
					log.Errorf("fetchLockDepositTx: cross chain info is empty, txHash is: %s", txData.GetHash().String())
					continue
				}
				toContractAddress, err := v.polySdk.GetStorage(autils.SideChainManagerContractAddress.ToHexString(), []byte{})
				if err != nil {
					log.Errorf("fetchLockDepositTx: get to asset contract address error:%s, dst chain id: %d, txHash is: %s",
						err, dstChainId, txData.GetHash().String())
					continue
				}

				// create args
				native, err := txData.MetaData.DeliveredAmount.Native()
				if err != nil {
					log.Errorf("fetchLockDepositTx: value parse to native error:%s, amount is: %s, txHash is: %s",
						err, txData.MetaData.DeliveredAmount.String(), txData.GetHash().String())
					continue
				}
				amount := new(big.Int).SetUint64(uint64(native.Float() * 1000000))
				sink := common.NewZeroCopySink(nil)
				sink.WriteVarBytes(dstAddress)
				sink.WriteString(amount.String())

				param := &common2.MakeTxParam{
					TxHash:              txData.GetHash().Bytes(),
					CrossChainID:        txData.GetHash().Bytes(),
					FromContractAddress: payment.Destination[:],
					ToChainID:           dstChainId,
					ToContractAddress:   toContractAddress,
					Method:              "unlock",
					Args:                sink.Bytes(),
				}

				sink2 := common.NewZeroCopySink(nil)
				param.Serialization(sink2)

				// commit vote
				var txHash string
				txHash, err = v.commitVote(height, sink2.Bytes(), param.TxHash)
				if err != nil {
					log.Errorf("commitVote failed:%v", err)
					return err
				}
				err = v.waitTx(txHash)
				if err != nil {
					log.Errorf("waitTx failed:%v", err)
					return err
				}
			}
		}
	}
	log.Infof("side height %d empty: %v", height, empty)

	return nil
}

func (v *Voter) commitVote(height uint32, value []byte, txhash []byte) (string, error) {
	log.Infof("commitVote, height: %d, value: %s, txhash: %s", height, hex.EncodeToString(value), hex.EncodeToString(txhash))
	tx, err := v.polySdk.Native.Ccm.ImportOuterTransfer(
		v.conf.SideConfig.SideChainId,
		value,
		height,
		nil,
		v.signer.Address[:],
		[]byte{},
		v.signer)
	if err != nil {
		return "", err
	} else {
		log.Infof("commitVote - send transaction to poly chain: ( poly_txhash: %s, side_txhash: %s, height: %d )",
			tx.ToHexString(), hex.EncodeToString(txhash), height)
		return tx.ToHexString(), nil
	}
}

func (v *Voter) waitTx(txHash string) (err error) {
	start := time.Now()
	var tx *types.Transaction
	for {
		tx, err = v.polySdk.GetTransaction(txHash)
		if tx == nil || err != nil {
			if time.Since(start) > time.Minute*5 {
				err = fmt.Errorf("waitTx timeout")
				return
			}
			time.Sleep(time.Second)
			continue
		}
		return
	}
}

func sleep() {
	time.Sleep(time.Second)
}
func randIdx(size int) int {
	return int(rand.Uint32()) % size
}
