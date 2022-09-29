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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	aptossdk "github.com/polynetwork/aptos-go-sdk/client"
	"github.com/polynetwork/aptos-voter/config"
	"github.com/polynetwork/aptos-voter/pkg/db"
	"github.com/polynetwork/aptos-voter/pkg/log"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	autils "github.com/polynetwork/poly/native/service/utils"
)

type Voter struct {
	polySdk *sdk.PolySdk
	signer  *sdk.Account
	clients []aptossdk.AptosClient
	conf    *config.Config
	bdb     *db.BoltDB
	idx     int
	mutex   sync.Mutex
}

func New(polySdk *sdk.PolySdk, signer *sdk.Account, conf *config.Config) *Voter {
	return &Voter{polySdk: polySdk, signer: signer, conf: conf}
}

func (v *Voter) Init() (err error) {
	bdb, err := db.NewBoltDB(v.conf.BoltDbPath)
	if err != nil {
		return
	}
	v.bdb = bdb
	var clients []aptossdk.AptosClient
	for _, node := range v.conf.SideConfig.RestURL {
		aptosSdk := aptossdk.NewAptosClient(node)
		clients = append(clients, aptosSdk)
	}
	v.clients = clients
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
	ticker := time.NewTicker(time.Second)
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
					err = v.fetchLockDepositEventByTxHash(ctx, txHash.(string))
					if err != nil {
						log.Errorf("fetchLockDepositEventByTxHash failed:%v", err)
						v.changeEndpoint()
						sleep()
						continue
					}
				}
				nextPolyHeight++
			}
		case <-ctx.Done():
			log.Info("quiting from signal...")
			return
		}
	}
}

func (v *Voter) StartVoter(ctx context.Context) {
	nextSequence := v.bdb.GetSideSequence()
	if v.conf.ForceConfig.SideSequence > 0 {
		nextSequence = v.conf.ForceConfig.SideSequence
	}
	ticker := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-ticker.C:
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				startSequence := nextSequence
				enentNum, err := v.fetchLockDepositEvents(ctx, nextSequence)
				if err != nil {
					log.Errorf("fetchLockDepositEvents failed:%v", err)
					v.changeEndpoint()
					sleep()
					continue
				}

				err = v.bdb.UpdateSideSequence(nextSequence)
				if err != nil {
					log.Errorf("UpdateSideSequence failed:%v", err)
				}

				if enentNum >= int(v.conf.SideConfig.Batch) || int(nextSequence-startSequence) < enentNum {
					continue
				}
				break

			}

		case <-ctx.Done():
			log.Info("quiting from signal...")
			return
		}
	}
}

func (v *Voter) fetchLockDepositEvents(ctx context.Context, nextSequence uint64) (int, error) {
	events, err := v.clients[v.idx].GetEventsByEventKey(ctx, v.conf.SideConfig.CcmEventKey, v.conf.SideConfig.Batch, strconv.Itoa(int(nextSequence)))
	if err != nil {
		log.Errorf("aptos GetEventsByEventKey failed:%v", err)
		v.changeEndpoint()
		sleep()
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	sort.Slice(events, func(i, j int) bool {
		x, _ := strconv.Atoi(events[i].SequenceNumber)
		y, _ := strconv.Atoi(events[j].SequenceNumber)
		return x < y
	})
	log.Infof("current aptos event sequence:%d", nextSequence)
	log.CheckRotateLogFile()

	for _, event := range events {
		if strings.EqualFold(strings.TrimPrefix(event.Key, "0x"), strings.TrimPrefix(v.conf.SideConfig.CcmEventKey, "0x")) {
			param := &common2.MakeTxParam{}
			rawData, err := hex.DecodeString(event.Data["raw_data"].(string))
			if err != nil {
				log.Errorf("decode rawdata err: %v, version: %s, eventsequence: %s", err, event.Version, event.SequenceNumber)
				continue
			}

			_ = param.Deserialization(common.NewZeroCopySource(rawData))
			if !v.conf.IsWhitelistMethod(param.Method) {
				log.Errorf("target contract method invalid %s, version: %s, eventsequence: %s", param.Method, event.Version, event.SequenceNumber)
				continue
			}

			raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
				append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), param.CrossChainID...))
			if len(raw) != 0 {
				log.Infof("StartVoter - ccid %s (version: %s, eventsequence: %s) already on poly",
					hex.EncodeToString(param.CrossChainID), event.Version, event.SequenceNumber)
				continue
			}

			//version -> tx, height -> block
			version, err := strconv.Atoi(event.Version)
			if err != nil {
				log.Errorf("tx version err: %v, version: %s, txid: %v", err, event.Version, hex.EncodeToString(param.CrossChainID))
				continue
			}
			txHash, err := v.commitVote(uint32(version), rawData, param.CrossChainID)
			if err != nil {
				log.Errorf("commitVote failed:%v, version: %s, txid: %v", err, event.Version, hex.EncodeToString(param.CrossChainID))
				return len(events), err
			}
			err = v.waitTx(txHash)
			if err != nil {
				log.Errorf("waitTx failed:%v", err)
				return len(events), err
			}
			nextSequence++
		}
	}
	log.Infof("side event nextSequence: %d", nextSequence)
	return len(events), nil
}

func (v *Voter) fetchLockDepositEventByTxHash(ctx context.Context, txHash string) error {
	tx, err := v.clients[v.idx].GetTransactionByHash(ctx, txHash)
	if err != nil {
		return fmt.Errorf("fetchLockDepositEventByTxHash, cannot get tx: %s info, err: %s", txHash, err)
	}
	for _, event := range tx.Events {
		if strings.EqualFold(strings.TrimPrefix(event.Key, "0x"), strings.TrimPrefix(v.conf.SideConfig.CcmEventKey, "0x")) {
			param := &common2.MakeTxParam{}
			rawData, err := hex.DecodeString(event.Data["raw_data"].(string))
			if err != nil {
				log.Errorf("decode rawdata err: %v, txHash: %s", err, txHash)
				continue
			}

			_ = param.Deserialization(common.NewZeroCopySource(rawData))
			if !v.conf.IsWhitelistMethod(param.Method) {
				log.Errorf("target contract method invalid %s, txHash: %s", param.Method, txHash)
				continue
			}

			raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
				append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), param.CrossChainID...))
			if len(raw) != 0 {
				log.Infof("fetchLockDepositEventByTxHash - ccid %s (tx_hash: %s) already on poly",
					hex.EncodeToString(param.CrossChainID), txHash)
				continue
			}

			//version -> tx, height -> block
			version, err := strconv.Atoi(tx.Version)
			if err != nil {
				log.Errorf("tx version err: %v, txHash: %s", err, txHash)
				continue
			}
			txHash, err = v.commitVote(uint32(version), rawData, param.CrossChainID)
			if err != nil {
				log.Errorf("commitVote failed:%v", err)
				continue
			}
		}
	}

	return nil
}

func (v *Voter) commitVote(version uint32, value []byte, txid []byte) (string, error) {
	log.Infof("commitVote, version: %d, value: %s, txid: %s", version, hex.EncodeToString(value), hex.EncodeToString(txid))
	tx, err := v.polySdk.Native.Ccm.ImportOuterTransfer(
		v.conf.SideConfig.SideChainId,
		value,
		version,
		nil,
		v.signer.Address[:],
		[]byte{},
		v.signer)
	if err != nil {
		return "", err
	} else {
		log.Infof("commitVote - send transaction to poly chain: ( poly_txhash: %s, side_txid: %s, side_version: %d )",
			tx.ToHexString(), hex.EncodeToString(txid), version)
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

func (v *Voter) changeEndpoint() {
	v.mutex.Lock()
	defer func() {
		v.mutex.Unlock()
	}()
	if v.idx == len(v.clients)-1 {
		v.idx = 0
	} else {
		v.idx = v.idx + 1
	}
	log.Infof("change endpoint to %d", v.idx)
}
