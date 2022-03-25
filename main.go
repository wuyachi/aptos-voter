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

package main

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/howeyc/gopass"
	sdk "github.com/polynetwork/poly-go-sdk"
	ripplesdk "github.com/polynetwork/ripple-sdk"
	"github.com/polynetwork/ripple-voter/config"
	"github.com/polynetwork/ripple-voter/pkg/log"
	"github.com/polynetwork/ripple-voter/pkg/voter"
)

var confFile string

func init() {
	flag.StringVar(&confFile, "conf", "./config.json", "configuration file path")
	flag.Parse()
}

func setUpPoly(polySdk *sdk.PolySdk, rpcAddr string) error {
	polySdk.NewRpcClient().SetAddress(rpcAddr)
	hdr, err := polySdk.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	polySdk.SetChainId(hdr.ChainID)
	return nil
}

func main() {
	log.InitLog(log.InfoLog, "./Log/", log.Stdout)

	conf, err := config.LoadConfig(confFile)
	if err != nil {
		log.Fatalf("LoadConfig fail:%v", err)
		return
	}

	polySdk := sdk.NewPolySdk()
	err = setUpPoly(polySdk, conf.PolyConfig.RestURL)
	if err != nil {
		log.Fatalf("setUpPoly failed: %v", err)
		return
	}
	wallet, err := polySdk.OpenWallet(conf.PolyConfig.WalletFile)
	if err != nil {
		log.Fatalf("polySdk.OpenWallet failed: %v", err)
		return
	}
	pass := []byte(conf.PolyConfig.WalletPwd)
	if len(pass) == 0 {
		fmt.Print("Enter Password: ")
		pass, err = gopass.GetPasswd()
		if err != nil {
			log.Fatalf("gopass.GetPasswd failed: %v", err)
			return
		}
	}

	signer, err := wallet.GetDefaultAccount(pass)
	if err != nil {
		log.Fatalf("wallet.GetDefaultAccount failed: %v", err)
		return
	}
	log.Infof("voter %s", signer.Address.ToBase58())

	rippleSdk := ripplesdk.NewRippleSdk()
	rippleSdk.NewRpcClient().SetAddress(conf.SideConfig.RestURL)

	v := voter.New(polySdk, rippleSdk, signer, conf)
	err = v.Init()
	if err != nil {
		log.Fatalf("Voter.init failed: %v", err)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go v.StartReplenish(ctx)
	go v.FeeScan(ctx)
	v.StartVoter(ctx)
}
