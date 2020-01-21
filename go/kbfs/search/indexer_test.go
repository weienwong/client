// Copyright 2020 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package search

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/blevesearch/bleve"
	"github.com/keybase/client/go/kbfs/data"
	"github.com/keybase/client/go/kbfs/idutil"
	"github.com/keybase/client/go/kbfs/libcontext"
	"github.com/keybase/client/go/kbfs/libkbfs"
	"github.com/keybase/client/go/kbfs/tlf"
	"github.com/keybase/client/go/kbfs/tlfhandle"
	"github.com/keybase/client/go/logger"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/stretchr/testify/require"
)

func testInitConfig(
	ctx context.Context, config libkbfs.Config, session idutil.SessionInfo,
	log logger.Logger) (
	newCtx context.Context, newConfig libkbfs.Config,
	configShutdown func(context.Context) error, err error) {
	configLocal, ok := config.(*libkbfs.ConfigLocal)
	if !ok {
		panic(fmt.Sprintf("Wrong config type: %T", config))
	}

	newConfig = libkbfs.ConfigAsUserWithMode(
		configLocal, session.Name, libkbfs.InitSingleOp)

	kbCtx := config.KbContext()
	params, err := Params(kbCtx, config.StorageRoot(), session.UID)
	if err != nil {
		return nil, nil, nil, err
	}
	newConfig.(*libkbfs.ConfigLocal).SetStorageRoot(params.StorageRoot)

	mdserver, err := libkbfs.MakeDiskMDServer(config, params.StorageRoot)
	if err != nil {
		return nil, nil, nil, err
	}
	newConfig.SetMDServer(mdserver)

	bserver := libkbfs.MakeDiskBlockServer(config, params.StorageRoot)
	newConfig.SetBlockServer(bserver)

	newCtx, err = libcontext.NewContextWithCancellationDelayer(
		libkbfs.CtxWithRandomIDReplayable(
			ctx, ctxIDKey, ctxOpID, newConfig.MakeLogger("")))
	if err != nil {
		return nil, nil, nil, err
	}

	return newCtx, newConfig, func(context.Context) error {
		mdserver.Shutdown()
		bserver.Shutdown(ctx)
		return nil
	}, nil
}

func writeFile(
	ctx context.Context, t *testing.T, kbfsOps libkbfs.KBFSOps, i *Indexer,
	rootNode, node libkbfs.Node, name, text string, newFile bool) {
	oldMD, err := kbfsOps.GetNodeMetadata(ctx, node)
	require.NoError(t, err)

	err = kbfsOps.Write(ctx, node, []byte(text), 0)
	require.NoError(t, err)
	err = kbfsOps.SyncAll(ctx, rootNode.GetFolderBranch())
	require.NoError(t, err)
	err = kbfsOps.SyncFromServer(ctx, rootNode.GetFolderBranch(), nil)
	require.NoError(t, err)

	t.Log("Wait for index to load")
	err = i.waitForIndex(ctx)
	require.NoError(t, err)

	t.Log("Index the file")
	namePPS := data.NewPathPartString(name, nil)
	if newFile {
		ids, err := i.blocksDb.GetNextDocIDs(1)
		require.NoError(t, err)
		usedDocID, err := i.indexChild(ctx, rootNode, "", namePPS, ids[0], 1)
		require.NoError(t, err)
		require.True(t, usedDocID)
	} else {
		err := i.updateChild(
			ctx, rootNode, "", namePPS, oldMD.BlockInfo.BlockPointer, 1)
		require.NoError(t, err)
	}

	err = kbfsOps.SyncAll(ctx, rootNode.GetFolderBranch())
	require.NoError(t, err)
	err = kbfsOps.SyncFromServer(ctx, rootNode.GetFolderBranch(), nil)
	require.NoError(t, err)
}

func writeNewFile(
	ctx context.Context, t *testing.T, kbfsOps libkbfs.KBFSOps, i *Indexer,
	rootNode libkbfs.Node, name, text string) {
	t.Logf("Making file %s", name)
	namePPS := data.NewPathPartString(name, nil)
	n, _, err := kbfsOps.CreateFile(
		ctx, rootNode, namePPS, false, libkbfs.NoExcl)
	require.NoError(t, err)
	writeFile(ctx, t, kbfsOps, i, rootNode, n, name, text, true)
}

func testSearch(t *testing.T, i *Indexer, word string, expected int) {
	query := bleve.NewQueryStringQuery(word)
	request := bleve.NewSearchRequest(query)
	result, err := i.index.Search(request)
	require.NoError(t, err)
	require.Len(t, result.Hits, expected)
}

func TestIndexFile(t *testing.T) {
	ctx := libcontext.BackgroundContextWithCancellationDelayer()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	config := libkbfs.MakeTestConfigOrBust(t, "user1", "user2")
	defer libkbfs.CheckConfigAndShutdown(ctx, t, config)

	tempdir, err := ioutil.TempDir("", "indexTest")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)
	config.SetStorageRoot(tempdir)

	i, err := newIndexerWithConfigInit(
		config, testInitConfig, kvstoreNamePrefix+"_TestIndexFile")
	require.NoError(t, err)
	defer func() {
		err := i.Shutdown(ctx)
		require.NoError(t, err)
	}()

	h, err := tlfhandle.ParseHandle(
		ctx, config.KBPKI(), config.MDOps(), nil, "user1", tlf.Private)
	require.NoError(t, err)
	kbfsOps := config.KBFSOps()
	rootNode, _, err := kbfsOps.GetOrCreateRootNode(ctx, h, data.MasterBranch)
	require.NoError(t, err)
	const aText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
	const aName = "a"
	writeNewFile(ctx, t, kbfsOps, i, rootNode, aName, aText)
	const bHTML = "Mauris et <a href=neque>sit</a> amet nisi " +
		"<b>condimentum</b> fringilla vel non augue"
	writeNewFile(ctx, t, kbfsOps, i, rootNode, "b.html", bHTML)

	t.Log("Search for plaintext")
	testSearch(t, i, "dolor", 1)

	t.Log("Search for lower-case")
	testSearch(t, i, "lorem", 1)

	t.Log("Search for html")
	testSearch(t, i, "condimentum", 1)

	t.Log("Search for word in html tag, which shouldn't be indexed")
	testSearch(t, i, "neque", 0)

	t.Log("Search for shared word")
	testSearch(t, i, "sit", 2)

	t.Log("Re-index a file using the same docID")
	aNamePPS := data.NewPathPartString(aName, nil)
	aNode, _, err := kbfsOps.Lookup(ctx, rootNode, aNamePPS)
	require.NoError(t, err)
	const aNewText = "Ut feugiat dolor in tortor viverra, ac egestas justo " +
		"tincidunt."
	writeFile(ctx, t, kbfsOps, i, rootNode, aNode, aName, aNewText, false)

	t.Log("Search for old and new words")
	testSearch(t, i, "dolor", 1) // two hits in same doc
	testSearch(t, i, "tortor", 1)

	t.Log("Add a hit in a filename")
	const dText = "Cras volutpat mi in purus interdum, sit amet luctus " +
		"velit accumsan."
	const dName = "dolor.txt"
	writeNewFile(ctx, t, kbfsOps, i, rootNode, dName, dText)
	testSearch(t, i, "dolor", 2)

	t.Log("Rename the file")
	const newDName = "neque.txt"
	newDNamePPS := data.NewPathPartString(newDName, nil)
	err = kbfsOps.Rename(
		ctx, rootNode, data.NewPathPartString(dName, nil), rootNode,
		newDNamePPS)
	require.NoError(t, err)
	err = i.renameChild(ctx, rootNode, "", newDNamePPS, 1)
	require.NoError(t, err)
	err = kbfsOps.SyncAll(ctx, rootNode.GetFolderBranch())
	require.NoError(t, err)
	err = kbfsOps.SyncFromServer(ctx, rootNode.GetFolderBranch(), nil)
	require.NoError(t, err)
	testSearch(t, i, "dolor", 1)
	testSearch(t, i, "neque", 1)

	t.Log("Delete a file")
	md, err := kbfsOps.GetNodeMetadata(ctx, aNode)
	require.NoError(t, err)
	err = kbfsOps.RemoveEntry(ctx, rootNode, aNamePPS)
	require.NoError(t, err)
	err = i.deleteFromUnrefs(
		ctx, rootNode.GetFolderBranch().Tlf,
		[]data.BlockPointer{md.BlockInfo.BlockPointer})
	require.NoError(t, err)
	err = kbfsOps.SyncAll(ctx, rootNode.GetFolderBranch())
	require.NoError(t, err)
	err = kbfsOps.SyncFromServer(ctx, rootNode.GetFolderBranch(), nil)
	require.NoError(t, err)
	testSearch(t, i, "tortor", 0)
}

func TestFullIndexSyncedTlf(t *testing.T) {
	ctx := libcontext.BackgroundContextWithCancellationDelayer()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	config := libkbfs.MakeTestConfigOrBust(t, "user1", "user2")
	defer libkbfs.CheckConfigAndShutdown(ctx, t, config)

	tempdir, err := ioutil.TempDir("", "indexTest")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)
	config.SetStorageRoot(tempdir)

	err = config.EnableDiskLimiter(tempdir)
	require.NoError(t, err)
	config.SetDiskCacheMode(libkbfs.DiskCacheModeLocal)
	err = config.MakeDiskBlockCacheIfNotExists()
	require.NoError(t, err)

	i, err := newIndexerWithConfigInit(
		config, testInitConfig, kvstoreNamePrefix+"_TestFullIndexSyncedTlf")
	require.NoError(t, err)
	defer func() {
		err := i.Shutdown(ctx)
		require.NoError(t, err)
	}()

	h, err := tlfhandle.ParseHandle(
		ctx, config.KBPKI(), config.MDOps(), nil, "user1", tlf.Private)
	require.NoError(t, err)
	kbfsOps := config.KBFSOps()
	rootNode, _, err := kbfsOps.GetOrCreateRootNode(ctx, h, data.MasterBranch)
	require.NoError(t, err)

	t.Log("Create two dirs with two files each")
	mkfiles := func(dirName, text1, text2 string) {
		dirNamePPS := data.NewPathPartString(dirName, nil)
		dirNode, _, err := kbfsOps.CreateDir(ctx, rootNode, dirNamePPS)
		require.NoError(t, err)
		f1Name := dirName + "_file1"
		f1NamePPS := data.NewPathPartString(f1Name, nil)
		f1Node, _, err := kbfsOps.CreateFile(
			ctx, dirNode, f1NamePPS, false, libkbfs.NoExcl)
		require.NoError(t, err)
		err = kbfsOps.Write(ctx, f1Node, []byte(text1), 0)
		require.NoError(t, err)
		f2Name := dirName + "_file2"
		f2NamePPS := data.NewPathPartString(f2Name, nil)
		f2Node, _, err := kbfsOps.CreateFile(
			ctx, dirNode, f2NamePPS, false, libkbfs.NoExcl)
		require.NoError(t, err)
		err = kbfsOps.Write(ctx, f2Node, []byte(text2), 0)
		require.NoError(t, err)
	}

	aName := "alpha"
	const a1Text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
	const a2Text = "Mauris et neque sit amet nisi condimentum fringilla " +
		"vel non augue"
	mkfiles(aName, a1Text, a2Text)

	bName := "beta"
	const b1Text = "Ut feugiat dolor in tortor viverra, ac egestas justo " +
		"tincidunt."
	const b2Text = "Cras volutpat mi in purus interdum, sit amet luctus " +
		"velit accumsan."
	mkfiles(bName, b1Text, b2Text)
	err = kbfsOps.SyncAll(ctx, rootNode.GetFolderBranch())
	require.NoError(t, err)
	err = kbfsOps.SyncFromServer(ctx, rootNode.GetFolderBranch(), nil)
	require.NoError(t, err)

	t.Log("Wait for index to load")
	err = i.waitForIndex(ctx)
	require.NoError(t, err)

	t.Log("Enable syncing")
	_, err = kbfsOps.SetSyncConfig(
		ctx, rootNode.GetFolderBranch().Tlf, keybase1.FolderSyncConfig{
			Mode: keybase1.FolderSyncMode_ENABLED,
		})
	require.NoError(t, err)
	err = i.waitForSyncs(ctx)
	require.NoError(t, err)

	t.Log("Check searches")
	testSearch(t, i, "dolor", 2)
	testSearch(t, i, "feugiat", 1)
	testSearch(t, i, aName, 3) // Child nodes have "alpha" in their name too
	testSearch(t, i, "file1", 2)
}
