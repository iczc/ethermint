package importer

import (
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"runtime/pprof"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sdkcodec "github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store"
	sdkstore "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/bank"
	"github.com/cosmos/cosmos-sdk/x/params"

	"github.com/cosmos/ethermint/core"
	cryptocodec "github.com/cosmos/ethermint/crypto/ethsecp256k1"
	"github.com/cosmos/ethermint/types"
	"github.com/cosmos/ethermint/x/evm"
	evmtypes "github.com/cosmos/ethermint/x/evm/types"

	ethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	ethcore "github.com/ethereum/go-ethereum/core"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	ethvm "github.com/ethereum/go-ethereum/core/vm"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	ethparams "github.com/ethereum/go-ethereum/params"
	ethrlp "github.com/ethereum/go-ethereum/rlp"

	abci "github.com/tendermint/tendermint/abci/types"
	tmlog "github.com/tendermint/tendermint/libs/log"
	dbm "github.com/tendermint/tm-db"
)

var (
	flagDataDir    string
	flagBlockchain string
	flagCPUProfile string

	genInvestor = ethcmn.HexToAddress("0x756F45E3FA69347A9A973A725E3C98bC4db0b5a0")

	logger = tmlog.NewNopLogger()

	rewardBig8  = big.NewInt(8)
	rewardBig32 = big.NewInt(32)
)

func init() {
	flag.StringVar(&flagCPUProfile, "cpu-profile", "", "write CPU profile")
	flag.StringVar(&flagDataDir, "datadir", "", "test data directory for state storage")
	flag.StringVar(&flagBlockchain, "blockchain", "blockchain", "ethereum block export file (blocks to import)")
	testing.Init()
	flag.Parse()
}

func newTestCodec() *sdkcodec.Codec {
	cdc := sdkcodec.New()

	evmtypes.RegisterCodec(cdc)
	types.RegisterCodec(cdc)
	auth.RegisterCodec(cdc)
	bank.RegisterCodec(cdc)
	sdk.RegisterCodec(cdc)
	cryptocodec.RegisterCodec(cdc)
	sdkcodec.RegisterCrypto(cdc)

	return cdc
}

func cleanup() {
	fmt.Println("cleaning up test execution...")
	os.RemoveAll(flagDataDir)

	if flagCPUProfile != "" {
		pprof.StopCPUProfile()
	}
}

func trapSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		cleanup()
		os.Exit(1)
	}()
}

// nolint: interfacer
func createAndTestGenesis(t *testing.T, cms sdk.CommitMultiStore, ak auth.AccountKeeper, evmKeeper evm.Keeper) {
	genBlock := ethcore.DefaultGenesisBlock()
	ms := cms.CacheMultiStore()
	ctx := sdk.NewContext(ms, abci.Header{}, false, logger)

	// Set the default Ethermint parameters to the parameter keeper store
	evmKeeper.SetParams(ctx, evmtypes.DefaultParams())

	// sort the addresses and insertion of key/value pairs matters
	genAddrs := make([]string, len(genBlock.Alloc))
	i := 0
	for addr := range genBlock.Alloc {
		genAddrs[i] = addr.String()
		i++
	}

	sort.Strings(genAddrs)

	for _, addrStr := range genAddrs {
		addr := ethcmn.HexToAddress(addrStr)
		acc := genBlock.Alloc[addr]

		evmKeeper.AddBalance(ctx, addr, acc.Balance)
		evmKeeper.SetCode(ctx, addr, acc.Code)
		evmKeeper.SetNonce(ctx, addr, acc.Nonce)

		for key, value := range acc.Storage {
			evmKeeper.SetState(ctx, addr, key, value)
		}
	}

	// get balance of one of the genesis account having 400 ETH
	b := evmKeeper.GetBalance(ctx, genInvestor)
	require.Equal(t, "200000000000000000000", b.String())

	// commit the stateDB with 'false' to delete empty objects
	//
	// NOTE: Commit does not yet return the intra merkle root (version)
	_, err := evmKeeper.Commit(ctx, false)
	require.NoError(t, err)

	// persist multi-store cache state
	ms.Write()

	// persist multi-store root state
	cms.Commit()

	// verify account mapper state
	genAcc := ak.GetAccount(ctx, sdk.AccAddress(genInvestor.Bytes()))
	require.NotNil(t, genAcc)

	evmDenom := evmKeeper.GetParams(ctx).EvmDenom
	balance := sdk.NewCoin(evmDenom, genAcc.GetCoins().AmountOf(evmDenom))
	require.Equal(t, sdk.NewIntFromBigInt(b), balance.Amount)
}

func TestImportBlocks(t *testing.T) {
	if flagDataDir == "" {
		flagDataDir = os.TempDir()
	}

	if flagCPUProfile != "" {
		f, err := os.Create(flagCPUProfile)
		require.NoError(t, err, "failed to create CPU profile")

		err = pprof.StartCPUProfile(f)
		require.NoError(t, err, "failed to start CPU profile")
	}

	db := dbm.NewDB("state", dbm.GoLevelDBBackend, flagDataDir)
	defer cleanup()
	trapSignals()

	cdc := newTestCodec()

	cms := store.NewCommitMultiStore(db)

	authStoreKey := sdk.NewKVStoreKey(auth.StoreKey)
	evmStoreKey := sdk.NewKVStoreKey(evmtypes.StoreKey)
	paramsStoreKey := sdk.NewKVStoreKey(params.StoreKey)
	paramsTransientStoreKey := sdk.NewTransientStoreKey(params.TStoreKey)

	// mount stores
	keys := []*sdk.KVStoreKey{authStoreKey, evmStoreKey, paramsStoreKey}
	for _, key := range keys {
		cms.MountStoreWithDB(key, sdk.StoreTypeIAVL, nil)
	}

	cms.MountStoreWithDB(paramsTransientStoreKey, sdk.StoreTypeTransient, nil)

	paramsKeeper := params.NewKeeper(cdc, paramsStoreKey, paramsTransientStoreKey)

	// Set specific subspaces
	authSubspace := paramsKeeper.Subspace(auth.DefaultParamspace)
	evmSubspace := paramsKeeper.Subspace(evmtypes.DefaultParamspace).WithKeyTable(evmtypes.ParamKeyTable())
	ak := auth.NewAccountKeeper(cdc, authStoreKey, authSubspace, types.ProtoAccount)
	evmKeeper := evm.NewKeeper(cdc, evmStoreKey, evmSubspace, ak)

	cms.SetPruning(sdkstore.PruneNothing)

	// load latest version (root)
	err := cms.LoadLatestVersion()
	require.NoError(t, err)

	// set and test genesis block
	createAndTestGenesis(t, cms, ak, evmKeeper)

	// open blockchain export file
	blockchainInput, err := os.Open(flagBlockchain)
	require.Nil(t, err)

	defer func() {
		err := blockchainInput.Close()
		require.NoError(t, err)
	}()

	// ethereum mainnet config
	chainContext := core.NewChainContext()
	vmConfig := ethvm.Config{}
	chainConfig := ethparams.MainnetChainConfig

	// create RLP stream for exported blocks
	stream := ethrlp.NewStream(blockchainInput, 0)
	startTime := time.Now()

	var block ethtypes.Block
	for {
		err = stream.Decode(&block)
		if err == io.EOF {
			break
		}

		require.NoError(t, err, "failed to decode block")

		var (
			usedGas = new(uint64)
			gp      = new(ethcore.GasPool).AddGas(block.GasLimit())
		)

		header := block.Header()
		chainContext.Coinbase = header.Coinbase

		chainContext.SetHeader(block.NumberU64(), header)

		// Create a cached-wrapped multi-store based on the commit multi-store and
		// create a new context based off of that.
		ms := cms.CacheMultiStore()
		ctx := sdk.NewContext(ms, abci.Header{}, false, logger)
		ctx = ctx.WithBlockHeight(int64(block.NumberU64()))

		if chainConfig.DAOForkSupport && chainConfig.DAOForkBlock != nil && chainConfig.DAOForkBlock.Cmp(block.Number()) == 0 {
			applyDAOHardFork(evmKeeper)
		}

		for i, tx := range block.Transactions() {
			evmKeeper.Prepare(ctx, tx.Hash(), block.Hash(), i)

			receipt, gas, err := applyTransaction(
				chainConfig, chainContext, nil, gp, evmKeeper, header, tx, usedGas, vmConfig,
			)
			require.NoError(t, err, "failed to apply tx at block %d; tx: %X; gas %d; receipt:%v", block.NumberU64(), tx.Hash(), gas, receipt)
			require.NotNil(t, receipt)
		}

		// apply mining rewards
		accumulateRewards(chainConfig, evmKeeper, header, block.Uncles())

		// commit stateDB
		_, err := evmKeeper.CommitStateDB.Commit(chainConfig.IsEIP158(block.Number()))
		require.NoError(t, err, "failed to commit StateDB")

		// simulate BaseApp EndBlocker commitment
		ms.Write()
		cms.Commit()

		// block debugging output
		if block.NumberU64() > 0 && block.NumberU64()%1000 == 0 {
			fmt.Printf("processed block: %d (time so far: %v)\n", block.NumberU64(), time.Since(startTime))
		}
	}
}

// accumulateRewards credits the coinbase of the given block with the mining
// reward. The total reward consists of the static block reward and rewards for
// included uncles. The coinbase of each uncle block is also rewarded.
func accumulateRewards(
	config *ethparams.ChainConfig, evmKeeper evm.Keeper,
	header *ethtypes.Header, uncles []*ethtypes.Header,
) {

	// select the correct block reward based on chain progression
	blockReward := ethash.FrontierBlockReward
	if config.IsByzantium(header.Number) {
		blockReward = ethash.ByzantiumBlockReward
	}

	// accumulate the rewards for the miner and any included uncles
	reward := new(big.Int).Set(blockReward)
	r := new(big.Int)

	for _, uncle := range uncles {
		r.Add(uncle.Number, rewardBig8)
		r.Sub(r, header.Number)
		r.Mul(r, blockReward)
		r.Div(r, rewardBig8)
		evmKeeper.CommitStateDB.AddBalance(uncle.Coinbase, r)
		r.Div(blockReward, rewardBig32)
		reward.Add(reward, r)
	}

	evmKeeper.CommitStateDB.AddBalance(header.Coinbase, reward)
}

// ApplyDAOHardFork modifies the state database according to the DAO hard-fork
// rules, transferring all balances of a set of DAO accounts to a single refund
// contract.
// Code is pulled from go-ethereum 1.9 because the StateDB interface does not include the
// SetBalance function implementation
// Ref: https://github.com/ethereum/go-ethereum/blob/52f2461774bcb8cdd310f86b4bc501df5b783852/consensus/misc/dao.go#L74
func applyDAOHardFork(evmKeeper evm.Keeper) {
	// Retrieve the contract to refund balances into
	if !evmKeeper.CommitStateDB.Exist(ethparams.DAORefundContract) {
		evmKeeper.CommitStateDB.CreateAccount(ethparams.DAORefundContract)
	}

	// Move every DAO account and extra-balance account funds into the refund contract
	for _, addr := range ethparams.DAODrainList() {
		evmKeeper.CommitStateDB.AddBalance(ethparams.DAORefundContract, evmKeeper.CommitStateDB.GetBalance(addr))
		evmKeeper.CommitStateDB.SetBalance(addr, new(big.Int))
	}
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
// Function is also pulled from go-ethereum 1.9 because of the incompatible usage
// Ref: https://github.com/ethereum/go-ethereum/blob/52f2461774bcb8cdd310f86b4bc501df5b783852/core/state_processor.go#L88
func applyTransaction(
	config *ethparams.ChainConfig, bc ethcore.ChainContext, author *ethcmn.Address,
	gp *ethcore.GasPool, evmKeeper evm.Keeper, header *ethtypes.Header,
	tx *ethtypes.Transaction, usedGas *uint64, cfg ethvm.Config,
) (*ethtypes.Receipt, uint64, error) {
	msg, err := tx.AsMessage(ethtypes.MakeSigner(config, header.Number))
	if err != nil {
		return nil, 0, err
	}

	// Create a new context to be used in the EVM environment
	blockCtx := ethcore.NewEVMBlockContext(header, bc, author)
	txCtx := ethcore.NewEVMTxContext(msg)

	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := ethvm.NewEVM(blockCtx, txCtx, evmKeeper.CommitStateDB, config, cfg)

	// Apply the transaction to the current state (included in the env)
	execResult, err := ethcore.ApplyMessage(vmenv, msg, gp)
	if err != nil {
		// NOTE: ignore vm execution error (eg: tx out of gas at block 51169) as we care only about state transition errors
		return &ethtypes.Receipt{}, 0, nil
	}

	// Update the state with pending changes
	var intRoot ethcmn.Hash
	if config.IsByzantium(header.Number) {
		err = evmKeeper.CommitStateDB.Finalise(true)
	} else {
		intRoot, err = evmKeeper.CommitStateDB.IntermediateRoot(config.IsEIP158(header.Number))
	}

	if err != nil {
		return nil, execResult.UsedGas, err
	}

	root := intRoot.Bytes()
	*usedGas += execResult.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing whether the root touch-delete accounts.
	receipt := ethtypes.NewReceipt(root, execResult.Failed(), *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = execResult.UsedGas

	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = ethcrypto.CreateAddress(vmenv.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs, err = evmKeeper.CommitStateDB.GetLogs(tx.Hash())
	receipt.Bloom = ethtypes.CreateBloom(ethtypes.Receipts{receipt})
	receipt.BlockHash = evmKeeper.CommitStateDB.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(evmKeeper.CommitStateDB.TxIndex())

	return receipt, execResult.UsedGas, err
}
