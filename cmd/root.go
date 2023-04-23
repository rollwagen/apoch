/*
Copyright © 2023 rollwagen@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"os"
	"strings"

	apoch "github.com/rollwagen/apoch/pkg"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logLevel string
	skipScan bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "apoch",
	Short: "Run a port scan of all VPC public IPs found in AWS ConfigService",
	Run: func(cmd *cobra.Command, args []string) {
		logger := setupLogger(logLevel)
		apoch.QueryIPsAndScan(logger, skipScan)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&logLevel, "loglevel", "info", "Select log level [\"debug\", \"info\", \"warn\", \"error\"]")
	rootCmd.Flags().BoolVar(&skipScan, "noscan", false, "Only discover public IPs and skip port scanning")
}

func setupLogger(logLevel string) *zap.SugaredLogger {
	zapLogLevel := zapcore.InfoLevel

	switch strings.ToUpper(logLevel) {
	case "ERROR":
		zapLogLevel = zapcore.ErrorLevel
	case "WARN":
		zapLogLevel = zapcore.WarnLevel
	case "DEBUG":
		zapLogLevel = zapcore.DebugLevel
	}

	encoderCfg := zapcore.EncoderConfig{
		MessageKey:  "message",
		LevelKey:    "level",
		TimeKey:     "time",
		EncodeLevel: zapcore.CapitalColorLevelEncoder,
	}

	encoder := zapcore.NewConsoleEncoder(encoderCfg)
	core := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapLogLevel)

	return zap.New(core).Sugar()
}
