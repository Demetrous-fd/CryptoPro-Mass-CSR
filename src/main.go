package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	cades "github.com/Demetrous-fd/CryptoPro-Adapter"
	"golang.org/x/exp/slog"
)

var (
	debugFlag    *bool
	skipRootFlag *bool
	versionFlag  *bool
	csrFileFlag  *string
)

func init() {
	debugFlag = flag.Bool("debug", false, "Включить отладочную информацию")
	skipRootFlag = flag.Bool("skip-root", false, "Пропустить установку корневого сертификата тестового УЦ")
	csrFileFlag = flag.String("file", "csr.json", "JSON файл с csr запросами")
	versionFlag = flag.Bool("version", false, "Отобразить версию программы")
}

type CSRsBlock struct {
	Requests []CsrParams
}

func main() {
	flag.Usage = defaultHelpUsage
	flag.Parse()

	if *versionFlag {
		fmt.Println("Masscsr version 0.0.0")
		fmt.Println("Repository: https://github.com/Demetrous-fd/CryptoPro-Mass-CSR")
		fmt.Println("Maintainer: Lazydeus (Demetrous-fd)")
		return
	}

	loggerLevel := &slog.LevelVar{}
	if *debugFlag {
		loggerLevel.Set(slog.LevelDebug)
	}
	loggerOptions := &slog.HandlerOptions{
		AddSource: *debugFlag,
		Level:     loggerLevel,
	}

	logFile, err := os.Create("logger.log")
	if err != nil {
		slog.Error(err.Error())
		return
	}
	defer logFile.Close()

	w := io.MultiWriter(os.Stdout, logFile)
	var handler slog.Handler = slog.NewTextHandler(w, loggerOptions)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	if _, err := os.Stat(*csrFileFlag); errors.Is(err, os.ErrNotExist) {
		slog.Error(fmt.Sprintf("File: '%s' not exists", *csrFileFlag))
		return
	}

	file, err := os.Open(*csrFileFlag)
	if err != nil {
		slog.Error(err.Error())
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	var csrsBlock CSRsBlock
	err = json.Unmarshal(data, &csrsBlock)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	cadesLocal, err := cades.NewCades()
	if err != nil {
		slog.Error(err.Error())
		return
	}
	defer cadesLocal.Close()

	if !*skipRootFlag {
		InstallRoot(cadesLocal)
	}

	x509 := cades.CreateX509EnrollmentRoot(cadesLocal)

	for _, csr := range csrsBlock.Requests {
		ExecuteCsrInstall(x509, &csr)
	}
}
