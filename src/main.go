package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	cades "github.com/Demetrous-fd/CryptoPro-Adapter"
	"golang.org/x/exp/slog"
)

var (
	debugFlag        *bool
	flatFlag         *bool
	skipRootFlag     *bool
	versionFlag      *bool
	csrFileFlag      *string
	outputFolderFlag *string
)

func init() {
	debugFlag = flag.Bool("debug", false, "Включить отладочную информацию")
	versionFlag = flag.Bool("version", false, "Отобразить версию программы")
	skipRootFlag = flag.Bool("skip-root", false, "Пропустить установку корневого сертификата тестового УЦ")
	flatFlag = flag.Bool("flat", false, "Не сохранять контейнер/сертификат/csr запрос в отдельной папке")

	csrFileFlag = flag.String("file", "csr.json", "JSON файл с csr запросами")
	outputFolderFlag = flag.String("folder", "test_certs", "Директория сохранения контейнеров/сертификатов/csr запросов")
}

type CSRsBlock struct {
	Requests []CsrParams
}

func main() {
	flag.Usage = defaultHelpUsage
	flag.Parse()

	if *versionFlag {
		fmt.Println("Masscsr version 0.1.0")
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

	if _, err := os.Stat(*outputFolderFlag); errors.Is(err, os.ErrNotExist) {
		os.Mkdir(*outputFolderFlag, os.ModePerm)
	}

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

	var containersInfo []ContainerInfo
	for _, csr := range csrsBlock.Requests {
		info := ExecuteCsrInstall(x509, &csr)

		if (info != &ContainerInfo{}) {
			containersInfo = append(containersInfo, *info)
		}
	}

	infoData, err := json.MarshalIndent(containersInfo, "", "\t")
	if err == nil {
		infoPath := filepath.Join(*outputFolderFlag, "info.json")
		infoFile, err := os.Create(infoPath)
		if err != nil {
			slog.Error(err.Error())
			return
		}
		defer infoFile.Close()

		infoFile.Write(infoData)
	}
}
