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
	skipStoreFlag    *bool
	versionFlag      *bool
	csrFileFlag      *string
	outputFolderFlag *string
)

func init() {
	debugFlag = flag.Bool("debug", false, "Включить отладочную информацию")
	versionFlag = flag.Bool("version", false, "Отобразить версию программы")
	skipRootFlag = flag.Bool("skip-root", false, "Пропустить этап загрузки и установки корневого сертификата тестового УЦ")
	skipStoreFlag = flag.Bool("skip-store", false, "Не сохранять корневой сертификата УЦ и ЭЦП в хранилище")
	flatFlag = flag.Bool("flat", false, "Не сохранять контейнер/сертификат/csr запрос в отдельной папке")

	csrFileFlag = flag.String("file", "csr.json", "JSON файл с csr запросами")
	outputFolderFlag = flag.String("folder", "test_certs", "Директория сохранения контейнеров/сертификатов/csr запросов")
}

type Config struct {
	Requests []CsrParams
	Params   *Params
}

type Params struct {
	Flat         *bool  `json:"flat"`
	SkipRoot     *bool  `json:"skipRoot"`
	SkipStore    *bool  `json:"skipStore"`
	OutputFolder string `json:"outputFolder"`
}

func main() {
	flag.Usage = defaultHelpUsage
	flag.Parse()

	if *versionFlag {
		fmt.Println("Masscsr version 0.2.0")
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

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	if config.Params.Flat == nil {
		config.Params.Flat = flatFlag
	}
	if config.Params.SkipRoot == nil {
		config.Params.SkipRoot = skipRootFlag
	}
	if config.Params.SkipStore == nil {
		config.Params.SkipStore = skipStoreFlag
	}
	if config.Params.OutputFolder == "" {
		config.Params.OutputFolder = *outputFolderFlag
	}

	if config.Params.OutputFolder == "" {
		if _, err := os.Stat(*outputFolderFlag); errors.Is(err, os.ErrNotExist) {
			os.Mkdir(*outputFolderFlag, os.ModePerm)
		}
	} else {
		if _, err := os.Stat(config.Params.OutputFolder); errors.Is(err, os.ErrNotExist) {
			os.Mkdir(config.Params.OutputFolder, os.ModePerm)
		}
	}

	cadesLocal, err := cades.NewCades()
	if err != nil {
		slog.Error(err.Error())
		return
	}
	defer cadesLocal.Close()

	if !*config.Params.SkipRoot {
		InstallRoot(cadesLocal, config.Params)
	}

	x509 := cades.CreateX509EnrollmentRoot(cadesLocal)

	var containersInfo []ContainerInfo
	for _, csr := range config.Requests {
		info := ExecuteCsrInstall(x509, &csr, config.Params)

		if (info != &ContainerInfo{}) {
			containersInfo = append(containersInfo, *info)
		}
	}

	infoData, err := json.MarshalIndent(containersInfo, "", "\t")
	if err == nil {
		var infoPath string
		if config.Params.OutputFolder == "" {
			infoPath = filepath.Join(*outputFolderFlag, "info.json")
		} else {
			infoPath = filepath.Join(config.Params.OutputFolder, "info.json")
		}

		infoFile, err := os.Create(infoPath)
		if err != nil {
			slog.Error(err.Error())
			return
		}
		defer infoFile.Close()

		infoFile.Write(infoData)
	}
}
