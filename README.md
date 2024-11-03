# CryptoPro Mass CSR

Приложение для создания тестовых электронных подписей КриптоПро на станциях с Windows и Linux.

[Ссылка на скачивание последней версии программы](https://github.com/Demetrous-fd/CryptoPro-Mass-CSR/releases/latest)

### Требования для запуска

- КриптоПро ЭЦП 4-5 версии
- [КриптоПро ЭЦП Browser plug-in](https://www.cryptopro.ru/products/cades/plugin)

### Использование

1. Создайте json файл `csr.json` с описанием csr запросов

```json
{
    "requests": [
        {
            "providerName": "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",  // Необязательный параметр
            "container": {
                "name": "Test_IvanIvanov",  // Необязательный параметр, значение по умолчанию Test_{uuid4}
                "exportable": true,  // Необязательный параметр, значение по умолчанию false
                "keyProtection": 0,  // Необязательный параметр, значение по умолчанию 0
                "keySpec": 1, // Необязательный параметр, значение по умолчанию 1 (AT_KEYEXCHANGE)
                "pin": "1"  // Необязательный параметр
            },  // Необязательный параметр
            "dn": {
                "CN": "Иванов Иван",
                "2.5.4.4": "Иванов",
                "2.5.4.42": "Иван",
                "2.5.4.12": "Директор департамента",
                "2.5.4.9": "ул. Ивановская 99",
                "2.5.4.11": "Отдел маркетинга",
                "O": "ОАО \"Серьезные люди\"",
                "2.5.4.7": "г. Москва",
                "2.5.4.8": "77 г. Москва",
                "C": "RU",
                "1.2.840.113549.1.9.1": "example@domain.ru",
                "1.3.6.1.4.1.311.20.2.3": "IvanIvanov@upn.domain.lan",
                "1.2.643.3.131.1.1": "000000000076",
                "1.2.643.100.1": "0000000000024",
                "1.2.643.100.3": "00000000052"
            },  // Обязательный параметр
            "extensionEKU": [
                "1.3.6.1.5.5.7.3.2",
                "1.3.6.1.5.5.7.3.4"
            ],  // Необязательный параметр, значение по умолчанию "1.3.6.1.5.5.7.3.2"
            "san": {
                "1.3.6.1.4.1.311.20.2.3": [
                    "IvanIvanov@upn.domain.lan",
                    "IvanIvanov@domain.ru"
                ]
            },  // Необязательный параметр, доступен с версии КриптоПро CSP 5.0 R4 (сборка 5.0.13300 Uroboros)
                // В данный момент можно добавить только OtherName(oid, value)
            "ekuKeyUsageFlags": 240  // Необязательный параметр, значение по умолчанию 240
        },
        {
            "container": {
                "name": "Test_Petrov",
                "exportable": true
            },
            "dn": {
                "CN": "Петров Пётр",
                "2.5.4.4": "Петров",
                "2.5.4.42": "Пётр",
                "2.5.4.12": "Зам.Директора департамента",
                "2.5.4.9": "ул. Ивановская 99",
                "2.5.4.11": "Отдел маркетинга",
                "O": "ОАО \"Серьезные люди\"",
                "2.5.4.7": "г. Москва",
                "2.5.4.8": "77 г. Москва",
                "C": "RU",
                "1.2.840.113549.1.9.1": "example@domain.ru",
                "1.2.643.3.131.1.1": "000000000076",
                "1.2.643.100.1": "0000000000024",
                "1.2.643.100.3": "00000000052"
            }
        }
    ],
    "params": {
        "flat": false,
        "skipRoot": false,
        "skipStore": false,
        "skipCSRRequest": false,
        "outputFolder": "test_certs",
        "ca": {
            "url": "testgost2012.cryptopro.ru"
        }
    }  // Аргументы запуска masscsr, необязательный параметр
}
```

2. Запустите masscsr
3. В папке `test_certs/{container.name}` сохраняется результат csr запроса: `{container.name}.(container;csr;cer;pfx)`
4. В файле `test_certs/info.json` находится информация о сгенерированных ЭЦП
```json
[
	{
		"name": "Test_IvanIvanov",
		"thumbprint": "f59668374c3e8f2d444402452aa113c9d78bbbbb",
		"containerName": "\\\\.\\REGISTRY\\Test_IvanIvanov",
		"containerFolder": "asdf234s.000",
		"containerPin": "1",
		"exportable": true
	},
	{
		"name": "Test_Petrov",
		"thumbprint": "1e1d7ee1e81774a8a06b0bd5aa0c80bffd451111",
		"containerName": "\\\\.\\REGISTRY\\Test_Petrov",
		"containerFolder": "bdq9javv.000",
		"exportable": true
	}
]
```

### Аргументы запуска

```shell
Использование:
  masscsr [flags]

Flags:
  -ca-url string
        Доменное имя УЦ (default "testgost2012.cryptopro.ru")
  -debug
        Включить отладочную информацию
  -file string
        JSON файл с csr запросами (default "csr.json")
  -flat
        Не сохранять контейнер/сертификат/csr запрос в отдельной папке
  -folder string
        Директория сохранения контейнеров/сертификатов/csr запросов (default "test_certs")
  -skip-csr-request
        Пропустить отправку запроса на выпуск сертификата
  -skip-root
        Пропустить этап загрузки и установки корневого сертификата УЦ
  -skip-store
        Не сохранять корневой сертификата УЦ и ЭЦП в хранилище
  -version
        Отобразить версию программы
```

### Поддержка проекта

Если вы обнаружили ошибку или хотите предложить идею для улучшения проекта, создайте issue.

Если у вас есть возможность и желание внести улучшения в проект, отправляйте pull request.
