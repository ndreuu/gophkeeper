# GophKeeper

Клиент-серверный менеджер приватных данных с CLI-клиентом. Поддерживает регистрацию, вход и синхронизацию нескольких клиентов одного пользователя.

## Запуск

```sh
make build VERSION=1.0.0
make cert
docker compose up -d --wait postgres
GOPHKEEPER_DATABASE_DSN='postgres://gophkeeper:development-only-password@localhost:5432/gophkeeper?sslmode=disable' ./bin/server
```


```sh
export GOPHKEEPER_CA_FILE="$PWD/certs/server.crt"
./bin/gophkeeper register -login alice
```

## Записи и команды

Создать `secret.json` с одним объектом нужного типа:

```json
{"kind":"login","title":"Site","login":{"login":"alice","password":"example-password"},"metadata":{"site":"https://example.org"}}
```

```json
{"kind":"text","title":"Note","text":"Private note","metadata":{"category":"personal"}}
```

```json
{"kind":"binary","title":"File","binary":{"name":"file.bin","data":"AAECAw=="},"metadata":{"description":"example file"}}
```

```json
{"kind":"card","title":"Card","card":{"number":"0000000000000000","holder":"TEST USER","expiry":"12/30","cvv":"000"},"metadata":{"bank":"Example"}}
```

`metadata` — необязательный словарь строк, `binary.data` — данные в base64. Входной JSON содержит секреты.

```sh
./bin/gophkeeper put -file secret.json
./bin/gophkeeper list
./bin/gophkeeper get <RECORD_ID>
./bin/gophkeeper sync
./bin/gophkeeper version
```

```sh
./bin/gophkeeper put -file secret.json -id <RECORD_ID> -revision 1
./bin/gophkeeper delete -revision 2 <RECORD_ID>
```
