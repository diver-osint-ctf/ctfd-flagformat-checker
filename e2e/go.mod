module github.com/diver-osint-ctf/ctfd-flagformat-checker/e2e

go 1.23

require github.com/diver-osint-ctf/ctfd-plugin-e2e v0.0.0-00010101000000-000000000000

require gopkg.in/yaml.v3 v3.0.1 // indirect

// テスト実行は ctfd-plugin-e2e リポジトリのルートから行う前提。
// プラグイン単体で `cd e2e && go test` する場合はこの replace パスを書き換える。
replace github.com/diver-osint-ctf/ctfd-plugin-e2e => ../../..
