module github.com/diver-osint-ctf/ctfd-flagformat-checker/e2e

go 1.24.1

require github.com/diver-osint-ctf/ctfd-plugin-e2e v0.0.0-00010101000000-000000000000

require github.com/ledongthuc/pdf v0.0.0-20250511090121-5959a4027728 // indirect

// テスト実行は ctfd-plugin-e2e リポジトリのルートから行う前提。
// プラグイン単体で `cd e2e && go test` する場合はこの replace パスを書き換える。
replace github.com/diver-osint-ctf/ctfd-plugin-e2e => ../../..
