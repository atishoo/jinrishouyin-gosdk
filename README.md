# 今日收银 SDK for golang
[![Go Reference](https://pkg.go.dev/badge/github.com/atishoo/jinrishouyin-gosdk.svg)](https://pkg.go.dev/github.com/atishoo/jinrishouyin-gosdk)

今日收银 golang 版本的 sdk

## 使用
```shell
go get -u github.com/atishoo/jinrishouyin-gosdk
```

## 初始化
```golang
var client = shouyin.NewShouyinTodayClient("appid", "private cert")
```