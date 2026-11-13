//go:build !goexperiment.runtimesecret

package hs

func secretDo(f func()) { f() }

const secretEnabled = false
