//go:build !darwin && !linux

package service

import "errors"

var errUnsupported = errors.New("the boot service is only supported on macOS and Linux")

func UnitPath() string               { return "" }
func SystemStoreDir() string         { return "" }
func Install(Config) (string, error) { return "", errUnsupported }
func Uninstall() (string, error)     { return "", errUnsupported }
func Status() (string, error)        { return "", errUnsupported }
