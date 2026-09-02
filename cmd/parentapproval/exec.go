package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
)

var execCommandContext = func(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if isDisplayHelper(name) {
		applyGraphicalSession(cmd)
	}
	return cmd.Run()
}

var execCommandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	applyGraphicalSession(cmd)
	out, err := cmd.Output()
	return string(out), err
}

var execStart = func(name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(name, args...)
	applyGraphicalSession(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func isDisplayHelper(name string) bool {
	switch filepath.Base(name) {
	case "omarchy-shell", "omarchy-notification-send":
		return true
	}
	return false
}

var binExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func jsonMarshal(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
