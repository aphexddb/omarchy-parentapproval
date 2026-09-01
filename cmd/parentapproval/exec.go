package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
)

var execCommandContext = func(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

var execCommandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

var execStart = func(name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

var binExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func jsonMarshal(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
