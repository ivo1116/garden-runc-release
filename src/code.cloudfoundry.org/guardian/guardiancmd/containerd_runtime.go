package guardiancmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func (cmd *CommonCommand) useContainerdRuntime() bool {
	return cmd.Containerd.Runtime != ""
}

func (cmd *CommonCommand) useContainerdForProcesses() bool {
	return cmd.Containerd.UseContainerdForProcesses || cmd.useContainerdRuntime()
}

func (cmd *CommonCommand) ValidateContainerdRuntime() error {
	if !cmd.useContainerdRuntime() {
		return nil
	}

	if !cmd.useContainerd() {
		return errors.New("--containerd-runtime requires containerd mode (--containerd-socket)")
	}

	if cmd.CPUThrottling.Enabled {
		return errors.New("--containerd-runtime cannot be combined with --enable-cpu-throttling")
	}

	if cmd.Containerd.RuntimeTarPath == "" {
		return errors.New("--containerd-runtime requires --containerd-runtime-tar-path")
	}

	runtime := cmd.Containerd.Runtime
	if !filepath.IsAbs(runtime) {
		return nil
	}

	info, err := os.Stat(runtime)
	if err != nil {
		return fmt.Errorf("containerd runtime: %w", err)
	}

	if info.IsDir() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("containerd runtime %s is not an executable file", runtime)
	}

	return nil
}
