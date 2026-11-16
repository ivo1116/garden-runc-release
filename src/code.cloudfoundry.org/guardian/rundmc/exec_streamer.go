package rundmc

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/lager/v3"
)

//counterfeiter:generate . ProcessExecer
type ProcessExecer interface {
	Exec(log lager.Logger, id string, spec garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error)
}

// ExecStreamer streams files by running tar inside the container, for
// runtimes whose containers can't be entered from the host.
type ExecStreamer struct {
	execer  ProcessExecer
	tarPath string
}

func NewExecStreamer(execer ProcessExecer, tarPath string) *ExecStreamer {
	return &ExecStreamer{execer: execer, tarPath: tarPath}
}

func (s *ExecStreamer) StreamIn(log lager.Logger, handle string, spec garden.StreamInSpec) error {
	stderr := new(bytes.Buffer)
	process, err := s.execer.Exec(log, handle, garden.ProcessSpec{
		Path: s.tarPath,
		Args: append([]string{"-x", "-o", "-f", "-"}, changeDirArgs(spec.Path)...),
		Dir:  spec.Path,
		User: streamUser(spec.User),
	}, garden.ProcessIO{
		Stdin:  spec.TarStream,
		Stderr: stderr,
	})
	if err != nil {
		return err
	}

	return waitForTar(process, stderr)
}

func (s *ExecStreamer) StreamOut(log lager.Logger, handle string, spec garden.StreamOutSpec) (io.ReadCloser, error) {
	sourcePath := filepath.Dir(spec.Path)
	compressPath := filepath.Base(spec.Path)
	if strings.HasSuffix(spec.Path, "/") {
		sourcePath = spec.Path
		compressPath = "."
	}

	reader, writer := io.Pipe()
	stderr := new(bytes.Buffer)
	args := append([]string{"-c", "-f", "-"}, changeDirArgs(sourcePath)...)
	process, err := s.execer.Exec(log, handle, garden.ProcessSpec{
		Path: s.tarPath,
		Args: append(args, compressPath),
		Dir:  sourcePath,
		User: streamUser(spec.User),
	}, garden.ProcessIO{
		Stdout: writer,
		Stderr: stderr,
	})
	if err != nil {
		return nil, err
	}

	go func() {
		writer.CloseWithError(waitForTar(process, stderr))
	}()

	return reader, nil
}

func waitForTar(process garden.Process, stderr *bytes.Buffer) error {
	exitCode, err := process.Wait()
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("tar exited with status %d: %s", exitCode, stderr.String())
	}
	return nil
}

func changeDirArgs(dir string) []string {
	if filepath.IsAbs(dir) {
		return []string{"-C", dir}
	}
	return nil
}

func streamUser(user string) string {
	if user == "" {
		return "root"
	}
	return user
}
