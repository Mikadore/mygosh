//go:build linux || darwin || freebsd || openbsd || netbsd

package process

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/command"
	"github.com/stretchr/testify/require"
)

func TestRunnerExecPreservesStreamsEnvironmentAndStatus(t *testing.T) {
	spec := currentIdentitySpec(t, "printf '%s' \"$HOME|$LANG\"; printf stderr >&2; exit 7")
	spec.RequestedEnvironment = map[string]string{"LANG": "C.UTF-8"}

	running, err := (Runner{}).Start(context.Background(), spec)
	require.NoError(t, err)
	stdout, stderr := readOutputs(running)
	result := running.Wait()
	require.Equal(t, 7, result.Status)
	require.Equal(t, spec.WorkingDirectory+"|C.UTF-8", string(<-stdout))
	require.Equal(t, "stderr", string(<-stderr))
	require.Equal(t, result, running.Wait(), "wait result must be stable and reaped exactly once")
}

func TestRunnerNonPTYStdinEOF(t *testing.T) {
	spec := currentIdentitySpec(t, "cat")
	running, err := (Runner{}).Start(context.Background(), spec)
	require.NoError(t, err)
	stdout, stderr := readOutputs(running)
	raw := []byte{0x00, 0xff, 'x', '\n'}
	require.NoError(t, running.WriteStdin(context.Background(), raw))
	require.NoError(t, running.CloseStdin())
	require.Equal(t, ExitResult(0), exitSummary(running.Wait()))
	require.Equal(t, raw, <-stdout)
	require.Empty(t, <-stderr)
}

func TestRunnerPTYMergesOutputAndResizes(t *testing.T) {
	spec := currentIdentitySpec(t, "read line; stty size; printf 'out'; printf 'err' >&2")
	spec.PTY = &PTYSpec{Terminal: "xterm", Rows: 24, Columns: 80}
	running, err := (Runner{}).Start(context.Background(), spec)
	require.NoError(t, err)
	require.Nil(t, running.Stderr())

	output := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(running.Stdout())
		output <- data
	}()
	require.NoError(t, running.Resize(context.Background(), command.WindowSize{Rows: 40, Columns: 100}))
	require.NoError(t, running.WriteStdin(context.Background(), []byte("go\n")))
	result := running.Wait()
	require.Empty(t, result.RuntimeFailure)
	require.Equal(t, 0, result.Status)
	data := <-output
	require.Contains(t, string(data), "40 100")
	require.Contains(t, string(data), "outerr")
}

func TestRunnerReportsSignal(t *testing.T) {
	spec := currentIdentitySpec(t, "kill -TERM $$")
	running, err := (Runner{}).Start(context.Background(), spec)
	require.NoError(t, err)
	stdout, stderr := readOutputs(running)
	require.NoError(t, running.CloseStdin())
	result := running.Wait()
	<-stdout
	<-stderr
	require.Equal(t, "SIGTERM", result.Signal)
}

func TestRunnerRejectsIdentityMismatchBeforeStart(t *testing.T) {
	spec := currentIdentitySpec(t, "true")
	if os.Geteuid() == 0 {
		t.Skip("root is deliberately allowed to select explicit credentials")
	}
	spec.UID++
	_, err := (Runner{}).Start(context.Background(), spec)
	require.ErrorContains(t, err, "identity mismatch")
}

func TestRunnerCancellationTerminatesProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	spec := currentIdentitySpec(t, "sleep 30 & child=$!; echo $child; wait")
	spec.TerminationGrace = 100 * time.Millisecond
	running, err := (Runner{}).Start(ctx, spec)
	require.NoError(t, err)

	reader := bufio.NewReader(running.Stdout())
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	childPID, err := strconv.Atoi(strings.TrimSpace(line))
	require.NoError(t, err)

	start := time.Now()
	cancel(context.Canceled)
	result := running.Wait()
	require.Less(t, time.Since(start), 2*time.Second)
	require.NotEmpty(t, result.Signal)

	deadline := time.Now().Add(2 * time.Second)
	for {
		err = syscall.Kill(childPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant process %d survived cancellation", childPID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunnerCleansResidualProcessGroupAfterLeaderExit(t *testing.T) {
	spec := currentIdentitySpec(t, "sleep 30 & echo $!")
	spec.TerminationGrace = 100 * time.Millisecond
	running, err := (Runner{}).Start(context.Background(), spec)
	require.NoError(t, err)

	line, err := bufio.NewReader(running.Stdout()).ReadString('\n')
	require.NoError(t, err)
	childPID, err := strconv.Atoi(strings.TrimSpace(line))
	require.NoError(t, err)
	require.Equal(t, 0, running.Wait().Status)

	deadline := time.Now().Add(2 * time.Second)
	for {
		err = syscall.Kill(childPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background descendant %d survived command completion", childPID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSpecRejectsRequestedTrustedEnvironmentReplacement(t *testing.T) {
	spec := currentIdentitySpec(t, "true")
	spec.RequestedEnvironment = map[string]string{"PATH": "/tmp"}
	_, err := (Runner{}).Start(context.Background(), spec)
	require.ErrorContains(t, err, "cannot replace trusted PATH")
}

func currentIdentitySpec(t *testing.T, script string) Spec {
	t.Helper()
	home := t.TempDir()
	groups, err := os.Getgroups()
	require.NoError(t, err)
	supplementary := make([]uint32, 0, len(groups))
	for _, group := range groups {
		if group != os.Getegid() {
			supplementary = append(supplementary, uint32(group))
		}
	}
	return Spec{
		Executable:       "/bin/sh",
		Argv:             []string{"sh", "-c", script},
		WorkingDirectory: home,
		TrustedEnvironment: map[string]string{
			"HOME":    home,
			"USER":    "test-user",
			"LOGNAME": "test-user",
			"SHELL":   "/bin/sh",
			"PATH":    "/usr/local/bin:/usr/bin:/bin",
		},
		UID:                 uint32(os.Geteuid()),
		GID:                 uint32(os.Getegid()),
		SupplementaryGroups: supplementary,
	}
}

func readOutputs(running command.RunningProcess) (<-chan []byte, <-chan []byte) {
	stdout := make(chan []byte, 1)
	stderr := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(running.Stdout())
		stdout <- data
	}()
	go func() {
		if running.Stderr() == nil {
			stderr <- nil
			return
		}
		data, _ := io.ReadAll(running.Stderr())
		stderr <- data
	}()
	return stdout, stderr
}

type ExitResult int

func exitSummary(result command.ExitResult) ExitResult {
	if result.Signal != "" || result.RuntimeFailure != "" {
		return -1
	}
	return ExitResult(result.Status)
}
