package security_test

import (
	"os"
	"testing"

	"github.com/yourorg/sectester"
)

var runner *sectester.SecRunner

func TestMain(m *testing.M) {
	// Initialize SecTester
	runner = sectester.NewSecRunner(sectester.Config{
		Hostname:  os.Getenv("BRIGHT_HOSTNAME"),
		ProjectID: os.Getenv("BRIGHT_PROJECT_ID"),
	})

	// Ensure runner is properly initialized
	if err := runner.Init(); err != nil {
		panic(err)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	runner.Clear()

	os.Exit(code)
}

func TestGetHealth(t *testing.T) {
	t.Parallel()

	baseUrl := os.Getenv("BRIGHT_TARGET_URL")

	tests := []string{
		"csrf",
		"excessive_data_exposure",
		"http_method_fuzzing",
		"insecure_tls_configuration",
		"version_control_systems",
	}

	attackParamLocations := []sectester.AttackParamLocation{
		sectester.AttackParamLocation.HEADER,
	}

	threshold := sectester.Severity.CRITICAL
	timeout := 40 * 60 // 40 minutes in seconds

	if err := runner.CreateScan(sectester.ScanConfig{
		Tests:               tests,
		AttackParamLocations: attackParamLocations,
		Threshold:           threshold,
		Timeout:             timeout,
	}).Run(sectester.ScanRunConfig{
		Method: sectester.HttpMethod.GET,
		Url:    baseUrl + "/health",
	}); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
}
