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

func TestGetApiTags(t *testing.T) {
	t.SetTimeout(40 * 60 * 1000) // 40 minutes timeout

	baseUrl := os.Getenv("BRIGHT_TARGET_URL")

	// Define the security tests to run
	tests := []string{"excessive_data_exposure", "csrf", "improper_asset_management", "insecure_tls_configuration"}

	// Run the security scan
	if err := runner.CreateScan(sectester.ScanConfig{
		Tests:               tests,
		AttackParamLocations: []sectester.AttackParamLocation{sectester.AttackParamLocation.QUERY},
		Threshold:           sectester.Severity.CRITICAL,
		Timeout:             40 * 60 * 1000, // 40 minutes timeout
	}).Run(sectester.ScanRunConfig{
		Method: sectester.HttpMethod.GET,
		URL:    baseUrl + "/api/tags",
	}); err != nil {
		t.Fatalf("Security scan failed: %v", err)
	}
}