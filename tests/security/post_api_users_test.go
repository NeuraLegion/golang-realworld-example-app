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

func TestPostApiUsers(t *testing.T) {
	t.Parallel()

	baseUrl := os.Getenv("BRIGHT_TARGET_URL")

	// Set timeout for the test
	t.SetTimeout(40 * 60 * 1000) // 40 minutes

	scan := runner.CreateScan(sectester.ScanConfig{
		Tests:               []string{"sqli", "csrf", "mass_assignment", "excessive_data_exposure", "xss", "secret_tokens"},
		AttackParamLocations: []sectester.AttackParamLocation{sectester.AttackParamLocation.BODY},
	})

	scan.Threshold(sectester.Severity.CRITICAL)
	scan.Timeout(40 * 60 * 1000) // 40 minutes

	err := scan.Run(sectester.ScanRunConfig{
		Method: sectester.HttpMethod.POST,
		Url:    baseUrl + "/api/users",
		Body:   `{"username":"exampleUser","email":"user@example.com","password":"examplePassword"}`,
	})

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
}