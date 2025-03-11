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

func TestGetArticlesBySlug(t *testing.T) {
	t.SetTimeout(40 * 60 * 1000) // 40 minutes timeout

	baseUrl := os.Getenv("BRIGHT_TARGET_URL")

	scan := runner.CreateScan(sectester.ScanConfig{
		Tests:                []string{"excessive_data_exposure", "id_enumeration", "sqli", "csrf", "xss"},
		AttackParamLocations: []sectester.AttackParamLocation{sectester.AttackParamLocation.PATH},
	})

	scan.Threshold(sectester.Severity.CRITICAL)
	scan.Timeout(40 * 60 * 1000) // 40 minutes timeout

	err := scan.Run(sectester.ScanRunConfig{
		Method: sectester.HttpMethod.GET,
		Url:    baseUrl + "/api/articles/sample-slug",
	})

	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}
}