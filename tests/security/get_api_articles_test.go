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

func TestGetApiArticles(t *testing.T) {
	t.SetTimeout(40 * 60 * 1000) // 40 minutes timeout

	baseUrl := os.Getenv("BRIGHT_TARGET_URL")

	scan := runner.CreateScan(sectester.ScanConfig{
		Tests:                []string{"sqli", "excessive_data_exposure", "csrf", "mass_assignment", "bopla"},
		AttackParamLocations: []sectester.AttackParamLocation{sectester.AttackParamLocation.QUERY},
	})

	scan.Threshold(sectester.Severity.CRITICAL)
	scan.Timeout(40 * 60 * 1000) // 40 minutes timeout

	err := scan.Run(sectester.ScanRunConfig{
		Method: sectester.HttpMethod.GET,
		Url:    baseUrl + "/api/articles",
		Query: map[string]string{
			"tag":       "example-tag",
			"author":    "example-author",
			"favorited": "example-user",
			"limit":     "20",
			"offset":    "0",
		},
	})

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
}