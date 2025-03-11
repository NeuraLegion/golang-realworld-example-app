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

func TestGetArticles(t *testing.T) {
	t.SetTimeout(40 * 60 * 1000) // 40 minutes timeout

	baseUrl := os.Getenv("BRIGHT_TARGET_URL")

	scan := runner.CreateScan(sectester.ScanConfig{
		Tests:                []string{"sqli", "excessive_data_exposure", "csrf", "bopla", "business_constraint_bypass"},
		AttackParamLocations: []sectester.AttackParamLocation{sectester.AttackParamLocation.QUERY},
		Threshold:            sectester.Severity.CRITICAL,
		Timeout:              40 * 60 * 1000, // 40 minutes timeout
	})

	if err := scan.Run(sectester.ScanRunConfig{
		Method: sectester.HttpMethod.GET,
		URL:    baseUrl + "/api/articles",
		Query: map[string]string{
			"tag":       "exampleTag",
			"author":    "exampleAuthor",
			"favorited": "exampleUser",
			"limit":     "20",
			"offset":    "0",
		},
	}); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
}