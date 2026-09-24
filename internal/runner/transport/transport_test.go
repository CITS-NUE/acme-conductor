package transport

import "testing"

func TestFiles(t *testing.T) {
	var s Source = Files{JobPath: "/in/job.json", ResultPath: "/out/result.json"}
	job, err := s.Acquire()
	if err != nil || job.JobPath != "/in/job.json" || job.ResultPath != "/out/result.json" || s.RequiresSignedResults() {
		t.Fatalf("job = %+v, err = %v, signed = %v", job, err, s.RequiresSignedResults())
	}
	if _, err := (Files{JobPath: "/in/job.json"}).Acquire(); err == nil {
		t.Fatal("a result path is required")
	}
}
