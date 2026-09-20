package dataplane

import "testing"

func TestRecordedResourceAggregatorCloseIsIdempotent(t *testing.T) {
	var zero recordedResourceAggregator
	zero.Close()
	zero.Close()
}
