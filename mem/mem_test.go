package mem

import (
	"testing"

	"github.com/runzhi214/keyring/contracttest"
	"github.com/runzhi214/keyring/core"
)

func TestContract(t *testing.T) {
	contracttest.RunContractTests(t, New(), func() core.Backend { return New() }, "mem")
}
