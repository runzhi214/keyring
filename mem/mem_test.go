package mem

import (
	"testing"

	"github.com/runzhi214/keyring"
	"github.com/runzhi214/keyring/contracttest"
)

func TestContract(t *testing.T) {
	contracttest.RunContractTests(t, New(), func() keyring.Backend { return New() })
}
