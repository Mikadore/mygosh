package user

import (
	"strconv"

	"github.com/rotisserie/eris"
	"github.com/samber/lo"
)

func IsASCIINumeric(s string) bool {
	return lo.EveryBy([]byte(s), func (c byte) bool {
		return c >= '0' && c <= '9'
	})
}

func ParseID(id string) (uint32, error) {
	if !IsASCIINumeric(id) {
		return 0, eris.Errorf("ID '%v' is not a valid ASCII decimal", id)
	}
	n, err := strconv.ParseUint(id, 10, 32)
	return uint32(n), err
}

func FormatID(id uint32) string {
	return strconv.FormatUint(uint64(id), 10)
}