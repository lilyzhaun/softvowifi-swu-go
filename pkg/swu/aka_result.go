package swu

import "errors"

func validateAKAResult(res, ck, ik []byte) error {
	if len(res) < 4 || len(res) > 16 {
		return errors.New("invalid AKA RES length")
	}
	if len(ck) != 16 {
		return errors.New("invalid AKA CK length")
	}
	if len(ik) != 16 {
		return errors.New("invalid AKA IK length")
	}
	return nil
}
