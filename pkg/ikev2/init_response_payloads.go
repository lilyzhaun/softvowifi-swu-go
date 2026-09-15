package ikev2

import "encoding/binary"

func decodeInitPayloads(data []byte) ([]Payload, error) {
	next := PayloadType(data[16])
	offset := IKE_HEADER_LEN
	var payloads []Payload
	for next != NoNextPayload {
		if offset+PAYLOAD_HEADER_LEN > len(data) {
			return nil, ErrInitResponse
		}
		header, err := DecodePayloadHeader(data[offset : offset+PAYLOAD_HEADER_LEN])
		if err != nil {
			return nil, err
		}
		length := int(header.PayloadLength)
		if length < PAYLOAD_HEADER_LEN || offset+length > len(data) {
			return nil, ErrInitResponse
		}
		body := data[offset+PAYLOAD_HEADER_LEN : offset+length]
		var payload Payload
		switch next {
		case SA:
			if err := checkInitSAFraming(body); err != nil {
				return nil, err
			}
			payload, err = DecodePayloadSA(body)
		case KE:
			payload, err = DecodePayloadKE(body)
		case NiNr:
			payload, err = DecodePayloadNonce(body)
		case N:
			payload, err = DecodePayloadNotify(body)
		case V, CERTREQ:
			payload = &RawPayload{PType: next, Data: body}
		case IDi, IDr, CERT, AUTH, D, TSI, TSR, SK, CP, EAP, EncryptedFragment:
			return nil, ErrInitResponse
		default:
			if header.Critical {
				return nil, ErrInitResponse
			}
		}
		if err != nil {
			return nil, err
		}
		if payload != nil {
			payloads = append(payloads, payload)
		}
		next = header.NextPayload
		offset += length
	}
	if offset != len(data) {
		return nil, ErrInitResponse
	}
	return payloads, nil
}

func checkInitSAFraming(body []byte) error {
	if len(body) < PROPOSAL_HEADER_LEN || body[0] != 0 || int(binary.BigEndian.Uint16(body[2:4])) != len(body) {
		return ErrInitResponse
	}
	offset := PROPOSAL_HEADER_LEN + int(body[6])
	count := int(body[7])
	for index := 0; index < count; index++ {
		if offset+TRANSFORM_HEADER_LEN > len(body) {
			return ErrInitResponse
		}
		length := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		if length < TRANSFORM_HEADER_LEN || offset+length > len(body) {
			return ErrInitResponse
		}
		terminal := byte(3)
		if index == count-1 {
			terminal = 0
		}
		if body[offset] != terminal {
			return ErrInitResponse
		}
		offset += length
	}
	if offset != len(body) {
		return ErrInitResponse
	}
	return nil
}
