package modbus

type FunctionHandler func(S *ModbusServer, clientAddr, clientRole string, req PDU) (res PDU, err error)

func (ms *ModbusServer) RegisterFunctionHandler(functionCode uint8, handler FunctionHandler) {
	ms.function[functionCode] = handler
}

// fcReadCoils, fcReadDiscreteInputs
func (ms *ModbusServer) fnReadCoils(S *ModbusServer, clientAddr, clientRole string, req PDU) (res PDU, err error) {
	var reqPayload = req.GetPayload()

	var coils []bool
	var resCount int
	if len(reqPayload) != 4 {
		err = ErrProtocolError
		return
	}

	// decode address and quantity fields
	addr := bytesToUint16(BIG_ENDIAN, reqPayload[0:2])
	quantity := bytesToUint16(BIG_ENDIAN, reqPayload[2:4])

	// ensure the reply never exceeds the maximum PDU length and we
	// never read past 0xffff
	if quantity > 2000 || quantity == 0 {
		err = ErrProtocolError
		return
	}
	if uint32(addr)+uint32(quantity)-1 > 0xffff {
		err = ErrIllegalDataAddress
		return
	}

	// invoke the appropriate handler
	if ms.handler != nil {
		if req.GetFunctionCode() == fcReadCoils {
			coils, err = ms.handler.HandleCoils(&CoilsRequest{
				ClientAddr: clientAddr,
				ClientRole: clientRole,
				UnitId:     req.GetUnitId(),
				Addr:       addr,
				Quantity:   quantity,
				IsWrite:    false,
				Args:       nil,
			})
		} else {
			coils, err = ms.handler.HandleDiscreteInputs(
				&DiscreteInputsRequest{
					ClientAddr: clientAddr,
					ClientRole: clientRole,
					UnitId:     req.GetUnitId(),
					Addr:       addr,
					Quantity:   quantity,
				})
		}
	}
	resCount = len(coils)

	// make sure the handler returned the expected number of items
	if err == nil && resCount != int(quantity) {
		ms.logger.Errorf("handler returned %v bools, "+
			"expected %v", resCount, quantity)
		err = ErrServerDeviceFailure
		return
	}

	if err != nil {
		return
	}

	// byte count (1 byte for 8 coils)
	var resPayload = []byte{uint8(resCount / 8)}
	if resCount%8 != 0 {
		resPayload[0]++
	}
	// coil values
	resPayload = append(resPayload, encodeBools(coils)...)

	return req.Resp(resPayload), nil
}

// fcWriteSingleCoil
func (ms *ModbusServer) fnWriteSingleCoil(S *ModbusServer, clientAddr, clientRole string, req PDU) (res PDU, err error) {
	var reqPayload = req.GetPayload()

	if len(reqPayload) != 4 {
		err = ErrProtocolError
		return
	}

	// decode the address field
	addr := bytesToUint16(BIG_ENDIAN, reqPayload[0:2])

	// validate the value field (should be either 0xff00 or 0x0000)
	if (reqPayload[2] != 0xff && reqPayload[2] != 0x00) ||
		reqPayload[3] != 0x00 {
		err = ErrProtocolError
		return
	}

	// invoke the coil handler
	if ms.handler != nil {
		_, err = ms.handler.HandleCoils(&CoilsRequest{
			ClientAddr: clientAddr,
			ClientRole: clientRole,
			UnitId:     req.GetUnitId(),
			Addr:       addr,
			Quantity:   1,    // request for a single coil
			IsWrite:    true, // this is a write request
			Args:       []bool{(reqPayload[2] == 0xff)},
		})
	}

	if err != nil {
		return
	}

	var resPayload []byte

	// echo the address and value in the response
	resPayload = append(resPayload, uint16ToBytes(BIG_ENDIAN, addr)...)
	resPayload = append(resPayload, reqPayload[2], reqPayload[3])

	return req.Resp(resPayload), nil
}

// fcWriteMultipleCoils
func (ms *ModbusServer) fnWriteMultipleCoils(S *ModbusServer, clientAddr, clientRole string, req PDU) (res PDU, err error) {
	var reqPayload = req.GetPayload()

	var expectedLen int

	if len(reqPayload) < 6 {
		err = ErrProtocolError
		return
	}

	// decode address and quantity fields
	addr := bytesToUint16(BIG_ENDIAN, reqPayload[0:2])
	quantity := bytesToUint16(BIG_ENDIAN, reqPayload[2:4])

	// ensure the reply never exceeds the maximum PDU length and we
	// never read past 0xffff
	if quantity > 0x7b0 || quantity == 0 {
		err = ErrProtocolError
		return
	}
	if uint32(addr)+uint32(quantity)-1 > 0xffff {
		err = ErrIllegalDataAddress
		return
	}

	// validate the byte count field (1 byte for 8 coils)
	expectedLen = int(quantity) / 8
	if quantity%8 != 0 {
		expectedLen++
	}

	if reqPayload[4] != uint8(expectedLen) {
		err = ErrProtocolError
		return
	}

	// make sure we have enough bytes
	if len(reqPayload)-5 != expectedLen {
		err = ErrProtocolError
		return
	}

	// invoke the coil handler
	if ms.handler != nil {
		_, err = ms.handler.HandleCoils(&CoilsRequest{
			ClientAddr: clientAddr,
			ClientRole: clientRole,
			UnitId:     req.GetUnitId(),
			Addr:       addr,
			Quantity:   quantity,
			IsWrite:    true, // this is a write request
			Args:       decodeBools(quantity, reqPayload[5:]),
		})
	}

	if err != nil {
		return
	}

	var resPayload []byte

	// echo the address and quantity in the response
	resPayload = append(resPayload, uint16ToBytes(BIG_ENDIAN, addr)...)
	resPayload = append(resPayload, uint16ToBytes(BIG_ENDIAN, quantity)...)

	return req.Resp(resPayload), nil
}

// fcReadHoldingRegisters, fcReadInputRegisters
func (ms *ModbusServer) fnReadHoldingRegisters(S *ModbusServer, clientAddr, clientRole string, req PDU) (res PDU, err error) {
	var reqPayload = req.GetPayload()

	var regs []uint16
	var resCount int

	if len(reqPayload) != 4 {
		err = ErrProtocolError
		return
	}

	// decode address and quantity fields
	addr := bytesToUint16(BIG_ENDIAN, reqPayload[0:2])
	quantity := bytesToUint16(BIG_ENDIAN, reqPayload[2:4])

	// ensure the reply never exceeds the maximum PDU length and we
	// never read past 0xffff
	if quantity > 0x007d || quantity == 0 {
		err = ErrProtocolError
		return
	}
	if uint32(addr)+uint32(quantity)-1 > 0xffff {
		err = ErrIllegalDataAddress
		return
	}

	// invoke the appropriate handler
	if ms.handler != nil {
		if req.GetFunctionCode() == fcReadHoldingRegisters {
			regs, err = ms.handler.HandleHoldingRegisters(
				&HoldingRegistersRequest{
					ClientAddr: clientAddr,
					ClientRole: clientRole,
					UnitId:     req.GetUnitId(),
					Addr:       addr,
					Quantity:   quantity,
					IsWrite:    false,
					Args:       nil,
				})
		} else {
			regs, err = ms.handler.HandleInputRegisters(
				&InputRegistersRequest{
					ClientAddr: clientAddr,
					ClientRole: clientRole,
					UnitId:     req.GetUnitId(),
					Addr:       addr,
					Quantity:   quantity,
				})
		}
	}
	resCount = len(regs)

	// make sure the handler returned the expected number of items
	if err == nil && resCount != int(quantity) {
		ms.logger.Errorf("handler returned %v 16-bit values, "+
			"expected %v", resCount, quantity)
		err = ErrServerDeviceFailure
		return
	}

	if err != nil {
		return
	}

	// byte count (2 bytes per register)
	var resPayload = []byte{uint8(resCount * 2)}
	// register values
	resPayload = append(resPayload, uint16sToBytes(BIG_ENDIAN, regs)...)

	return req.Resp(resPayload), nil
}

// fcWriteSingleRegister
func (ms *ModbusServer) fnWriteSingleRegister(S *ModbusServer, clientAddr, clientRole string, req PDU) (res PDU, err error) {
	var reqPayload = req.GetPayload()

	var value uint16

	if len(reqPayload) != 4 {
		err = ErrProtocolError
		return
	}

	// decode address and value fields
	addr := bytesToUint16(BIG_ENDIAN, reqPayload[0:2])
	value = bytesToUint16(BIG_ENDIAN, reqPayload[2:4])

	// invoke the handler
	if ms.handler != nil {
		_, err = ms.handler.HandleHoldingRegisters(
			&HoldingRegistersRequest{
				ClientAddr: clientAddr,
				ClientRole: clientRole,
				UnitId:     req.GetUnitId(),
				Addr:       addr,
				Quantity:   1,    // request for a single register
				IsWrite:    true, // request is a write
				Args:       []uint16{value},
			})
	}

	if err != nil {
		return
	}

	var resPayload []byte
	// echo the address and value in the response
	resPayload = append(resPayload, uint16ToBytes(BIG_ENDIAN, addr)...)
	resPayload = append(resPayload, uint16ToBytes(BIG_ENDIAN, value)...)

	return req.Resp(resPayload), nil
}

// fcWriteMultipleRegisters
func (ms *ModbusServer) fnWriteMultipleRegisters(S *ModbusServer, clientAddr, clientRole string, req PDU) (res PDU, err error) {
	var reqPayload = req.GetPayload()
	var expectedLen int

	if len(reqPayload) < 6 {
		err = ErrProtocolError
		return
	}

	// decode address and quantity fields
	addr := bytesToUint16(BIG_ENDIAN, reqPayload[0:2])
	quantity := bytesToUint16(BIG_ENDIAN, reqPayload[2:4])

	// ensure the reply never exceeds the maximum PDU length and we
	// never read past 0xffff
	if quantity > 0x007b || quantity == 0 {
		err = ErrProtocolError
		return
	}
	if uint32(addr)+uint32(quantity)-1 > 0xffff {
		err = ErrIllegalDataAddress
		return
	}

	// validate the byte count field (2 bytes per register)
	expectedLen = int(quantity) * 2

	if reqPayload[4] != uint8(expectedLen) {
		err = ErrProtocolError
		return
	}

	// make sure we have enough bytes
	if len(reqPayload)-5 != expectedLen {
		err = ErrProtocolError
		return
	}

	// invoke the holding register handler
	if ms.handler != nil {
		_, err = ms.handler.HandleHoldingRegisters(
			&HoldingRegistersRequest{
				ClientAddr: clientAddr,
				ClientRole: clientRole,
				UnitId:     req.GetUnitId(),
				Addr:       addr,
				Quantity:   quantity,
				IsWrite:    true, // this is a write request
				Args:       bytesToUint16s(BIG_ENDIAN, reqPayload[5:]),
			})
		if err != nil {
			return
		}
	}

	var resPayload []byte
	// echo the address and quantity in the response
	resPayload = append(resPayload, uint16ToBytes(BIG_ENDIAN, addr)...)
	resPayload = append(resPayload, uint16ToBytes(BIG_ENDIAN, quantity)...)

	return req.Resp(resPayload), nil
}
