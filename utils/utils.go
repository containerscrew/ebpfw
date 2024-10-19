package utils


func GetProtocolType(protocol uint8) string{
	if protocol == 6 {
		return "TCP"
	} else if protocol == 17 {
		return "UDP"
	}
	return "Unknown"
}