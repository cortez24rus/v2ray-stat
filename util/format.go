package util

import "fmt"

// FormatData форматирует значения скорости или трафика в человеко-читаемый вид.
// unit: "bps" для скорости/трафика в битах (Gbps, Mbps, kbps, bps), "byte" для трафика в байтах (GB, MB, KB, B).
func FormatData(value float64, unit string) string {
	switch unit {
	case "bps":
		const (
			mbit = 1_000_000
			kbit = 1_000
		)
		switch {
		case value >= mbit:
			return fmt.Sprintf("%.2f Mbps", value/mbit)
		case value >= kbit:
			return fmt.Sprintf("%.2f kbps", value/kbit)
		default:
			return fmt.Sprintf("%.0f bps", value)
		}
	case "byte":
		const (
			GiB = 1_073_741_824
			MiB = 1_048_576
			KiB = 1_024
		)
		switch {
		case value >= GiB:
			return fmt.Sprintf("%.2f GiB", value/GiB)
		case value >= MiB:
			return fmt.Sprintf("%.2f MiB", value/MiB)
		case value >= KiB:
			return fmt.Sprintf("%.2f KiB", value/KiB)
		default:
			return fmt.Sprintf("%.0f B", value)
		}
	default:
		return fmt.Sprintf("%.0f %s", value, unit)
	}
}
