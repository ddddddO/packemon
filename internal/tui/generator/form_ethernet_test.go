package generator

import (
	"testing"

	"github.com/ddddddO/packemon"
)

func TestValidateAndParseMACAddress(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantAddr  bool // whether we expect a non-nil address
		wantValid bool // whether the validation should pass
	}{
		// Valid hex format tests
		{
			name:      "valid hex format with 0x prefix",
			input:     "0x3c585d55770e",
			wantAddr:  true,
			wantValid: true,
		},
		{
			name:      "valid hex format uppercase",
			input:     "0x3C585D55770E",
			wantAddr:  true,
			wantValid: true,
		},
		
		// Valid colon-separated format tests
		{
			name:      "valid colon format lowercase",
			input:     "3c:58:5d:55:77:0e",
			wantAddr:  true,
			wantValid: true,
		},
		{
			name:      "valid colon format uppercase",
			input:     "3C:58:5D:55:77:0E",
			wantAddr:  true,
			wantValid: true,
		},
		{
			name:      "valid colon format mixed case",
			input:     "3c:58:5D:55:77:0e",
			wantAddr:  true,
			wantValid: true,
		},
		
		// Partial input tests (should be valid but no address)
		{
			name:      "partial hex input",
			input:     "0x3c58",
			wantAddr:  false,
			wantValid: true,
		},
		{
			name:      "partial colon input",
			input:     "3c:58:5d",
			wantAddr:  false,
			wantValid: true,
		},
		{
			name:      "empty input",
			input:     "",
			wantAddr:  false,
			wantValid: true,
		},
		{
			name:      "single character",
			input:     "3",
			wantAddr:  false,
			wantValid: true,
		},
		
		// Invalid format tests
		{
			name:      "too long hex format",
			input:     "0x3c585d55770e123456",
			wantAddr:  false,
			wantValid: false,
		},
		{
			name:      "too long colon format",
			input:     "3c:58:5d:55:77:0e:12:34",
			wantAddr:  false,
			wantValid: false,
		},
		{
			name:      "invalid hex characters",
			input:     "0x3c585d55770g",
			wantAddr:  false,
			wantValid: true, // Should allow typing until complete
		},
		{
			name:      "malformed colon format",
			input:     "3c:58:5d:55:77:0e:",
			wantAddr:  false,
			wantValid: true, // Should allow typing
		},
		{
			name:      "too many characters",
			input:     "012345678901234567890", // 21 characters
			wantAddr:  false,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, valid := validateAndParseMACAddress(tt.input)
			
			if valid != tt.wantValid {
				t.Errorf("validateAndParseMACAddress(%q) valid = %v, want %v", tt.input, valid, tt.wantValid)
			}
			
			if tt.wantAddr && addr == nil {
				t.Errorf("validateAndParseMACAddress(%q) returned nil address, want non-nil", tt.input)
			}
			
			if !tt.wantAddr && addr != nil {
				t.Errorf("validateAndParseMACAddress(%q) returned non-nil address %v, want nil", tt.input, addr)
			}
			
			// Verify the parsed address has correct length when non-nil
			if addr != nil && len(addr) != 6 {
				t.Errorf("validateAndParseMACAddress(%q) returned address with length %d, want 6", tt.input, len(addr))
			}
		})
	}
}

// Test specific MAC address values
func TestValidateAndParseMACAddressValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantAddr packemon.HardwareAddr
	}{
		{
			name:     "hex format specific value",
			input:    "0x3c585d55770e",
			wantAddr: packemon.HardwareAddr{0x3c, 0x58, 0x5d, 0x55, 0x77, 0x0e},
		},
		{
			name:     "colon format specific value",
			input:    "3c:58:5d:55:77:0e",
			wantAddr: packemon.HardwareAddr{0x3c, 0x58, 0x5d, 0x55, 0x77, 0x0e},
		},
		{
			name:     "all zeros",
			input:    "00:00:00:00:00:00",
			wantAddr: packemon.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "all ones (broadcast)",
			input:    "ff:ff:ff:ff:ff:ff",
			wantAddr: packemon.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, valid := validateAndParseMACAddress(tt.input)
			
			if !valid {
				t.Fatalf("validateAndParseMACAddress(%q) validation failed", tt.input)
			}
			
			if addr == nil {
				t.Fatalf("validateAndParseMACAddress(%q) returned nil address", tt.input)
			}
			
			// Compare byte by byte
			for i := 0; i < len(tt.wantAddr); i++ {
				if addr[i] != tt.wantAddr[i] {
					t.Errorf("validateAndParseMACAddress(%q) byte %d = %02x, want %02x", 
						tt.input, i, addr[i], tt.wantAddr[i])
				}
			}
		})
	}
}
