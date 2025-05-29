package generator

import (
	"testing"

	"github.com/ddddddO/packemon"
)

func TestValidateAndParseMACAddress(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantAddr    bool   // whether we expect a non-nil address
		wantValid   bool   // whether the validation should pass
		wantError   string // expected error message
	}{
		// Valid hex format tests
		{
			name:      "valid hex format with 0x prefix",
			input:     "0x3c585d55770e",
			wantAddr:  true,
			wantValid: true,
			wantError: "",
		},
		{
			name:      "valid hex format uppercase",
			input:     "0x3C585D55770E",
			wantAddr:  true,
			wantValid: true,
			wantError: "",
		},
		
		// Valid colon-separated format tests
		{
			name:      "valid colon format lowercase",
			input:     "3c:58:5d:55:77:0e",
			wantAddr:  true,
			wantValid: true,
			wantError: "",
		},
		{
			name:      "valid colon format uppercase",
			input:     "3C:58:5D:55:77:0E",
			wantAddr:  true,
			wantValid: true,
			wantError: "",
		},
		{
			name:      "valid colon format mixed case",
			input:     "3c:58:5D:55:77:0e",
			wantAddr:  true,
			wantValid: true,
			wantError: "",
		},
		
		// Valid dash-separated format tests
		{
			name:      "valid dash format lowercase",
			input:     "3c-58-5d-55-77-0e",
			wantAddr:  true,
			wantValid: true,
			wantError: "",
		},
		{
			name:      "valid dash format uppercase",
			input:     "3C-58-5D-55-77-0E",
			wantAddr:  true,
			wantValid: true,
			wantError: "",
		},
		{
			name:      "valid dash format mixed case",
			input:     "3c-58-5D-55-77-0e",
			wantAddr:  true,
			wantValid: true,
			wantError: "",
		},
		
		// Partial input tests (should be valid but no address)
		{
			name:      "partial hex input",
			input:     "0x3c58",
			wantAddr:  false,
			wantValid: true,
			wantError: "",
		},
		{
			name:      "partial colon input",
			input:     "3c:58:5d",
			wantAddr:  false,
			wantValid: true,
			wantError: "",
		},
		{
			name:      "partial dash input",
			input:     "3c-58-5d",
			wantAddr:  false,
			wantValid: true,
			wantError: "",
		},
		{
			name:      "empty input",
			input:     "",
			wantAddr:  false,
			wantValid: true,
			wantError: "",
		},
		{
			name:      "single character",
			input:     "3",
			wantAddr:  false,
			wantValid: true,
			wantError: "",
		},
		
		// Invalid format tests
		{
			name:      "too long hex format",
			input:     "0x3c585d55770e123456",
			wantAddr:  false,
			wantValid: false,
			wantError: "MAC address too long (max 20 characters)",
		},
		{
			name:      "too long colon format",
			input:     "3c:58:5d:55:77:0e:12:34",
			wantAddr:  false,
			wantValid: false,
			wantError: "Invalid MAC address format",
		},
		{
			name:      "too long dash format",
			input:     "3c-58-5d-55-77-0e-12-34",
			wantAddr:  false,
			wantValid: false,
			wantError: "Invalid MAC address format",
		},
		{
			name:      "invalid hex characters in colon format",
			input:     "3c:58:5d:55:77:0g",
			wantAddr:  false,
			wantValid: true, // Should allow typing
			wantError: "Invalid character: g",
		},
		{
			name:      "invalid hex characters in dash format",
			input:     "3c-58-5d-55-77-0z",
			wantAddr:  false,
			wantValid: true, // Should allow typing
			wantError: "Invalid character: z",
		},
		{
			name:      "malformed colon format",
			input:     "3c:58:5d:55:77:0e:",
			wantAddr:  false,
			wantValid: true, // Should allow typing
			wantError: "",
		},
		{
			name:      "too many characters",
			input:     "012345678901234567890", // 21 characters
			wantAddr:  false,
			wantValid: false,
			wantError: "MAC address too long (max 20 characters)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateAndParseMACAddress(tt.input)
			
			if result.Valid != tt.wantValid {
				t.Errorf("validateAndParseMACAddress(%q) valid = %v, want %v", tt.input, result.Valid, tt.wantValid)
			}
			
			if tt.wantAddr && result.Address == nil {
				t.Errorf("validateAndParseMACAddress(%q) returned nil address, want non-nil", tt.input)
			}
			
			if !tt.wantAddr && result.Address != nil {
				t.Errorf("validateAndParseMACAddress(%q) returned non-nil address %v, want nil", tt.input, result.Address)
			}
			
			// Verify the parsed address has correct length when non-nil
			if result.Address != nil && len(result.Address) != 6 {
				t.Errorf("validateAndParseMACAddress(%q) returned address with length %d, want 6", tt.input, len(result.Address))
			}
			
			// Check error message
			if result.Error != tt.wantError {
				t.Errorf("validateAndParseMACAddress(%q) error = %q, want %q", tt.input, result.Error, tt.wantError)
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
			name:     "dash format specific value",
			input:    "3c-58-5d-55-77-0e",
			wantAddr: packemon.HardwareAddr{0x3c, 0x58, 0x5d, 0x55, 0x77, 0x0e},
		},
		{
			name:     "all zeros colon",
			input:    "00:00:00:00:00:00",
			wantAddr: packemon.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "all zeros dash",
			input:    "00-00-00-00-00-00",
			wantAddr: packemon.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "all ones (broadcast) colon",
			input:    "ff:ff:ff:ff:ff:ff",
			wantAddr: packemon.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name:     "all ones (broadcast) dash",
			input:    "ff-ff-ff-ff-ff-ff",
			wantAddr: packemon.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateAndParseMACAddress(tt.input)
			
			if !result.Valid {
				t.Fatalf("validateAndParseMACAddress(%q) validation failed", tt.input)
			}
			
			if result.Address == nil {
				t.Fatalf("validateAndParseMACAddress(%q) returned nil address", tt.input)
			}
			
			// Compare byte by byte
			for i := 0; i < len(tt.wantAddr); i++ {
				if result.Address[i] != tt.wantAddr[i] {
					t.Errorf("validateAndParseMACAddress(%q) byte %d = %02x, want %02x", 
						tt.input, i, result.Address[i], tt.wantAddr[i])
				}
			}
		})
	}
}

// Test error message extraction
func TestValidateAndParseMACAddressErrorMessages(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError string
	}{
		{
			name:      "too long input",
			input:     "123456789012345678901",
			wantError: "MAC address too long (max 20 characters)",
		},
		{
			name:      "invalid character in colon format",
			input:     "3c:58:5d:55:77:XX",
			wantError: "Invalid character: X",
		},
		{
			name:      "invalid character in dash format",
			input:     "3c-58-5d-55-77-@#",
			wantError: "Invalid character: @",
		},
		{
			name:      "too many segments colon",
			input:     "3c:58:5d:55:77:0e:aa",
			wantError: "Invalid MAC address format",
		},
		{
			name:      "too many segments dash",
			input:     "3c-58-5d-55-77-0e-bb",
			wantError: "Invalid MAC address format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateAndParseMACAddress(tt.input)
			
			if result.Error != tt.wantError {
				t.Errorf("validateAndParseMACAddress(%q) error = %q, want %q", 
					tt.input, result.Error, tt.wantError)
			}
		})
	}
}
