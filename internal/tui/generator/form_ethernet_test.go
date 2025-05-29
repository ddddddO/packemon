package generator

import (
	"testing"

	"github.com/ddddddO/packemon"
)

func TestValidateAndParseMACAddress(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantHasAddr bool   // whether we expect HasAddress to be true
		wantValid   bool   // whether the validation should pass
		wantError   string // expected error message
	}{
		// Valid hex format tests
		{
			name:        "valid hex format with 0x prefix",
			input:       "0x3c585d55770e",
			wantHasAddr: true,
			wantValid:   true,
			wantError:   "",
		},
		{
			name:        "valid hex format uppercase",
			input:       "0x3C585D55770E",
			wantHasAddr: true,
			wantValid:   true,
			wantError:   "",
		},
		
		// Valid colon-separated format tests
		{
			name:        "valid colon format lowercase",
			input:       "3c:58:5d:55:77:0e",
			wantHasAddr: true,
			wantValid:   true,
			wantError:   "",
		},
		{
			name:        "valid colon format uppercase",
			input:       "3C:58:5D:55:77:0E",
			wantHasAddr: true,
			wantValid:   true,
			wantError:   "",
		},
		{
			name:        "valid colon format mixed case",
			input:       "3c:58:5D:55:77:0e",
			wantHasAddr: true,
			wantValid:   true,
			wantError:   "",
		},
		
		// Valid dash-separated format tests
		{
			name:        "valid dash format lowercase",
			input:       "3c-58-5d-55-77-0e",
			wantHasAddr: true,
			wantValid:   true,
			wantError:   "",
		},
		{
			name:        "valid dash format uppercase",
			input:       "3C-58-5D-55-77-0E",
			wantHasAddr: true,
			wantValid:   true,
			wantError:   "",
		},
		{
			name:        "valid dash format mixed case",
			input:       "3c-58-5D-55-77-0e",
			wantHasAddr: true,
			wantValid:   true,
			wantError:   "",
		},
		
		// Partial input tests (should be valid but no address)
		{
			name:        "partial hex input",
			input:       "0x3c58",
			wantHasAddr: false,
			wantValid:   true,
			wantError:   "",
		},
		{
			name:        "partial colon input",
			input:       "3c:58:5d",
			wantHasAddr: false,
			wantValid:   true,
			wantError:   "",
		},
		{
			name:        "partial dash input",
			input:       "3c-58-5d",
			wantHasAddr: false,
			wantValid:   true,
			wantError:   "",
		},
		{
			name:        "empty input",
			input:       "",
			wantHasAddr: false,
			wantValid:   true,
			wantError:   "",
		},
		{
			name:        "single character",
			input:       "3",
			wantHasAddr: false,
			wantValid:   true,
			wantError:   "",
		},
		
		// Invalid format tests
		{
			name:        "too long hex format",
			input:       "0x3c585d55770e123456",
			wantHasAddr: false,
			wantValid:   false,
			wantError:   "MAC address too long (max 20 characters)",
		},
		{
			name:        "too long colon format",
			input:       "3c:58:5d:55:77:0e:12:34",
			wantHasAddr: false,
			wantValid:   false,
			wantError:   "Invalid MAC address format",
		},
		{
			name:        "too long dash format",
			input:       "3c-58-5d-55-77-0e-12-34",
			wantHasAddr: false,
			wantValid:   false,
			wantError:   "Invalid MAC address format",
		},
		{
			name:        "invalid hex characters in colon format",
			input:       "3c:58:5d:55:77:0g",
			wantHasAddr: false,
			wantValid:   true, // Should allow typing
			wantError:   "Invalid character: g",
		},
		{
			name:        "invalid hex characters in dash format",
			input:       "3c-58-5d-55-77-0z",
			wantHasAddr: false,
			wantValid:   true, // Should allow typing
			wantError:   "Invalid character: z",
		},
		{
			name:        "malformed colon format",
			input:       "3c:58:5d:55:77:0e:",
			wantHasAddr: false,
			wantValid:   true, // Should allow typing
			wantError:   "",
		},
		{
			name:        "too many characters",
			input:       "012345678901234567890", // 21 characters
			wantHasAddr: false,
			wantValid:   false,
			wantError:   "MAC address too long (max 20 characters)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateAndParseMACAddress(tt.input)
			
			if result.Valid != tt.wantValid {
				t.Errorf("validateAndParseMACAddress(%q) valid = %v, want %v", tt.input, result.Valid, tt.wantValid)
			}
			
			if result.HasAddress != tt.wantHasAddr {
				t.Errorf("validateAndParseMACAddress(%q) HasAddress = %v, want %v", tt.input, result.HasAddress, tt.wantHasAddr)
			}
			
			// Verify the parsed address has correct length when HasAddress is true
			if result.HasAddress {
				// Address should be valid with 6 bytes
				var emptyAddr packemon.HardwareAddr
				if result.Address == emptyAddr {
					t.Errorf("validateAndParseMACAddress(%q) returned empty address when HasAddress is true", tt.input)
				}
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
			
			if !result.HasAddress {
				t.Fatalf("validateAndParseMACAddress(%q) HasAddress = false, want true", tt.input)
			}
			
			// Compare the addresses
			if result.Address != tt.wantAddr {
				t.Errorf("validateAndParseMACAddress(%q) address = %v, want %v", tt.input, result.Address, tt.wantAddr)
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
