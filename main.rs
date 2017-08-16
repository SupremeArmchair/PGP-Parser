// Sequence of confidentialy by encryption with PGP
// 1, Sender creates a message
// 2. Sender's PGP session creates a random number to be used as a session key
// 3. Session key is encypted using each recipients private key, encrypted session keys start message
// 4. Sender's PGP encrypts message with the session key
// 5. Recieving PGP decrypts session key with recipient's private key
// 6. Recieving PGP decrypts message using the session key (message will be decompressed if compressed)

// Authentication with the digital signature
// 1, Sender creates message
// 2. Sending software generates a hash code of the message
// 3. Sending software generates a signature from the hash code of the message
// 4. Binary sequence is attached to the message
// 5. Recieving software keeps a copy of the message signature
// 6. Recieving software genereates a new hash code for the recieved message and 
// verifies it using message signature

// Native representation of message is in octets

// Types of S2K
// 	Simple S2K
//		Directly hashes string to produce the key data
//		Octet 0: 0x00
//		Octet 1: hash algorithm
//		Hashes the passphrase to produce the session key
//		If hash size is greater than session key size, the leftmost octets of the hash are used in the key
//		If hash size is less than session key size, multiple instances of the hash context are created, enough to produce required key data
//			Preloaded with 0, 1, 2, 3... octets of zeros
//		As data is hashed, it is given independently to each hash context
//			Since contexts have been initialized differently, they will each produce a different hash output
//			Once a passphrase is hashed, the output data from the multiple hashes is concatenated, first hash leftmost, to produce the key data with any excess octets on the right discarded
//	Salted S2K
//		Includes a "salt" value in S2K specifier (arbitrary data)
//			Gets hashed with the passphrase string
//		Octet 0: 0x01
//		Octet 1: hash algorithm
//		Ocets 2-9: 8-octet salt value
//		Main difference is that input to hash functions consists of 8 octets of salt from S2K specifier followed by passphrase
//	Iterated and Salted S2K
//		Includes both salt and an octet count
//		Salt is combined with passphrase and resulting value is hashed repeatedly
//		Octet 0: 0x03
//		Octet 1: hash algorithm
//		Octet 2-9: 8 octet salt value
//		Octet 10: count, a one octet, coded value
//		Count is coded into a one octet number using this formula
//			count = ((Int32)16 + (c & 15)) << ((c >> 4) + EXPHBIAS);
//			Coded in C, Int32 is is a type for a 32 bit integer and the variable "c" is the coded count, octet 10 
//			Hashes passphrase and salt data multiple times
//			Total number of octets to be hashed is specified in the encoded count in the S2K specifier
//			Note that the resulting count value is an octet count of how many octets will be hashed
//			One or more hash contexts are set up as with the other S2K algorithms, depending on how many octets of key data are needed
//			Then the salt, followed by passphrase data, is repeatedly hashed until the number of octets specified by the octet count has been hashed
//			The exception is if the octet cout is less than the size of the salt plus passphrase, the full salt plus passphrase will be hashed even though it is greater than the octet count
//			After hashing is done, data is unloaded from hash contexts with other S2K algorithms
// 	For compatibility, when an S2K specifier is used, the special value 254 or 255 is stored in the position where the hash algorithm octet would have been in the old data structure
//		This is then followed immediately by a one octet algorithm identifier, and then by the S2K specifier as encoded above

// Preceding the secret data there will be one of these possibilites
//	0: secret data is unencrypted
//	255 or 254: followed by algorithm octet and S2K specifier
//	Cipher algorithm: use Simple S2K algorithm using MD5 hash
//		Provided for backwards compatibility, may be understood but SHOULD NOT be generated, as it is deprecated
//	These are followed by an initial vector of the same length as the block size of the cipher for the decryption of the secret values, if they are encrypted, and then the secret-key values themselves

// OpenPGP can create a Symmetric-key encrypted session key (ESK) packet at the front of a message
// 	This is used to allow S2K specifiers to be used for the passphrase conversion or to create messages with a mix of symmetric-key ESKs and public-key ESKs
// 	This allows a message to be decrypted either with a passphrase or a public key pair
//	PGP 2.x always used IDEA with simple string-to-key conversion when encrypting a message with a symmetric algorithm
//		This is deprecated, but may be used for backwards compatibility

// PGP Packet Header
//	First octet of header is called "Packet Tag"
//		Determines the format of the header and denotes the package it contains
//	Remainder of packet header is the length of the packet
//	Most significant bit is the leftmost bit, called bit 7. AKA 0x80 (NULL?)
//		Bit 7 - always one
//		Bit 6 - new packet format if set
//	PGP 2.6.x only uses old format packets
//		Software for this must only use old format packets
//		If interoperability is not an issue, new packet format is recommended
//		Old format packets have 4 bits of packet tags, new format packets have 6	

pub enum PGPHandshakeType {
	
}

fn main() {
	let first_octet = ;
	let secret_data = ;
	
	// Checks first octet for type of S2K (if there is one)
	match first_octet {
		0x00 => hash_algorithm = octet_1 // Simple S2K!
		0x01 => hash_algorithm = octet_1, 8_octet_salt_value = octets_2_through_9// Salted S2K!
		0x03 => hash_algorithm = octet_1, 8_octet_salt_value = octets_2_through_9, count = octet_10// Iterated and Salted S2K!
		=> println!("Error!");
	}

	// Checks secret data for encryption type
	match secret_data {
		0 => // data not encrypted
		254 | 255 => // followed by algorithm octet and S2K specifier
		=> // cipher algorithm, simple S2K algorithm with MD5 hash
	}
	
	// HEADER CHECKING SECTION
	let firstoctet = ;
	let significant_bit = ;
	
	if four_bit { // OLD FORMAT
		// Old format packets can only have tags <= 15
		let packet_tag = bits5-2;
		let length_type = bits1-0;
		
		match length_type {
			0 => packet_length = 1, header_length = 2
			1 => packet_length = 2, header_length = 3
			2 => packet_length = 4, header_length = 5
			3 => packet_length = ?, header_length = 1 // if this, packet length must be determined by finding the length of the file the packet is in
		}
		match firstoctet {
		
		}
		match significant_bit {
			// leftmost bit, called bit 7
			// bit 7 - always 1, bit 6 - new packet format if set
			
		}
	}

	else if six_bit { // NEW FORMAT
		// New format packets can only have tags >= 16
		let packet_tag = "bits5-0";		
		
		match body_length {
			1 => length up to 191, body_length = firstoctet // Octet value less than 192
			2 => length up to 192, body_length = ((firstoctet - 192( << 8) + (secondoctet) + 192  // Octet is between 192 and 223 
			5 => length up to 4,294,967,295,body_length = (secondoctet << 24) | (thirdoctet << 16) | (fourthoctet << 8) | (fifthoctet) // Octet is greater than 255
			=> partial body length encodes packet of indeterminate length, making it a stream // 224 <= octet < 255, header is one octet long, length found is a power of 2, from 1 to 1,074,741,824 (2^30), body_length = 1 << (firstoctet & 01F);, partial_body_length_header specifies the portion's length, another length header (1, 2, 5, partial) follows that portion, the last header in the packet MUST NOT be a partial body length header, partial body length headers may only be used for the non final parts of the packet, last body length header can be a zero length header, implementation may use partial body lengths for data packets (literal, compressed, encrypted), first partial length must be at least 512 octets long, partial body lengths MUST NOT be used for any other packet types
		}
		match firstoctet {
			
		}
		match significant_bit {
			
		}
	}
	match signature_types {
		0x00 => // signature of a binary type
		0x01 => // signature of a canonical text document
		0x02 => // standalone signature
		0x10 => // generic certification of a User ID and Public-Key packet
		0x11 => // persona certification of a User ID and Public-Key packet
		0x12 => // casual certification of a User ID and Public-Key packet
		0x13 => // positive certification of a User ID and Public-Key packet
		0x18 => // subkey Binding Signature
		0x19 => // primary Key Binding Signature
		0x1F => // signature directly on a key
		0x20 => // key revocation signature
		0x28 => // subkey revocation signature
		0x30 => // certification revocation signature
		0x40 => // timestamp signature
		0x50 => // third-party confirmation signature
	}
	match v3signaturepacket {
		// - One-octet version number (3).
		// One-octet length of following hashed material.  MUST be 5.
			// One-octet signature type.
			// Four-octet creation time.
		// Eight-octet Key ID of signer.
		// One-octet public-key algorithm.
		// One-octet hash algorithm.
		// Two-octet field holding left 16 bits of signed hash value.
		// One or more multiprecision integers comprising the signature.
		
		// Algorithm-Specific Fields for RSA signatures:
			// multiprecision integer (MPI) of RSA signature value m**d mod n.
		// Algorithm-Specific Fields for DSA signatures:
			// MPI of DSA value r.
			// MPI of DSA value s.
			
		/* MD5:        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05

	     - RIPEMD-160: 0x2B, 0x24, 0x03, 0x02, 0x01

	     - SHA-1:      0x2B, 0x0E, 0x03, 0x02, 0x1A

	     - SHA224:     0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04

	     - SHA256:     0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01

	     - SHA384:     0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02

	     - SHA512:     0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03

	   The ASN.1 Object Identifiers (OIDs) are as follows:

	     - MD5:        1.2.840.113549.2.5

	     - RIPEMD-160: 1.3.36.3.2.1

	     - SHA-1:      1.3.14.3.2.26

	     - SHA224:     2.16.840.1.101.3.4.2.4

	     - SHA256:     2.16.840.1.101.3.4.2.1

	     - SHA384:     2.16.840.1.101.3.4.2.2

	     - SHA512:     2.16.840.1.101.3.4.2.3

	   The full hash prefixes for these are as follows:

	       MD5:        0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86,
	                   0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00,
	                   0x04, 0x10

	       RIPEMD-160: 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24,
	                   0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14

	       SHA-1:      0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E,
	                   0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14

	       SHA224:     0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	                   0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
	                   0x00, 0x04, 0x1C

	       SHA256:     0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	                   0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	                   0x00, 0x04, 0x20

	       SHA384:     0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	                   0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	                   0x00, 0x04, 0x30

	       SHA512:     0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	                   0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
	                   0x00, 0x04, 0x40
	*/
	}
	match v4signaturepacket {
		/*
		The body of a version 4 Signature packet contains:

     - One-octet version number (4).

     - One-octet signature type.

     - One-octet public-key algorithm.

     - One-octet hash algorithm.

     - Two-octet scalar octet count for following hashed subpacket data.
       Note that this is the length in octets of all of the hashed
       subpackets; a pointer incremented by this number will skip over
       the hashed subpackets.

     - Hashed subpacket data set (zero or more subpackets).

     - Two-octet scalar octet count for the following unhashed subpacket
       data.  Note that this is the length in octets of all of the
       unhashed subpackets; a pointer incremented by this number will
       skip over the unhashed subpackets.

     - Unhashed subpacket data set (zero or more subpackets).

     - Two-octet field holding the left 16 bits of the signed hash
       value.

     - One or more multiprecision integers comprising the signature.*/
	}
	match signature_subpacket {
		/*
		Each subpacket consists of a subpacket header and a body.  The header
   consists of:

     - the subpacket length (1, 2, or 5 octets),

     - the subpacket type (1 octet),

   and is followed by the subpacket-specific data.

   The length includes the type octet but not this length.  Its format
   is similar to the "new" format packet header lengths, but cannot have
   Partial Body Lengths.  That is:

       if the 1st octet <  192, then
           lengthOfLength = 1
           subpacketLen = 1st_octet

       if the 1st octet >= 192 and < 255, then
           lengthOfLength = 2
           subpacketLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192

       if the 1st octet = 255, then
           lengthOfLength = 5
           subpacket length = [four-octet scalar starting at 2nd_octet]

   The value of the subpacket type octet may be:

            0 = Reserved
            1 = Reserved
            2 = Signature Creation Time
            3 = Signature Expiration Time
            4 = Exportable Certification
            5 = Trust Signature
            6 = Regular Expression
            7 = Revocable
            8 = Reserved
            9 = Key Expiration Time
           10 = Placeholder for backward compatibility
           11 = Preferred Symmetric Algorithms
           12 = Revocation Key
           13 = Reserved
           14 = Reserved
           15 = Reserved
           16 = Issuer
           17 = Reserved
           18 = Reserved
           19 = Reserved
           20 = Notation Data
           21 = Preferred Hash Algorithms
           22 = Preferred Compression Algorithms
           23 = Key Server Preferences
           24 = Preferred Key Server
           25 = Primary User ID
           26 = Policy URI
           27 = Key Flags
           28 = Signer's User ID
           29 = Reason for Revocation
           30 = Features
           31 = Signature Target
           32 = Embedded Signature
   100 To 110 = Private or experimental
   
   An implementation SHOULD ignore any subpacket of a type that it does
   not recognize.
   
   Bit 7 of the subpacket type is the "critical" bit.
   
   Implementations SHOULD implement the three preferred algorithm
   subpackets (11, 21, and 22)
   
   A subpacket may be found either in the hashed or unhashed subpacket
   sections of a signature.  If a subpacket is not hashed, then the
   information in it cannot be considered definitive because it is not
   part of the signature proper.
   		*/
	}
	match signature_creation_time {
		/*
		(4-octet time field)

   The time the signature was made.

   MUST be present in the hashed area.
	*/
	}
	match issuer {
		/*
		(8-octet Key ID)

   The OpenPGP Key ID of the key issuing the signature.
	*/
	}
	match key_expiration_time_field {
		/*
		(4-octet time field)

   The validity period of the key.  This is the number of seconds after
   the key creation time that the key expires.  If this is not present
   or has a value of zero, the key never expires.  This is found only on
   a self-signature.
   */
	}
}
