The Tribble family of ciphers are stream ciphers designed for ease of implementation. The author found that after implementing stream ciphers in a number of programming languages, with the intentional exclusion of RC4, certain languages were lacking in stable byte-by-byte stream cipher implementations, with algorithms like Salsa and ChaCha being typically implemented in block modes, or requiring obnoxious platform-dependent extensions.

Tribble ciphers are a form of 'Hashing Stream Cipher'. They operate in CTR mode and are highly stateful ("online"), allowing them to encrypt/decrypt traffic as it arrives rather than waiting for a full block or requiring pre-determined padding. They are intended to be very simple to write and understand, even in unfamiliar languages. They have only one basic dependency (any secure hashing function with pseudo-random properties), and have well understood security properties.

Some reasons to use Tribble ciphers:

* Very easy to implement and understand (as ciphers go), regardless of language.
* Work with whatever hashing algorithm you give them (although some are highly discourged, namely MD5 and SHA1)
* Terse code; easily fit in a single file.
* Inherit most of the security properties of the hash used, providing predictable security.
* Easy to implement in constrained environments, like shellcode.
* Take advantage of hardware support for hashing algorithms.
* Did I mention they're really easy to implement?

Some reasons not to use Tribble ciphers:

* Not nearly as fast as alternative stream ciphers, like Salsa or ChaCha, or block ciphers in stream modes. The un-optimised, managed, C# reference implementation benchmarks in at somewhere in the vague realm of 13Mib/s on commodity hardware.
* No integrity, meaning that an attacker could alter the ciphertext in transit. This is generally A Bad Thing(tm), but not an issue for every use case. Use your head.
* If the underlying hash implementation is vulnerable to timing attacks, then so is the Tribble cipher.
* If you were to encrypt an incredibly large amount of data with the same key, it would become theoretically possible to brute-force the key in a reasonable time frame. By incredibly large I mean staggeringly, stupidly, heat-death-of-the-universe-first sort of large: 2^48-ish bytes. If you're really paranoid, you can use a random IV (just XOR the key against it) to remove the risk entirely.

Implementation tip: SHA-512 is the recommended default, as it's typically faster than SHA-256 and has some cryptographic properties that make it marginally better suited for this purpose. Obviously avoid any known weak hash algorithms (MD5, SHA1, etc).

The implementations within the repo attempt to take advantage of language features where possible, with a separate 'basic' implementation for copy/pasting. The C# Tribble class is the reference implementation, with the most comprehensive unit tests.

Here is a TribbleSHA512 implementation in C# as an example. Don't use this in a production environment as it has no validity checks or disposal - use the classes in the repository instead:

```
public class TribbleSHA512
{
	private readonly SHA512 _hash = SHA512.Create();
	private Int64 _counter = 0;
	private Byte _position = 0;
	private Byte[] _state;

	//Requires 64-byte key, as it's a 512-bit hash
	public TribbleSHA512(Byte[] key)
	{
		_state = key.ToArray();
		Next();
	}

	private void Next()
	{
		var counterBytes = BitConverter.GetBytes(_counter);
		for (var i = 0; i < 8; i++)
			_state[i] ^= counterBytes[i];
		_state = _hash.ComputeHash(_state);
		_counter++;
		_position = 0;
	}

	//Call XOR to encrypt/decrypt
	public Byte[] XOR(Byte[] input)
	{
		var output = new Byte[input.Length];
		for (var i = 0; i < input.Length; i++)
		{
			output[i] = (Byte)(input[i] ^ _state[_position]);
			_position++;
			if (_position % 64 == 0) Next();
		}
		return output;
	}
}
```

Encryption
```Byte[] ciphertext = new TribbleSHA512(key).XOR(plaintext)```
Decryption
```Byte[] plaintext = new TribbleSHA512(key).XOR(ciphertext)```

Condensed version
```
class t {
	SHA512 _h = SHA512.Create();
	Int64 _c = 0;
	Byte _p = 0;
	Byte[] _s;

	t(Byte[] k) {
		_s = k.ToArray(); n();
	}

	void n() {
		var cb = BitConverter.GetBytes(_c);
		for (var i = 0; i < 8; i++) _s[i] ^= cb[i];
		_s = _h.ComputeHash(_s);
		_c++; _p = 0;
	}

	Byte[] X(Byte[] in) {
		var out = new Byte[in.Length];
		for (var i = 0; i < in.Length; i++) {
			out[i] = (Byte)(in[i] ^ _s[_p]); _p++;
			if (_p % 64 == 0) n();
		}
		return out;
	}
}
```
