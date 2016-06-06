using System;
using System.Linq;
using System.Security.Cryptography;

namespace TribbleCipher
{
    public class TribbleSHA512 : IDisposable
    {
        private Int64 _counter;
        private Byte _position;
        private readonly SHA512 _hash = SHA512.Create();
        private Byte[] _state;
        private readonly Byte[] _key;

        public TribbleSHA512(Byte[] key)
        {
            if (key == null || key.Length != 64)
                throw new ArgumentException(@"Invalid key", "key");
            _state = key.ToArray();
            _key = key.ToArray();
            Next();
        }

        internal void Next()
        {
            var counterBytes = BitConverter.GetBytes(_counter);
            for (var i = 0; i < 8; i++)
                _state[i] ^= counterBytes[i];
            _state = _hash.ComputeHash(_state);
            _counter++;
            _position = 0;
        }

        public Byte[] XOR(Byte[] input)
        {
            var output = new Byte[input.Length];
            for (var i = 0; i < input.Length; i++)
            {
                output[i] = (Byte)(input[i] ^ _state[_position]);
                _position++;
                if (_position % 64 == 0)
                    Next();
            }
            return output;
        }

        internal void Reset()
        {
            _counter = 0;
            _position = 0;
            _state = _key.ToArray();
            Next();
        }

        public void Dispose()
        {
            _hash.Dispose();
        }
    }
}
