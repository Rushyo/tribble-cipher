using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TribbleCipher;

namespace TribbleCipherTests
{
    [TestClass]
    public class TribbleTests
    {
        private static readonly Byte[] Sample256BitKey = new Byte[]
        {
            0xfa, 0x7f, 0x62, 0x55, 0x13, 0xb5, 0xaa, 0xcd, 0x51, 0xac, 0x64, 0xc5, 0xa6, 0x7d, 0x9d, 0x42,
            0xfe, 0x71, 0x80, 0x60, 0x19, 0x41, 0xca, 0x01, 0x17, 0xeb, 0x91, 0xe1, 0xa3, 0x26, 0x3e, 0x66,
        };

        private static readonly Byte[] Sample384BitKey = new Byte[]
        {
            0xfa, 0x7f, 0x62, 0x55, 0x13, 0xb5, 0xaa, 0xcd, 0x51, 0xac, 0x64, 0xc5, 0xa6, 0x7d, 0x9d, 0x42,
            0xfe, 0x71, 0x80, 0x60, 0x19, 0x41, 0xca, 0x01, 0x17, 0xeb, 0x91, 0xe1, 0xa3, 0x26, 0x3e, 0x66,
            0x5c, 0x1c, 0x04, 0x4d, 0x9d, 0xba, 0xf8, 0x5c, 0xb0, 0xfe, 0x67, 0x39, 0x9e, 0xe2, 0x48, 0x43,
        };

        private static readonly Byte[] Sample512BitKey = new Byte[]
        {
            0xfa, 0x7f, 0x62, 0x55, 0x13, 0xb5, 0xaa, 0xcd, 0x51, 0xac, 0x64, 0xc5, 0xa6, 0x7d, 0x9d, 0x42,
            0xfe, 0x71, 0x80, 0x60, 0x19, 0x41, 0xca, 0x01, 0x17, 0xeb, 0x91, 0xe1, 0xa3, 0x26, 0x3e, 0x66,
            0x5c, 0x1c, 0x04, 0x4d, 0x9d, 0xba, 0xf8, 0x5c, 0xb0, 0xfe, 0x67, 0x39, 0x9e, 0xe2, 0x48, 0x43,
            0x3e, 0x81, 0x51, 0x4c, 0x92, 0x31, 0x79, 0x0f, 0x7f, 0x34, 0x53, 0x98, 0x37, 0xb8, 0x1e, 0xe5
        };

        [TestMethod]
        public void XOR_504Bits()
        {
            using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
            {
                Byte[] plaintext =
                    Encoding.ASCII.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit nullam.");
                Byte[] ciphertext = tribble.XOR(plaintext);
                tribble.Reset();
                Byte[] thereAndBackAgain = tribble.XOR(ciphertext);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
            }
        }

        [TestMethod]
        public void XOR_512Bits()
        {
            using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
            {
                Byte[] plaintext =
                    Encoding.ASCII.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit posuere.");
                Byte[] ciphertext = tribble.XOR(plaintext);
                tribble.Reset();
                Byte[] thereAndBackAgain = tribble.XOR(ciphertext);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
            }
        }

        [TestMethod]
        public void XOR_520Bits()
        {
            using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
            {
                Byte[] plaintext =
                    Encoding.ASCII.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit volutpat.");
                Byte[] ciphertext = tribble.XOR(plaintext);
                tribble.Reset();
                Byte[] thereAndBackAgain = tribble.XOR(ciphertext);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
            }
        }

        [TestMethod]
        public void XOR_1030Bits()
        {
            using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
            {
                Byte[] plaintext = Encoding.ASCII.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed eu risus aliquam, dapibus est id, mattis arcu. Vestibulum cras amet.");
                Byte[] ciphertext = tribble.XOR(plaintext);
                tribble.Reset();
                Byte[] thereAndBackAgain = tribble.XOR(ciphertext);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
            }
        }

        [TestMethod]
        public void XOR_ManyIterations()
        {
            using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
            {
                Byte[] plaintext = Encoding.ASCII.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam ut nibh velit. Proin sagittis consequat elementum. Cras aliquet sed.");
                var ciphertext = new List<Byte>();
                for(var i = 0; i < plaintext.Length; i++)
                    ciphertext.Add(tribble.XOR(plaintext.Skip(i).Take(1).ToArray())[0]);
                tribble.Reset();
                var thereAndBackAgain = new List<Byte>();
                for(var i = 0; i < plaintext.Length; i++)
                    thereAndBackAgain.Add(tribble.XOR(ciphertext.Skip(i).Take(1).ToArray())[0]);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain.ToArray());
            }
        }

        [TestMethod]
        public void StreamTest_ReuseKey()
        {
            var plaintext = new Byte[256];
            using (var memoryStream = new MemoryStream(new Byte[256]))
            {
                using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
                {
                    var ciphertext = new Byte[256];
                    using (ICryptoTransform tribbleTransform = tribble.CreateEncryptor())
                    {
                        using (
                            var cryptoStream = new NotClosingCryptoStream(memoryStream, tribbleTransform, CryptoStreamMode.Read))
                        {
                            cryptoStream.Read(ciphertext, 0, 256);
                        }
                    }
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    memoryStream.Write(ciphertext, 0, 256);
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    var thereAndBackAgain = new Byte[256];
                    using (ICryptoTransform tribbleTransform = tribble.CreateDecryptor())
                    {
                        using (var cryptoStream = new NotClosingCryptoStream(memoryStream, tribbleTransform, CryptoStreamMode.Read))
                            cryptoStream.Read(thereAndBackAgain, 0, 256);
                    }
                    CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
                    
                }
            }
        }

        [TestMethod]
        public void StreamTest_SetKey()
        {
            var plaintext = new Byte[256];
            using (var memoryStream = new MemoryStream(new Byte[256]))
            {
                using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
                {
                    var ciphertext = new Byte[256];
                    using (ICryptoTransform tribbleTransform = tribble.CreateEncryptor(Sample512BitKey, null))
                    {
                        using (
                            var cryptoStream = new NotClosingCryptoStream(memoryStream, tribbleTransform, CryptoStreamMode.Read))
                        {
                            cryptoStream.Read(ciphertext, 0, 256);
                        }
                    }
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    memoryStream.Write(ciphertext, 0, 256);
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    var thereAndBackAgain = new Byte[256];
                    using (ICryptoTransform tribbleTransform = tribble.CreateDecryptor(Sample512BitKey, null))
                    {
                        using (var cryptoStream = new NotClosingCryptoStream(memoryStream, tribbleTransform, CryptoStreamMode.Read))
                            cryptoStream.Read(thereAndBackAgain, 0, 256);
                    }
                    CollectionAssert.AreEqual(plaintext, thereAndBackAgain);

                }
            }
        }


        [TestMethod]
        public void SHA256_XOR()
        {
            using (var tribble = new Tribble<SHA256>(Sample256BitKey, SHA256.Create()))
            {
                Byte[] plaintext =
                    Encoding.ASCII.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit posuere.");
                Byte[] ciphertext = tribble.XOR(plaintext);
                tribble.Reset();
                Byte[] thereAndBackAgain = tribble.XOR(ciphertext);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
            }
        }


        [TestMethodAttribute]
        public void SHA384_XOR()
        {
            using (var tribble = new Tribble<SHA384>(Sample384BitKey, SHA384.Create()))
            {
                Byte[] plaintext =
                    Encoding.ASCII.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit posuere.");
                Byte[] ciphertext = tribble.XOR(plaintext);
                tribble.Reset();
                Byte[] thereAndBackAgain = tribble.XOR(ciphertext);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
            }
        }


        [TestMethod]
        public void XOR_UTF8Test()
        {
            using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
            {
                Byte[] plaintext =
                    Encoding.UTF8.GetBytes("Lǫr̨e͟m̛ i̡psu̶m͡ do̵lor̛ sít ͟a̧me̛t͜,͡ ̢conseçte͞tu͞r͝ ͜a͝di͞p͢i̕s̀ci̕n͟g͏ ̴e͏lit ̧posuer̀e͢.");
                Byte[] ciphertext = tribble.XOR(plaintext);
                tribble.Reset();
                Byte[] thereAndBackAgain = tribble.XOR(ciphertext);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
            }
        }

        [TestMethod]
        public void XOR_UCS2Test()
        {
            using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
            {
                Byte[] plaintext =
                    Encoding.Unicode.GetBytes("Lǫr̨e͟m̛ i̡psu̶m͡ do̵lor̛ sít ͟a̧me̛t͜,͡ ̢conseçte͞tu͞r͝ ͜a͝di͞p͢i̕s̀ci̕n͟g͏ ̴e͏lit ̧posuer̀e͢.");
                Byte[] ciphertext = tribble.XOR(plaintext);
                tribble.Reset();
                Byte[] thereAndBackAgain = tribble.XOR(ciphertext);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
            }
        }

        [TestMethod]
        public void XOR_1MData()
        {
            using (var tribble = new Tribble<SHA512>(Sample512BitKey, SHA512.Create()))
            {
                Byte[] plaintext = new Byte[1024*1024];
                Byte[] ciphertext = tribble.XOR(plaintext);
                tribble.Reset();
                Byte[] thereAndBackAgain = tribble.XOR(ciphertext);
                CollectionAssert.AreEqual(plaintext, thereAndBackAgain);
            }
        }
    }
}
