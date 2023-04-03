using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Path = System.IO.Path;

namespace Ecryption_Tool
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        readonly CspParameters _cspp = new CspParameters();
        RSACryptoServiceProvider _rsa;
        const string EncrFolder = @"c:\Users\32465\Encrypt\";
        const string DecrFolder = @"c:\Users\32465\Decrypt\";
        const string SrcFolder = @"c:\docs\";

        const string PubKeyFile = @"c:\encrypt\rsaPublicKey.txt";
        const string KeyName = "Key01";
        public void CreateAesKeys()
        {
            _cspp.KeyContainerName = KeyName;
            _rsa = new RSACryptoServiceProvider(_cspp)
            {
                PersistKeyInCsp = true
            };

            label1.Content = _rsa.PublicOnly
        ? $"Key: {_cspp.KeyContainerName} - Public Only"
        : $"Key: {_cspp.KeyContainerName} - Full Key Pair";
        }

        private void CreateEncryption()
        {
            if (_rsa is null)
            {
                MessageBox.Show("Key not set.");
            }
            else
            {
                OpenFileDialog _encryptOpenFileDialog = new OpenFileDialog();
                // Display a dialog box to select a file to encrypt.
                _encryptOpenFileDialog.InitialDirectory = SrcFolder;
                if (_encryptOpenFileDialog.ShowDialog() == true)
                {
                    string fName = _encryptOpenFileDialog.FileName;
                    if (fName != null)
                    {
                        // Pass the file name without the path.
                        EncryptFile(new FileInfo(fName));
                    }
                }
            }
        }
        private void EncryptFile(FileInfo file)
        {
            // Create instance of Aes for
            // symmetric encryption of the data.
            Aes aes = Aes.Create();
            ICryptoTransform transform = aes.CreateEncryptor();

            // Use RSACryptoServiceProvider to
            // encrypt the AES key.
            // rsa is previously instantiated:
            //    rsa = new RSACryptoServiceProvider(cspp);
            byte[] keyEncrypted = _rsa.Encrypt(aes.Key, false);

            // Create byte arrays to contain
            // the length values of the key and IV.
            int lKey = keyEncrypted.Length;
            byte[] LenK = BitConverter.GetBytes(lKey);
            int lIV = aes.IV.Length;
            byte[] LenIV = BitConverter.GetBytes(lIV);

            // Write the following to the FileStream
            // for the encrypted file (outFs):
            // - length of the key
            // - length of the IV
            // - ecrypted key
            // - the IV
            // - the encrypted cipher content

            // Change the file's extension to ".enc"
            string outFile = Path.Combine(EncrFolder, Path.ChangeExtension(file.Name, ".enc"));

            using (var outFs = new FileStream(outFile, FileMode.Create))
            {
                outFs.Write(LenK, 0, 4);
                outFs.Write(LenIV, 0, 4);
                outFs.Write(keyEncrypted, 0, lKey);
                outFs.Write(aes.IV, 0, lIV);

                // Now write the cipher text using
                // a CryptoStream for encrypting.
                using (var outStreamEncrypted =
                    new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                {
                    // By encrypting a chunk at
                    // a time, you can save memory
                    // and accommodate large files.
                    int count = 0;
                    int offset = 0;

                    // blockSizeBytes can be any arbitrary size.
                    int blockSizeBytes = aes.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];
                    int bytesRead = 0;

                    using (var inFs = new FileStream(file.FullName, FileMode.Open))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamEncrypted.Write(data, 0, count);
                            bytesRead += blockSizeBytes;
                        } while (count > 0);
                    }
                    outStreamEncrypted.FlushFinalBlock();
                }
            }
        }

        private void CreateDecryption()
        {
            if (_rsa is null)
            {
                MessageBox.Show("Key not set.");
            }
            else
            {
                OpenFileDialog _decryptOpenFileDialog = new OpenFileDialog();
                // Display a dialog box to select the encrypted file.
                _decryptOpenFileDialog.InitialDirectory = EncrFolder;
                if (_decryptOpenFileDialog.ShowDialog() == true)
                {
                    string fName = _decryptOpenFileDialog.FileName;
                    if (fName != null)
                    {
                        DecryptFile(new FileInfo(fName));
                    }
                }
            }
        }
        private void DecryptFile(FileInfo file)
        {
            // Create instance of Aes for
            // symmetric decryption of the data.
            Aes aes = Aes.Create();

            // Create byte arrays to get the length of
            // the encrypted key and IV.
            // These values were stored as 4 bytes each
            // at the beginning of the encrypted package.
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];

            // Construct the file name for the decrypted file.
            string outFile =
                Path.ChangeExtension(file.FullName.Replace("Encrypt", "Decrypt"), ".txt");

            // Use FileStream objects to read the encrypted
            // file (inFs) and save the decrypted file (outFs).
            using (var inFs = new FileStream(file.FullName, FileMode.Open))
            {
                inFs.Seek(0, SeekOrigin.Begin);
                inFs.Read(LenK, 0, 3);
                inFs.Seek(4, SeekOrigin.Begin);
                inFs.Read(LenIV, 0, 3);

                // Convert the lengths to integer values.
                int lenK = BitConverter.ToInt32(LenK, 0);
                int lenIV = BitConverter.ToInt32(LenIV, 0);

                // Determine the start postition of
                // the ciphter text (startC)
                // and its length(lenC).
                int startC = lenK + lenIV + 8;
                int lenC = (int)inFs.Length - startC;

                // Create the byte arrays for
                // the encrypted Aes key,
                // the IV, and the cipher text.
                byte[] KeyEncrypted = new byte[lenK];
                byte[] IV = new byte[lenIV];

                // Extract the key and IV
                // starting from index 8
                // after the length values.
                inFs.Seek(8, SeekOrigin.Begin);
                inFs.Read(KeyEncrypted, 0, lenK);
                inFs.Seek(8 + lenK, SeekOrigin.Begin);
                inFs.Read(IV, 0, lenIV);

                Directory.CreateDirectory(DecrFolder);
                // Use RSACryptoServiceProvider
                // to decrypt the AES key.
                byte[] KeyDecrypted = _rsa.Decrypt(KeyEncrypted, false);

                // Decrypt the key.
                ICryptoTransform transform = aes.CreateDecryptor(KeyDecrypted, IV);

                // Decrypt the cipher text from
                // from the FileSteam of the encrypted
                // file (inFs) into the FileStream
                // for the decrypted file (outFs).
                using (var outFs = new FileStream(outFile, FileMode.Create))
                {
                    int count = 0;
                    int offset = 0;

                    // blockSizeBytes can be any arbitrary size.
                    int blockSizeBytes = aes.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];

                    // By decrypting a chunk a time,
                    // you can save memory and
                    // accommodate large files.

                    // Start at the beginning
                    // of the cipher text.
                    inFs.Seek(startC, SeekOrigin.Begin);
                    using (var outStreamDecrypted =
                        new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamDecrypted.Write(data, 0, count);
                        } while (count > 0);

                        outStreamDecrypted.FlushFinalBlock();
                    }
                }
            }
        }
        private void BtnAesGen_Click(object sender, RoutedEventArgs e)
        {

            CreateAesKeys();
            CreateEncryption();

            //var sleutelText = txtboxSleutel.Text;
            ////ecnrypt the plain text 
            //bool isCreateKeyFleCreated = SaveEncryptedText(sleutelText);

            //if (isCreateKeyFleCreated)
            //{
            //    MessageBox.Show("Success", "Key Generated");
            //}

        }
        private bool SaveEncryptedText(string plainText)
        {
            try
            {
                // Create Aes that generates a new key and initialization vector (IV).
                // Same key must be used in encryption and decryption
                using (AesManaged aes = new AesManaged())
                {
                    // Encrypt string
                    byte[] encrypted = Encrypt(plainText, aes.Key, aes.IV);
                    bool isFileCreated = CreateAesFile(encrypted, aes.Key, aes.IV);
                    return isFileCreated;
                }
            }
            catch (Exception exp)
            {
                Console.WriteLine(exp.Message);
            }
            return false;
        }
        private bool CreateAesFile(byte[] text, byte[] key, byte[] iv)
        {
            //make sure that the folder exists 
            CreateAesFolder();
            string file = text[0].ToString() + text[1].ToString() + ".key";
            string projectPath = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.FullName;
            string folderName = "Aes Keys";
            string fileName = System.IO.Path.Combine(projectPath, folderName, file);
            try
            {
                if (!File.Exists(fileName))
                {
                    FileStream stream = new FileStream(fileName, FileMode.CreateNew);
                    StringBuilder cipherText = new StringBuilder();
                    foreach (byte b in text)
                    {
                        cipherText.Append(b.ToString() + "|");
                    }
                    StringBuilder keyText = new StringBuilder();
                    foreach (byte b in key)
                    {
                        keyText.Append(b.ToString() + "|");
                    }
                    StringBuilder ivText = new StringBuilder();
                    foreach (byte b in iv)
                    {
                        ivText.Append(b.ToString() + "|");
                    }
                    // Create a StreamWriter from FileStream  
                    using (StreamWriter writer = new StreamWriter(stream))
                    {
                        writer.Write($"{cipherText},\n{keyText},\n{ivText}");
                    }
                    return true;
                }
            }
            catch (Exception exp)
            {
                MessageBox.Show(exp.Message);
            }
            return false;

        }
        private void CreateAesFolder()
        {
            string dir = "Aes Keys";
            string projectPath = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.FullName;
            string folderName = System.IO.Path.Combine(projectPath, dir);
            // If directory does not exist, create it
            if (!Directory.Exists(folderName))
            {
                Directory.CreateDirectory(folderName);
            }
        }
        private byte[] Encrypt(string simpleText, byte[] key, byte[] iv)
        {
            byte[] encrypted;
            // Create a new AesManaged.
            using (AesManaged aes = new AesManaged())
            {
                // Create encryptor
                ICryptoTransform encryptor = aes.CreateEncryptor(key, iv);
                // Create MemoryStream
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream
                    // to encrypt
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // Create StreamWriter and write data to a stream
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(simpleText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data
            return encrypted;
        }
        private string Base64Encode(string text)
        {
            var textBytes = System.Text.Encoding.UTF8.GetBytes(text);
            return System.Convert.ToBase64String(textBytes);
        }
        public static string Base64Decode(string base64)
        {
            var base64Bytes = System.Convert.FromBase64String(base64);
            return System.Text.Encoding.UTF8.GetString(base64Bytes);
        }


        private void BtnReadFile_Click(object sender, RoutedEventArgs e)
        {
            CreateAesKeys();
            CreateDecryption();
            //string dir = "Aes Keys";
            //string projectPath = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.FullName;
            //string fullFolderPath = System.IO.Path.Combine(projectPath, dir);
            //OpenFileDialog openFileDialog1 = new OpenFileDialog();
            //openFileDialog1.InitialDirectory = fullFolderPath;
            //openFileDialog1.Title = "Browse Aes File";
            //try
            //{
            //    if (openFileDialog1.ShowDialog() == true)
            //    {
            //        ReadFile(openFileDialog1.FileName);
            //    }
            //}
            //catch (Exception ex)
            //{

            //    MessageBox.Show("Incorrect file", "Error");
            //}

        }
        private void ReadFile(string fileName)
        {
            StringBuilder stringBuilder = new StringBuilder();
            using (StreamReader sr = new StreamReader(fileName))
            {
                stringBuilder.AppendLine(sr.ReadToEnd());
            }
            ConvertFile(stringBuilder);
        }

        private void ConvertFile(StringBuilder stringBuilder)
        {
            string[] keys = stringBuilder.ToString().Split(',');
            string[] cipherText = keys[0].Split('|');
            string[] key = keys[1].Split('|');
            string[] iv = keys[2].Split('|');

            byte[] cipherInBytes = new byte[cipherText.Length - 1];
            byte[] keyInBytes = new byte[key.Length - 1];
            byte[] ivInBytes = new byte[iv.Length - 1];

            for (int i = 0; i < cipherInBytes.Length; i++)
            {
                cipherInBytes[i] = Byte.Parse(cipherText[i]);
            }
            for (int i = 0; i < keyInBytes.Length; i++)
            {
                keyInBytes[i] = Byte.Parse(key[i]);
            }
            for (int i = 0; i < ivInBytes.Length; i++)
            {
                ivInBytes[i] = Byte.Parse(iv[i]);
            }

            string plainText = Decryptie(cipherInBytes, keyInBytes, ivInBytes);

            lblOutput.Content = plainText;
        }

        private string Decryptie(byte[] cipheredText, byte[] key, byte[] iv)
        {
            string plaintext = String.Empty;
            using (AesManaged aes = new AesManaged())
            {

                // Create a decryptor
                ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
                // Create the streams used for decryption.
                using (MemoryStream ms = new MemoryStream(cipheredText))
                {
                    // Create crypto stream
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }

        private void btnRsaSleutel_Click(object sender, RoutedEventArgs e)
        {
            // Save the public key created by the RSA
            // to a file. Caution, persisting the
            // key to a file is a security risk.
            Directory.CreateDirectory(EncrFolder);
            using (var sw = new StreamWriter(PubKeyFile, false))
            {
                sw.Write(_rsa.ToXmlString(false));
            }
        }
        private void ImportPublicKey()
        {
            using (var sr = new StreamReader(PubKeyFile))
            {
                _cspp.KeyContainerName = KeyName;
                _rsa = new RSACryptoServiceProvider(_cspp);

                string keytxt = sr.ReadToEnd();
                _rsa.FromXmlString(keytxt);
                _rsa.PersistKeyInCsp = true;

                label1.Content = _rsa.PublicOnly
                    ? $"Key: {_cspp.KeyContainerName} - Public Only"
                    : $"Key: {_cspp.KeyContainerName} - Full Key Pair";
            }
        }
        private void GetPrivateKey()
        {
            _cspp.KeyContainerName = KeyName;
            _rsa = new RSACryptoServiceProvider(_cspp)
            {
                PersistKeyInCsp = true
            };

            label1.Content = _rsa.PublicOnly
                ? $"Key: {_cspp.KeyContainerName} - Public Only"
                : $"Key: {_cspp.KeyContainerName} - Full Key Pair";
        }
    }
}