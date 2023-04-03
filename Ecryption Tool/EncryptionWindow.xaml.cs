using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
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
using System.Windows.Shapes;
using static System.Net.Mime.MediaTypeNames;

namespace Ecryption_Tool
{
    /// <summary>
    /// Interaction logic for EncryptionWindow.xaml
    /// </summary>
    public partial class EncryptionWindow : Window
    {
        public EncryptionWindow()
        {
            InitializeComponent();

        }
        // Declare CspParmeters and RsaCryptoServiceProvider
        // objects with global scope of your Form class.
        readonly CspParameters _cspp = new CspParameters();
        RSACryptoServiceProvider _rsa;
        // Path variables for source, encryption, and
        // decryption folders. Must end with a backslash.
        const string EncrFolder = "\\Encrypt\\";
        const string DecrFolder = "\\Decrypt\\";
        private string SrcFolder = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.FullName;

        private string pubKeyFolder = "PublicKeys";
        const string PubKeyFile = "rsaPublicKey.txt";
        /*System.IO.Path.Combine(SrcFolder, PubKeyFolder ,PubKeyFile);*/
        const string KeyName = "Key01";
        Bitmap image;
        string base64Text;
        private void buttonEncryptFile_Click(object sender, RoutedEventArgs e)
        {
            if (_rsa is null)
            {
                MessageBox.Show("Key not set.");
            }
            else
            {
                OpenFileDialog dialog = new OpenFileDialog();
                dialog.Filter = "Image Files(*.BMP;*.JPG;*.PNG)|*.BMP;*.JPG;*.PNG" +
                "|All files(*.*)|*.*";
                //dialog.Filter = "Text|*.txt|All|*.*";
                dialog.CheckFileExists = true;
                dialog.Multiselect = false;
                if (dialog.ShowDialog() == true)
                {
                    string fName = dialog.FileName;
                    image = new Bitmap(dialog.FileName);
                    byte[] imageArray = System.IO.File.ReadAllBytes(dialog.FileName);
                    base64Text = Convert.ToBase64String(imageArray); //base64Text must be global but I'll use  richtext

                    //MakeTextFile(new FileInfo(fName), base64Text);
                    EncryptFile(MakeTextFile(new FileInfo(fName), base64Text));
                }
            }
        }

        private void EncryptFile(FileInfo fileInfo)
        {
            string base64Text;
            //Create instance of Aes for
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
            string path = SrcFolder + EncrFolder;
            string outTextFile = System.IO.Path.Combine(path, System.IO.Path.ChangeExtension(fileInfo.Name, ".enc"));

            // System.IO.Path.Combine(EncrFolder, System.IO.Path.ChangeExtension(fileInfo.Name, ".enc"));
            //string outFile = System.IO.Path.ChangeExtension(outTextFile, ".enc");
            using (var outFs = new FileStream(outTextFile, FileMode.Create))
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

                    using (var inFs = new FileStream(fileInfo.FullName, FileMode.Open))
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
            File.Delete(fileInfo.ToString());
        }

        private void buttonDecryptFile_Click(object sender, RoutedEventArgs e)
        {
            if (_rsa is null)
            {
                MessageBox.Show("Key not set.");
            }
            else
            {
                OpenFileDialog _decryptOpenFileDialog = new OpenFileDialog();
                // Display a dialog box to select the encrypted file.
                string fullPath = SrcFolder + EncrFolder;
                _decryptOpenFileDialog.InitialDirectory = fullPath;
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

        private void DecryptFile(FileInfo fileInfo)
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
            string newPath = SrcFolder + DecrFolder;

            var outFile =
                System.IO.Path.ChangeExtension(fileInfo.Name, ".txt");

            string newOutFilePath = System.IO.Path.Combine(newPath, outFile);
            FileInfo newfileInfo = new FileInfo(newOutFilePath);
            // Use FileStream objects to read the encrypted
            // file (inFs) and save the decrypted file (outFs).
            using (var inFs = new FileStream(fileInfo.FullName, FileMode.Open))
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

                //Directory.CreateDirectory(DecrFolder);
                // Use RSACryptoServiceProvider
                // to decrypt the AES key.
                byte[] KeyDecrypted = _rsa.Decrypt(KeyEncrypted, false);

                // Decrypt the key.
                ICryptoTransform transform = aes.CreateDecryptor(KeyDecrypted, IV);

                // Decrypt the cipher text from
                // from the FileSteam of the encrypted
                // file (inFs) into the FileStream
                // for the decrypted file (outFs).
                using (var outFs = new FileStream(newOutFilePath, FileMode.Create))
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
                ConvertImage(newfileInfo);
            }
            File.Delete(newOutFilePath);
        }
        public void ConvertImage(FileInfo filePath)
        {
            StringBuilder stringBuilder = new StringBuilder();
            using (FileStream fs = new FileStream(filePath.FullName, FileMode.Open, FileAccess.Read))
            {
                using (StreamReader st = new StreamReader(fs))
                {
                    stringBuilder.Append(st.ReadToEnd());
                    SaveImage(stringBuilder.ToString(), filePath.Name);
                }
            }
        }
        public void SaveImage(string base64, string fileName)
        {
            string newPath = SrcFolder + DecrFolder;
            string imageName = System.IO.Path.ChangeExtension(fileName, ".jpg");
            using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(base64)))
            {
                using (Bitmap bm2 = new Bitmap(ms))
                {
                    bm2.Save(newPath + imageName);
                }
            }
        }
        private void buttonCreateAsmKeys_Click(object sender, RoutedEventArgs e)
        {
            // Stores a key pair in the key container.
            _cspp.KeyContainerName = KeyName;
            _rsa = new RSACryptoServiceProvider(_cspp)
            {
                PersistKeyInCsp = true
            };

            label1.Content = _rsa.PublicOnly
                ? $"Key: {_cspp.KeyContainerName} - Public Only"
                : $"Key: {_cspp.KeyContainerName} - Full Key Pair";

        }

        private void buttonExportPublicKey_Click(object sender, RoutedEventArgs e)
        {
            // Save the public key created by the RSA
            // to a file. Caution, persisting the
            // key to a file is a security risk.
            //Directory.CreateDirectory(EncrFolder);
            string path = SrcFolder + "\\PublicKeys\\"+ PubKeyFile;
            using (var sw = new StreamWriter(path, false))
            {
                sw.Write(_rsa.ToXmlString(false));
            }
        }

        private void buttonImportPublicKey_Click(object sender, RoutedEventArgs e)
        {
            using (var sr = new StreamReader(PubKeyFile))
            {
                _cspp.KeyContainerName = KeyName;
                _rsa = new RSACryptoServiceProvider(_cspp);

                string keytxt = sr.ReadToEnd();
                _rsa.FromXmlString(keytxt);
                _rsa.PersistKeyInCsp = true;

                label2.Content = _rsa.PublicOnly
                    ? $"Key: {_cspp.KeyContainerName} - Public Only"
                    : $"Key: {_cspp.KeyContainerName} - Full Key Pair";
            }

        }

        private void buttonGetPrivateKey_Click(object sender, RoutedEventArgs e)
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
        private FileInfo MakeTextFile(FileInfo fileInfo, string base64String)
        {
            string fileName = System.IO.Path.ChangeExtension(fileInfo.Name, ".txt");
            string folder = SrcFolder + EncrFolder;
            string outFile = System.IO.Path.Combine(folder, fileName);
            using (FileStream fs = new FileStream(outFile, FileMode.OpenOrCreate))
            {
                using (StreamWriter sr = new StreamWriter(fs))
                {
                    sr.Write(base64String);
                    sr.Close();
                }
                fs.Close();
            }
            return new FileInfo(outFile);

        }
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            InitializeFolders();
        }
        private void InitializeFolders()
        {
            string SrcFolder = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.FullName;
            const string EncrFolder = "Encrypt\\";
            const string DecrFolder = "Decrypt\\";
            const string PubKeyFolder = "PublicKeys\\";
            List<string> folderList = new List<string>();
            folderList.Add(EncrFolder);
            folderList.Add(DecrFolder);
            folderList.Add(PubKeyFolder);
            foreach (var item in folderList)
            {
                string folderPath = System.IO.Path.Combine(SrcFolder, item);
                bool isExists = IsFolderExist(folderPath);
                if (!isExists)
                {
                    Directory.CreateDirectory(folderPath);
                }
            }

        }
        private bool IsFolderExist(string folder)
        {
            bool isFolderExist = false;
            if (Directory.Exists(folder))
            {
                isFolderExist = true;
            }
            return isFolderExist;
        }
    }
}
