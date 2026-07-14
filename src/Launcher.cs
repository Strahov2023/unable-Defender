using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("Defender Control")]
[assembly: AssemblyDescription("Integrity-checked launcher for Defender Control")]
[assembly: AssemblyCompany("Defender Control")]
[assembly: AssemblyProduct("Defender Control")]
[assembly: AssemblyCopyright("Copyright © 2026")]
[assembly: AssemblyVersion("1.3.0.0")]
[assembly: AssemblyFileVersion("1.3.0.0")]

internal static class Launcher
{
    // Build.ps1 заменяет маркер фактическим SHA-256 перед компиляцией.
    private const string ExpectedScriptSha256 = "__SCRIPT_SHA256__";
    private const uint LoadLibrarySearchSystem32 = 0x00000800;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetDefaultDllDirectories(uint directoryFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SetDllDirectory(string pathName);

    [STAThread]
    private static int Main()
    {
        HardenDllSearchPath();
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        try
        {
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string sourceScript = Path.Combine(baseDirectory, "DefenderControl.ps1");

            if (!File.Exists(sourceScript))
            {
                ShowError("Не найден файл DefenderControl.ps1 рядом с приложением.");
                return 2;
            }

            string runtimeScript = CreateVerifiedRuntimeCopy(sourceScript);
            StartVerifiedScript(runtimeScript);
            return 0;
        }
        catch (InvalidDataException exception)
        {
            ShowError(
                "Проверка целостности не пройдена. DefenderControl.ps1 был изменён после сборки.\r\n\r\n" +
                exception.Message +
                "\r\n\r\nНе запускайте приложение и восстановите файлы из доверенного выпуска.");
            return 3;
        }
        catch (Exception exception)
        {
            ShowError("Не удалось безопасно запустить Defender Control.\r\n\r\n" + exception.Message);
            return 1;
        }
    }

    private static string CreateVerifiedRuntimeCopy(string sourcePath)
    {
        if (ExpectedScriptSha256.Length != 64 || ExpectedScriptSha256.IndexOf("__", StringComparison.Ordinal) >= 0)
        {
            throw new InvalidDataException("В EXE отсутствует корректный контрольный хеш.");
        }

        string runtimeDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "DefenderControl",
            "Runtime");
        EnsureProtectedDirectory(runtimeDirectory);

        string destinationPath = Path.Combine(runtimeDirectory, "DefenderControl-" + ExpectedScriptSha256 + ".ps1");
        string temporaryPath = Path.Combine(runtimeDirectory, Guid.NewGuid().ToString("N") + ".tmp");

        try
        {
            // FileShare.Read запрещает запись и удаление исходника на протяжении проверки и копирования.
            using (FileStream source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                string sourceHash = ComputeSha256(source);
                if (!FixedTimeEquals(sourceHash, ExpectedScriptSha256))
                {
                    throw new InvalidDataException("SHA-256 исходного скрипта не совпадает с ожидаемым.");
                }

                source.Position = 0;
                using (FileStream destination = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    source.CopyTo(destination);
                    destination.Flush(true);
                }
            }

            VerifyFileHash(temporaryPath, ExpectedScriptSha256);
            ProtectFile(temporaryPath);

            if (File.Exists(destinationPath))
            {
                RejectReparsePoint(destinationPath, "защищённый файл сценария");
                VerifyFileHash(destinationPath, ExpectedScriptSha256);
                ProtectFile(destinationPath);
                File.Delete(temporaryPath);
            }
            else
            {
                File.Move(temporaryPath, destinationPath);
            }

            VerifyFileHash(destinationPath, ExpectedScriptSha256);
            return destinationPath;
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                try { File.Delete(temporaryPath); } catch { }
            }
        }
    }

    private static void EnsureProtectedDirectory(string directoryPath)
    {
        string commonData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string applicationDirectory = Path.Combine(commonData, "DefenderControl");
        Directory.CreateDirectory(applicationDirectory);
        RejectReparsePoint(applicationDirectory, "каталог DefenderControl");
        ApplyProtectedDirectoryAcl(applicationDirectory);

        Directory.CreateDirectory(directoryPath);
        RejectReparsePoint(directoryPath, "каталог Runtime");
        ApplyProtectedDirectoryAcl(directoryPath);
    }

    private static void ApplyProtectedDirectoryAcl(string directoryPath)
    {

        SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        DirectorySecurity security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(administratorsSid);
        security.AddAccessRule(new FileSystemAccessRule(
            systemSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            administratorsSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        Directory.SetAccessControl(directoryPath, security);
    }

    private static void ProtectFile(string filePath)
    {
        SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        FileSecurity security = new FileSecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(administratorsSid);
        security.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(administratorsSid, FileSystemRights.FullControl, AccessControlType.Allow));
        File.SetAccessControl(filePath, security);
    }

    private static void RejectReparsePoint(string path, string description)
    {
        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Обнаружена недопустимая точка повторной обработки: " + description + ".");
        }
    }

    private static void HardenDllSearchPath()
    {
        try
        {
            SetDefaultDllDirectories(LoadLibrarySearchSystem32);
            SetDllDirectory(string.Empty);
        }
        catch
        {
            // Проверка SHA-256 и защищённый runtime остаются обязательными.
        }
    }

    private static string ComputeSha256(Stream stream)
    {
        using (SHA256 algorithm = SHA256.Create())
        {
            byte[] hash = algorithm.ComputeHash(stream);
            StringBuilder builder = new StringBuilder(hash.Length * 2);
            foreach (byte value in hash)
            {
                builder.Append(value.ToString("X2"));
            }
            return builder.ToString();
        }
    }

    private static void VerifyFileHash(string path, string expectedHash)
    {
        using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            string actualHash = ComputeSha256(stream);
            if (!FixedTimeEquals(actualHash, expectedHash))
            {
                throw new InvalidDataException("Контрольная сумма защищённой копии не совпадает.");
            }
        }
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        if (left == null || right == null || left.Length != right.Length)
        {
            return false;
        }

        int difference = 0;
        for (int index = 0; index < left.Length; index++)
        {
            difference |= left[index] ^ right[index];
        }
        return difference == 0;
    }

    private static void StartVerifiedScript(string scriptPath)
    {
        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.FileName = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell\\v1.0\\powershell.exe");
        startInfo.Arguments = "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File \"" + scriptPath + "\"";
        startInfo.WorkingDirectory = Path.GetDirectoryName(scriptPath);
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        Process.Start(startInfo);
    }

    private static void ShowError(string message)
    {
        MessageBox.Show(message, "Defender Control", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
