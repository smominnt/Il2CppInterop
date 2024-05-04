using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Il2CppInterop.Common;
using Il2CppInterop.Common.XrefScans;
using Microsoft.Extensions.Logging;
using TerraFX.Interop.Windows;

namespace Il2CppInterop.Runtime;

internal class MemoryUtils
{
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static unsafe nint FindSignatureInModule(ProcessModule module, SignatureDefinition sigDef)
    {
        // On newer Unity (6000.x) the loaded GameAssembly maps some pages PAGE_NOACCESS / guard pages; the raw
        // linear byte walk in FindSignatureInBlock dereferences them and throws a fatal AccessViolationException.
        // Use VirtualQuery to enumerate the module's regions and scan only the readable committed ones, skipping
        // the rest -- without ever modifying page protections. VirtualQuery and the TerraFX MEMORY_BASIC_INFORMATION
        // fields are Windows-only (the struct is annotated for Windows 6.1+); elsewhere (where this guard-page issue
        // does not arise) fall back to the plain whole-module scan.
        nint ptr = 0;
        if (OperatingSystem.IsWindowsVersionAtLeast(6, 1))
        {
            // Protections that permit reading; TerraFX defines no single composite of these.
            const uint pageReadable = PAGE.PAGE_READONLY | PAGE.PAGE_READWRITE | PAGE.PAGE_WRITECOPY |
                                      PAGE.PAGE_EXECUTE_READ | PAGE.PAGE_EXECUTE_READWRITE | PAGE.PAGE_EXECUTE_WRITECOPY;
            var regions = GetModuleRegions(module);
            foreach (var region in regions)
            {
                if (region.State != MEM.MEM_COMMIT || (region.Protect & PAGE.PAGE_GUARD) != 0 ||
                    (region.Protect & pageReadable) == 0)
                    continue;
                ptr = FindSignatureInBlock((nint)region.BaseAddress, (long)region.RegionSize,
                    sigDef.pattern, sigDef.mask, sigDef.offset);
                if (ptr != 0)
                    break;
            }
        }
        else
        {
            ptr = FindSignatureInBlock(module.BaseAddress, module.ModuleMemorySize,
                sigDef.pattern, sigDef.mask, sigDef.offset);
        }

        if (ptr != 0 && sigDef.xref)
            ptr = XrefScannerLowLevel.JumpTargets(ptr).FirstOrDefault();
        return ptr;
    }

    public static nint FindSignatureInBlock(nint block, long blockSize, string pattern, string mask, long sigOffset = 0)
    {
        return FindSignatureInBlock(block, blockSize, pattern.ToCharArray(), mask.ToCharArray(), sigOffset);
    }

    public static unsafe nint FindSignatureInBlock(nint block, long blockSize, char[] pattern, char[] mask,
        long sigOffset = 0)
    {
        // Stop at blockSize - mask.Length so the inner read (block + address + mask.Length - 1) never passes the
        // end of this block. When the caller scans per-region (Unity 6 readable regions interleaved with guard /
        // PAGE_NOACCESS pages), an overread off the tail would fault the adjacent page -> a fatal
        // AccessViolationException that aborts the chainloader. If the block is smaller than the mask, scan nothing.
        for (long address = 0; address <= blockSize - mask.Length; address++)
        {
            var found = true;
            for (uint offset = 0; offset < mask.Length; offset++)
                if (*(byte*)(address + block + offset) != (byte)pattern[offset] && mask[offset] != '?')
                {
                    found = false;
                    break;
                }

            if (found)
                return (nint)(address + block + sigOffset);
        }

        return 0;
    }

    /// <summary>
    /// Walks the module's address space via <c>VirtualQuery</c>, collecting each memory region so the scan can pick
    /// the readable committed ones. Stops at the first <c>VirtualQuery</c> failure or once the module end is reached.
    /// </summary>
    [SupportedOSPlatform("windows6.1")]
    internal static unsafe List<MEMORY_BASIC_INFORMATION> GetModuleRegions(ProcessModule module)
    {
        var regions = new List<MEMORY_BASIC_INFORMATION>();
        var moduleEndAddress = (long)module.BaseAddress + module.ModuleMemorySize;
        var currentAddress = (long)module.BaseAddress;
        while (currentAddress < moduleEndAddress)
        {
            MEMORY_BASIC_INFORMATION memoryInfo = default;
            var result = Windows.VirtualQuery((void*)currentAddress, &memoryInfo, (nuint)sizeof(MEMORY_BASIC_INFORMATION));
            if (result == 0)
                break; // error, or reached the end of the module's mapped memory

            regions.Add(memoryInfo);
            currentAddress = (long)memoryInfo.BaseAddress + (long)memoryInfo.RegionSize;
        }

        return regions;
    }

    public static void RuntimeModuleDump(ILogger logger, out byte[] il2cppBytes, out byte[] metadataBytes, byte[] metadataSignatureToScan, byte[] magicToFix, int metadataSignatureOffset = 252)
    {
        Process process = Process.GetCurrentProcess();
        var module = process
            .Modules.OfType<ProcessModule>()
            .Single((x) => x.ModuleName is "GameAssembly.dll" or "GameAssembly.so" or "UserAssembly.dll");
        if (module.ModuleName == null)
        {
            logger.LogError("GameAssembly.dll or GameAssembly.so or UserAssembly.dll not found");
            il2cppBytes = [];
            metadataBytes = [];
            return;
        }
        var moduleBytes = new byte[module.ModuleMemorySize];

        // Directly use TerraFX regions without translation projection
        var regions = GetModuleRegions(module);

        SetModuleRegions(regions, PAGE_EXECUTE_READWRITE);
        if (!ReadProcessMemory(process.Handle, module.BaseAddress, moduleBytes, module.ModuleMemorySize, out _))
        {
            logger.LogError("Failed to read process memory");
            il2cppBytes = [];
            metadataBytes = [];
            return;
        }
        SetModuleRegions(regions);

        using (var stream = new MemoryStream(moduleBytes))
        using (var reader = new BinaryReader(stream))
        using (var writer = new BinaryWriter(stream))
        {
            stream.Position = 0x3C;
            var peHeaderOffset = reader.ReadInt32();
            stream.Position = peHeaderOffset + 6;
            var numberOfSections = reader.ReadUInt16();
            var sizeOfOptionalHeader = reader.ReadUInt16();
            var section0StartPosition = (int)stream.Position + sizeOfOptionalHeader;

            for (var i = 0; i < numberOfSections; i++)
            {
                stream.Position = section0StartPosition + (i * 40);
                var virtualSize = reader.ReadUInt32();
                var virtualAddress = reader.ReadUInt32();
                writer.Write(virtualSize);
                writer.Write(virtualAddress);
            }
        }

        il2cppBytes = moduleBytes;
        var byteArray = moduleBytes;

        var index = Array.IndexOf(byteArray, (byte)metadataSignatureToScan[0]);
        while (index >= 0 && index <= byteArray.Length - metadataSignatureToScan.Length)
        {
            if (byteArray.Skip(index).Take(metadataSignatureToScan.Length).SequenceEqual(metadataSignatureToScan))
            {
                var trimmedArray = new byte[byteArray.Length - index + metadataSignatureOffset];
                Array.Copy(byteArray, index - metadataSignatureOffset, trimmedArray, 0, trimmedArray.Length);
                if (magicToFix.Length >= 0)
                    Array.Copy(magicToFix, 0, trimmedArray, 0, magicToFix.Length);

                byteArray = trimmedArray;
                break;
            }
            index = Array.IndexOf(byteArray, (byte)metadataSignatureToScan[0], index + 1);
        }

        metadataBytes = byteArray;
    }

    public static unsafe void SetModuleRegions(List<MEMORY_BASIC_INFORMATION> protectedRegions, uint? newProtection = null)
    {
        foreach (var region in protectedRegions)
        {
            var result = VirtualProtect((IntPtr)region.BaseAddress, (uint)region.RegionSize, newProtection ?? region.Protect, out _);
            if (!result)
            {
                var error = Marshal.GetLastWin32Error();
                Logger.Instance.LogError("VirtualProtect failed with error code {error}", error);
            }
        }
    }

    public static void ValidateMetadata(ILogger logger, string metadataPath, byte[] il2cppBytes, ref byte[] metadataBytes)
    {
        if (il2cppBytes == metadataBytes)
        {
            logger.LogWarning("global-metadata.dat is not embedded in GameAssembly.dll.");
            if (File.Exists(metadataPath))
            {
                logger.LogWarning("Found global-metadata.dat at the default path, using it instead.");
                metadataBytes = File.ReadAllBytes(metadataPath);
            }
            else
            {
                logger.LogWarning("global-metadata.dat is not found at the default location. Input file path:");
                metadataPath = Path.Combine(Console.ReadLine() ?? string.Empty);
                metadataBytes = File.ReadAllBytes(metadataPath);
            }
        }
    }

    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    public struct SignatureDefinition
    {
        public string pattern;
        public string mask;
        public int offset;
        public bool xref;
    }
}
