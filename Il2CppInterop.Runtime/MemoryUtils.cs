using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Il2CppInterop.Common.XrefScans;
using Microsoft.Extensions.Logging;
using TerraFX.Interop.Windows;

namespace Il2CppInterop.Runtime;

public class MemoryUtils
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
        int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    // Protections that permit reading; TerraFX defines no single composite of these.
    private const uint PageReadable = PAGE.PAGE_READONLY | PAGE.PAGE_READWRITE | PAGE.PAGE_WRITECOPY |
                                      PAGE.PAGE_EXECUTE_READ | PAGE.PAGE_EXECUTE_READWRITE |
                                      PAGE.PAGE_EXECUTE_WRITECOPY;

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
            foreach (var region in GetModuleRegions(module))
            {
                if (region.State != MEM.MEM_COMMIT || (region.Protect & PAGE.PAGE_GUARD) != 0 ||
                    (region.Protect & PageReadable) == 0)
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
    public static unsafe List<MEMORY_BASIC_INFORMATION> GetModuleRegions(ProcessModule module)
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


    /// <summary>
    /// Reads the module region by region. Guard pages are skipped (left zeroed). Committed PAGE_NOACCESS
    /// regions are made PAGE_READONLY just long enough to read, then restored. Readable regions are untouched.
    /// </summary>
    [SupportedOSPlatform("windows6.1")]
    private static unsafe byte[] ReadModuleMemory(ILogger logger, Process process, ProcessModule module)
    {
        var bytes = new byte[module.ModuleMemorySize];
        var moduleBase = (long)module.BaseAddress;

        foreach (var region in GetModuleRegions(module))
        {
            if (region.State != MEM.MEM_COMMIT || (region.Protect & PAGE.PAGE_GUARD) != 0)
                continue;

            var start = (long)region.BaseAddress - moduleBase;
            if (start < 0 || start >= bytes.Length)
                continue;
            var size = (int)Math.Min((long)region.RegionSize, bytes.Length - start);

            var restore = false;
            uint oldProtect = 0;
            if ((region.Protect & PageReadable) == 0)
            {
                // PAGE_NOACCESS (or similar): temporarily make it readable
                if (!VirtualProtect((nint)region.BaseAddress, (nuint)size, PAGE.PAGE_READONLY, out oldProtect))
                {
                    logger.LogDebug("Skipping unreadable region at {addr:X}", (long)region.BaseAddress);
                    continue;
                }
                restore = true;
            }

            try
            {
                var buffer = new byte[size];
                if (ReadProcessMemory(process.Handle, (nint)region.BaseAddress, buffer, size, out var read))
                    Array.Copy(buffer, 0, bytes, start, (long)read);
                else
                    logger.LogDebug("ReadProcessMemory failed for region at {addr:X}", (long)region.BaseAddress);
            }
            finally
            {
                if (restore)
                    VirtualProtect((nint)region.BaseAddress, (nuint)size, oldProtect, out _);
            }
        }

        return bytes;
    }

    [SupportedOSPlatform("windows6.1")]
    public static void RuntimeModuleDump(ILogger logger, out byte[] il2cppBytes, out byte[] metadataBytes, byte[] metadataSignatureToScan, byte[] magicToFix, int metadataSignatureOffset = 252)
    {
        Process process = Process.GetCurrentProcess();
        var module = process
            .Modules.OfType<ProcessModule>()
            .SingleOrDefault(x => x.ModuleName is "GameAssembly.dll" or "GameAssembly.so" or "UserAssembly.dll");
        if (module?.ModuleName == null)
        {
            logger.LogError("GameAssembly.dll or GameAssembly.so or UserAssembly.dll not found");
            il2cppBytes = [];
            metadataBytes = [];
            return;
        }

        var moduleBytes = ReadModuleMemory(logger, process, module);

        using (var stream = new MemoryStream(moduleBytes))
        using (var reader = new BinaryReader(stream))
        using (var writer = new BinaryWriter(stream))
        {
            // Parse the PE header to get the section headers
            stream.Position = 0x3C;
            var peHeaderOffset = reader.ReadInt32();
            logger.LogDebug("peHeaderOffset: {peHeaderOffset}", peHeaderOffset);
            stream.Position = peHeaderOffset + 6;
            var numberOfSections = reader.ReadUInt16();
            var timeDateStame = reader.ReadUInt32();
            var pointerToSymbolTable = reader.ReadUInt32();
            var numberOfSymbols = reader.ReadUInt32();
            var sizeOfOptionalHeader = reader.ReadUInt16();
            var characteristics = reader.ReadUInt16();
            var section0StartPosition = (int)stream.Position + sizeOfOptionalHeader;

            // Update each section header's PointerToRawData and SizeOfRawData fields
            logger.LogDebug("numberOfSections: {numberOfSections}", numberOfSections);
            for (var i = 0; i < numberOfSections; i++)
            {
                stream.Position = section0StartPosition + (i * 40);
                var sectionNameBytes = reader.ReadBytes(8);
                var sectionName = Encoding.ASCII.GetString(sectionNameBytes).TrimEnd('\0');
                var virtualSize = reader.ReadUInt32();
                var virtualAddress = reader.ReadUInt32();
                logger.LogDebug("{sectionName}: VirtualSize {virtualSize:X} VirtualAddress {virtualAddress:X}", sectionName, virtualSize, virtualAddress);
                writer.Write(virtualSize);
                writer.Write(virtualAddress);
            }
        }

        logger.LogDebug("Processed {module.ModuleName}", module.ModuleName);
        il2cppBytes = moduleBytes;

        var byteArray = moduleBytes;

        // search for pattern in the byte array
        var index = Array.IndexOf(byteArray, metadataSignatureToScan[0]);
        while (index >= 0 && index <= byteArray.Length - metadataSignatureToScan.Length)
        {
            if (byteArray.AsSpan(index, metadataSignatureToScan.Length).SequenceEqual(metadataSignatureToScan))
            {
                // pattern found, trim everything before it
                var trimmedArray = new byte[byteArray.Length - index + metadataSignatureOffset];
                // copy the metadata bytes
                Array.Copy(byteArray, index - metadataSignatureOffset, trimmedArray, 0, trimmedArray.Length);
                // this is required for il2cppdumper to work
                if (magicToFix.Length > 0)
                    Array.Copy(magicToFix, 0, trimmedArray, 0, magicToFix.Length);

                byteArray = trimmedArray;
                break;
            }
            index = Array.IndexOf(byteArray, metadataSignatureToScan[0], index + 1);
        }

        logger.LogDebug("Processed global-metadata.dat");
        metadataBytes = byteArray;
        return;
    }

    public static void ValidateMetadata(ILogger logger, string metadataPath, byte[] il2cppBytes, ref byte[] metadataBytes)
    {
        //metadataBytes will equal il2cppBytes if the search pattern did not match.
        //In this case, global-metadata.dat is not embedded in GameAssembly.dll and most likely at the default path.
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
                logger.LogWarning("global-meatadata.dat is not found at the default location. " +
                    "It may be hidden somewhere else. " +
                    "\n Input the file path: (Example: C:\\Users\\_\\<YourGame>\\fake-global-metadata-name.fakeExtension");
                metadataPath = Path.Combine(Console.ReadLine() ?? string.Empty);
                metadataBytes = File.ReadAllBytes(metadataPath);
            }
        }
    }

    public struct SignatureDefinition
    {
        public string pattern;
        public string mask;
        public int offset;
        public bool xref;
    }
}
