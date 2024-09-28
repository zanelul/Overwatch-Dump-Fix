#include "import_deobfuscation.h"

#include <malloc.h>

#include "ntdll.h"
#include "plugin.h"

#include "..\zydis\zydis.h"


//
// Define an arbitrary limit to the amount of IAT entries we parse before
//  assuming failure.
//
#define IAT_ENTRY_LIMIT 1500


//
// IdfpGetIatEntries
//
// Copy the import address table from the remote process into a local buffer.
//
// On success, callers must free 'ppIatEntries' via 'HeapFree'.
//
_Check_return_
BOOL
IdfpGetIatEntries(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR ImageBase,
    _In_ ULONG_PTR IatSection,
    _In_ ULONG cbIatSection,
    _Outptr_ PULONG_PTR* ppIatEntries,
    _Out_ PSIZE_T pcIatEntries
)
{
    PULONG_PTR pIatEntries = NULL;
    ULONG cbIatEntries = 0;
    ULONG cLastEntry = 0;
    SIZE_T cIatEntries = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *ppIatEntries = NULL;
    *pcIatEntries = 0;

    //
    // Lazily clamp our search range.
    //
    cbIatEntries = min(cbIatSection, IAT_ENTRY_LIMIT * sizeof(*pIatEntries));
    cLastEntry = cbIatEntries / sizeof(ULONG_PTR);

    pIatEntries = (PULONG_PTR)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        cbIatEntries);
    if (!pIatEntries)
    {
        ERR_PRINT("HeapAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //
    // Copy our IAT search range into a local buffer.
    //
    status = ReadProcessMemory(
        hProcess,
        (PVOID)IatSection,
        pIatEntries,
        cbIatEntries,
        NULL);
    if (!status)
    {
        ERR_PRINT(
            "ReadProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
            GetLastError(),
            IatSection,
            cbIatEntries);
        goto exit;
    }

    for (ULONG_PTR i = 0; i < cLastEntry && pIatEntries[i] < ImageBase; ++i)
    {
        cIatEntries++;
    }

    // Set out parameters.
    *ppIatEntries = pIatEntries;
    *pcIatEntries = cIatEntries;

exit:
    if (!status)
    {
        if (pIatEntries)
        {
            if (!HeapFree(GetProcessHeap(), 0, pIatEntries))
            {
                ERR_PRINT("HeapFree failed: %u\n", GetLastError());
            }
        }
    }

    return status;
}

struct SContext {
    ZyanU64 Registers[ZYDIS_REGISTER_MAX_VALUE];
    ZydisRegister RegisterValues[2];
    ZyanU64 ImmediateValue;
};

void GetInstructionContext(ZydisDisassembledInstruction Instruction, SContext* Context) {
    for (int i = 0; i < Instruction.info.operand_count; ++i) {
        ZydisDecodedOperand& Operand = Instruction.operands[i];

        if (Operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            if (Operand.reg.value == ZYDIS_REGISTER_RFLAGS || Operand.reg.value == ZYDIS_REGISTER_RIP) {
                continue;
            }

            if (Context->RegisterValues[0] == ZYDIS_REGISTER_NONE) {
                Context->RegisterValues[0] = Operand.reg.value;
            }
            else {
                Context->RegisterValues[1] = Operand.reg.value;
            }
        }
        else if (Operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            Context->ImmediateValue = Operand.imm.value.u;
        }
    }
}

// IdfpDeobfuscateEntry
//
_Check_return_
BOOL
IdfpDeobfuscateEntry(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR pObfuscatedEntry,
    _Out_ PULONG_PTR pDeobfuscatedEntry
)
{
    ZydisDisassembledInstruction Instruction;
    SContext Context{};
    ULONG_PTR DeobfuscatedEntry = 0;
    ZyanU64 Address = pObfuscatedEntry;
    BOOL status = TRUE;

    // Zero out parameters.
    *pDeobfuscatedEntry = NULL;

    // Emulate the instruction
    while (!DeobfuscatedEntry) {
        ZeroMemory(Context.RegisterValues, 2);

        BYTE ByteCodes[10];
        ReadProcessMemory(hProcess, (LPCVOID)Address, &ByteCodes, 10, nullptr);
        ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, Address, ByteCodes, 10, &Instruction);
        GetInstructionContext(Instruction, &Context);
        Address += Instruction.info.length;
        //INF_PRINT("Emulating: %s", Instruction.text);

        switch (Instruction.info.mnemonic) {
        case ZYDIS_MNEMONIC_MOV: {
            Context.Registers[Context.RegisterValues[0]] = Context.ImmediateValue;
            break;
        }
        case ZYDIS_MNEMONIC_XOR: {
            Context.Registers[Context.RegisterValues[0]] ^= Context.ImmediateValue;
            break;
        }
        case ZYDIS_MNEMONIC_IMUL: {
            if (Context.RegisterValues[1] != ZYDIS_REGISTER_NONE) {
                Context.Registers[Context.RegisterValues[0]] *= Context.Registers[Context.RegisterValues[1]];
            }
            else {
                Context.Registers[Context.RegisterValues[0]] *= Context.ImmediateValue;
            }
            break;
        }
        case ZYDIS_MNEMONIC_ADD: {
            Context.Registers[Context.RegisterValues[0]] += Context.ImmediateValue;
            break;
        }
        case ZYDIS_MNEMONIC_SUB: {
            Context.Registers[Context.RegisterValues[0]] -= Context.ImmediateValue;
            break;
        }
        case ZYDIS_MNEMONIC_JMP: {
            if (Context.RegisterValues[0] != ZYDIS_REGISTER_NONE) {
                DeobfuscatedEntry = Context.Registers[Context.RegisterValues[0]];
            }
            else {
                Address += Context.ImmediateValue;
            }
            break;
        }
        default: {
            ERR_PRINT("IdfpDeobfuscateEntry failed to emulate instruction");
            break;
        }
        }
    }
    
    if (!DeobfuscatedEntry)
    {
        ERR_PRINT("Failed to deobfuscate entry.\n");
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    *pDeobfuscatedEntry = DeobfuscatedEntry;

exit:
    return status;
}


//
// We use two pages for the emulation buffer so that we do not have the handle
//  edge cases where the diassembler incorrectly reads past the page boundary.
//
#define EMULATION_BUFFER_SIZE   (PAGE_SIZE * 2)


//
// IdfpDeobfuscateIatEntries
//
// Deobfuscate the elements in 'pIatEntries'. Each obfuscated pointer is
//  overwritten with its deobfuscated import address in the remote process.
//
_Check_return_
BOOL
IdfpDeobfuscateIatEntries(
    _In_ HANDLE hProcess,
    _Inout_ PULONG_PTR pIatEntries,
    _In_ SIZE_T cIatEntries
)
{
    PVOID pDeobfuscationPage = NULL;
    ULONG_PTR DeobfuscatedEntry = 0;
    SIZE_T cDeobfuscatedEntries = 0;
    BOOL status = TRUE;

    //
    // Deobfuscate all IAT entries.
    //
    for (SIZE_T i = 0; i < cIatEntries; ++i)
    {
        //
        // Skip null entries.
        //
        if (!pIatEntries[i])
        {
            continue;
        }

        //
        // TODO We should VirtualQuery the deobfuscation page to verify that it
        //  is valid and readable.
        //

        status = IdfpDeobfuscateEntry(
            hProcess,
            pIatEntries[i],
            &DeobfuscatedEntry);
        if (!status)
        {
            ERR_PRINT("IdfpDeobfuscateEntry failed for entry: %p.\n",
                pIatEntries[i]);
            goto exit;
        }

        //
        // Update the entry.
        //
        pIatEntries[i] = DeobfuscatedEntry;

        cDeobfuscatedEntries++;
    }

    INF_PRINT("Successfully deobfuscated %Iu IAT entries.\n",
        cDeobfuscatedEntries);

exit:
    return status;
}


//
// IdfpPatchImportAddressTable
//
_Check_return_
BOOL
IdfpPatchImportAddressTable(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR ImageBase,
    _In_ const REMOTE_PE_HEADER& RemotePeHeader,
    _In_ ULONG_PTR IatSection,
    _In_ PULONG_PTR pDeobfuscatedIatEntries,
    _In_ SIZE_T cIatEntries

)
{
    PIMAGE_DATA_DIRECTORY pImageDataDirectoryIat = NULL;
    IMAGE_DATA_DIRECTORY IatDataDirectoryPatch = {};
    SIZE_T cbIatEntries = 0;
    BOOL status = TRUE;

    INF_PRINT("Patching the import address table...\n");

    cbIatEntries = cIatEntries * sizeof(ULONG_PTR);

    //
    // Patch the IAT data directory entry in the remote pe header to reflect
    //  our deobfuscated IAT. We must do this so that Scylla can correctly
    //  rebuild the IAT.
    //
    // Calculate the address of the remote IAT data directory entry.
    //
    pImageDataDirectoryIat = (PIMAGE_DATA_DIRECTORY)(
        ImageBase +
        (ULONG_PTR)&RemotePeHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] -
        (ULONG_PTR)&RemotePeHeader.dosHeader);

    //
    // Sanity check.
    //
    if (cbIatEntries > MAXDWORD)
    {
        ERR_PRINT("Unexpected IAT entries size: 0x%IX\n", cbIatEntries);
        status = FALSE;
        goto exit;
    }

    //
    // Initialize the data directory patch.
    //
    IatDataDirectoryPatch.VirtualAddress = (DWORD)(IatSection - ImageBase);
    IatDataDirectoryPatch.Size = (DWORD)cbIatEntries;

    INF_PRINT("Patching the IAT data directory entry at %p:\n",
        pImageDataDirectoryIat);
    INF_PRINT("    VirtualAddress:  0x%X\n",
        IatDataDirectoryPatch.VirtualAddress);
    INF_PRINT("    Size:            0x%X\n", IatDataDirectoryPatch.Size);

    //
    // Write the patch to the remote process.
    //
    status = WriteProcessMemory(
        hProcess,
        pImageDataDirectoryIat,
        &IatDataDirectoryPatch,
        sizeof(IatDataDirectoryPatch),
        NULL);
    if (!status)
    {
        ERR_PRINT(
            "WriteProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
            GetLastError(),
            pImageDataDirectoryIat,
            sizeof(IatDataDirectoryPatch));
        goto exit;
    }

    //
    // Overwrite the obfuscated IAT in the remote process with the deobfuscated
    //  table.
    //
    status = WriteProcessMemory(
        hProcess,
        (PVOID)IatSection,
        pDeobfuscatedIatEntries,
        cbIatEntries,
        NULL);
    if (!status)
    {
        ERR_PRINT(
            "WriteProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
            GetLastError(),
            IatSection,
            cbIatEntries);
        goto exit;
    }

    INF_PRINT("Successfully patched remote IAT.\n");

exit:
    return status;
}


//
// IdfDeobfuscateImportAddressTable
//
_Use_decl_annotations_
BOOL
IdfDeobfuscateImportAddressTable(
    HANDLE hProcess,
    ULONG_PTR ImageBase,
    ULONG cbImageSize,
    const REMOTE_PE_HEADER& RemotePeHeader
)
{
    PIMAGE_SECTION_HEADER pIatSectionHeader = NULL;
    ULONG_PTR IatSection = 0;
    ULONG cbIatSection = 0;
    PULONG_PTR pIatEntries = NULL;
    SIZE_T cIatEntries = 0;
    BOOL status = TRUE;

    INF_PRINT("Deobfuscating the import address table...\n");

    pIatSectionHeader = GetPeSectionByName(RemotePeHeader, ".rdata");
    if (!pIatSectionHeader)
    {
        ERR_PRINT("Error: failed to get PE section containing the IAT.\n");
        status = FALSE;
        goto exit;
    }

    IatSection = ImageBase + pIatSectionHeader->VirtualAddress;
    cbIatSection = pIatSectionHeader->Misc.VirtualSize;

    //
    // Verify that the IAT section is inside the target image.
    //
    if (IatSection < ImageBase ||
        ImageBase + cbImageSize < IatSection + cbIatSection)
    {
        ERR_PRINT("Error: IAT section is corrupt.\n");
        ERR_PRINT("    IatSection:      %p - %p\n",
            IatSection,
            IatSection + cbIatSection);
        ERR_PRINT("    Debuggee Image:  %p - %p\n",
            ImageBase,
            ImageBase + cbImageSize);
        status = FALSE;
        goto exit;
    }

    INF_PRINT("Found the remote IAT: %p\n", IatSection);

    status = IdfpGetIatEntries(
        hProcess,
        ImageBase,
        IatSection,
        cbIatSection,
        &pIatEntries,
        &cIatEntries);
    if (!status)
    {
        ERR_PRINT("Error: failed to enumerate IAT entries.\n");
        goto exit;
    }

    INF_PRINT("The remote IAT contains %Iu elements.\n", cIatEntries);

    status = IdfpDeobfuscateIatEntries(
        hProcess,
        pIatEntries,
        cIatEntries);
    if (!status)
    {
        ERR_PRINT("Error: failed to deobfuscate the remote IAT.\n");
        goto exit;
    }

    status = IdfpPatchImportAddressTable(
        hProcess,
        ImageBase,
        RemotePeHeader,
        IatSection,
        pIatEntries,
        cIatEntries);
    if (!status)
    {
        ERR_PRINT("Error: failed to patch the remote IAT.\n");
        goto exit;
    }

    INF_PRINT("Successfully restored the remote IAT.\n");

exit:
    if (pIatEntries)
    {
        if (!HeapFree(GetProcessHeap(), 0, pIatEntries))
        {
            ERR_PRINT("HeapFree failed: %u\n", GetLastError());
        }
    }

    return status;
}
